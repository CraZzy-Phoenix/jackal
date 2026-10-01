const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

const PBKDF2_ITERATIONS = 100000;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

/* =========================================================
   COOKIE
   ========================================================= */

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const match = cookie.match(
    new RegExp(
      "(?:^|;\\s*)" +
        name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
        "=([^;]*)"
    )
  );

  return match ? decodeURIComponent(match[1]) : null;
}

function sessionCookie(value, maxAge = SESSION_SECONDS) {
  return [
    `jackal_admin_session=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict"
  ].join("; ");
}

/* =========================================================
   PASSWORD HASHING
   ========================================================= */

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function hashPassword(password, saltBytes) {
  const encoder = new TextEncoder();

  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    passwordKey,
    256
  );

  return new Uint8Array(derivedBits);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(32));

  const hash = await hashPassword(password, salt);

  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(salt)
  };
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function verifyPassword(password, storedHash, storedSalt) {
  try {
    const salt = base64ToBytes(storedSalt);

    const calculatedHash = await hashPassword(
      password,
      salt
    );

    const expectedHash = base64ToBytes(storedHash);

    return constantTimeEqual(
      calculatedHash,
      expectedHash
    );
  } catch {
    return false;
  }
}

/* =========================================================
   USER
   ========================================================= */

async function getUserByUsername(env, username) {
  return await env.DB.prepare(`
    SELECT
      id,
      username,
      password_hash,
      password_salt,
      active,
      is_superadmin,
      created_at,
      updated_at
    FROM admin_users
    WHERE username = ?
    LIMIT 1
  `)
    .bind(username)
    .first();
}

async function getUserById(env, userId) {
  return await env.DB.prepare(`
    SELECT
      id,
      username,
      active,
      is_superadmin,
      created_at,
      updated_at
    FROM admin_users
    WHERE id = ?
    LIMIT 1
  `)
    .bind(userId)
    .first();
}

/* =========================================================
   PERMISSIONS
   ========================================================= */

async function getUserPermissions(env, userId) {
  const result = await env.DB.prepare(`
    SELECT
      resource,
      can_view,
      can_create,
      can_edit,
      can_delete
    FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .all();

  return result.results || [];
}

function permissionObject(permissions) {
  const result = {};

  for (const permission of permissions) {
    result[permission.resource] = {
      view: Boolean(permission.can_view),
      create: Boolean(permission.can_create),
      edit: Boolean(permission.can_edit),
      delete: Boolean(permission.can_delete)
    };
  }

  return result;
}

/* =========================================================
   SESSION
   ========================================================= */

async function createSession(env, user) {
  const sessionId = crypto.randomUUID();

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO admin_sessions
      (id, username, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      sessionId,
      user.username,
      expiresAt,
      now
    )
    .run();

  return sessionId;
}

async function getSession(request, env) {
  const sessionId = getCookie(
    request,
    "jackal_admin_session"
  );

  if (!sessionId) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(`
    SELECT
      id,
      username,
      expires_at
    FROM admin_sessions
    WHERE id = ?
      AND expires_at > ?
    LIMIT 1
  `)
    .bind(sessionId, now)
    .first();

  if (!session) {
    return null;
  }

  const user = await getUserByUsername(
    env,
    session.username
  );

  if (!user || !user.active) {
    return null;
  }

  return {
    session,
    user
  };
}

async function requireSession(request, env) {
  const result = await getSession(
    request,
    env
  );

  if (!result) {
    return json(
      {
        ok: false,
        error: "Nicht angemeldet."
      },
      401
    );
  }

  return result;
}

/* =========================================================
   PERMISSION CHECK
   ========================================================= */

async function hasPermission(
  env,
  user,
  resource,
  action
) {
  if (Number(user.is_superadmin) === 1) {
    return true;
  }

  const permission = await env.DB.prepare(`
    SELECT
      can_view,
      can_create,
      can_edit,
      can_delete
    FROM admin_permissions
    WHERE user_id = ?
      AND resource = ?
    LIMIT 1
  `)
    .bind(user.id, resource)
    .first();

  if (!permission) {
    return false;
  }

  return Number(permission[`can_${action}`]) === 1;
}

async function requirePermission(
  request,
  env,
  resource,
  action
) {
  const auth = await requireSession(
    request,
    env
  );

  if (auth instanceof Response) {
    return auth;
  }

  const allowed = await hasPermission(
    env,
    auth.user,
    resource,
    action
  );

  if (!allowed) {
    return json(
      {
        ok: false,
        error: "Keine Berechtigung.",
        resource,
        action
      },
      403
    );
  }

  return auth;
}

/* =========================================================
   LOGIN
   ========================================================= */

async function handleLogin(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        ok: false,
        error: "Ungültige Anfrage."
      },
      400
    );
  }

  const username = String(
    body?.username || ""
  ).trim();

  const password = String(
    body?.password || ""
  );

  if (!username || !password) {
    return json(
      {
        ok: false,
        error:
          "Bitte Benutzername und Passwort eingeben."
      },
      400
    );
  }

  /*
   * Zuerst versuchen wir den Benutzer
   * aus admin_users zu laden.
   */

  const user = await getUserByUsername(
    env,
    username
  );

  /*
   * -------------------------------------------------------
   * BOOTSTRAP
   * -------------------------------------------------------
   *
   * Solange noch KEIN Benutzer in admin_users existiert,
   * funktioniert der bisherige Cloudflare-Secret-Login.
   *
   * Dadurch verlieren wir beim Umbau nicht den Zugang.
   */

  const userCount = await env.DB.prepare(`
    SELECT COUNT(*) AS count
    FROM admin_users
  `).first();

  const hasUsers =
    Number(userCount?.count || 0) > 0;

  if (!user && !hasUsers) {
    if (
      username !== env.ADMIN_USERNAME ||
      password !== env.ADMIN_PASSWORD
    ) {
      return json(
        {
          ok: false,
          error:
            "Benutzername oder Passwort ist falsch."
        },
        401
      );
    }

    /*
     * Temporärer Bootstrap-User.
     *
     * Dieser wird hier noch NICHT automatisch
     * in die Datenbank geschrieben.
     */

    const bootstrapUser = {
      id: "bootstrap",
      username,
      active: 1,
      is_superadmin: 1
    };

    /*
     * Für den ersten Login brauchen wir
     * allerdings eine echte DB-Session.
     *
     * Deshalb wird hier zunächst nur eine
     * temporäre Session mit dem Username erzeugt.
     */

    const sessionId = crypto.randomUUID();

    const now = Math.floor(
      Date.now() / 1000
    );

    const expiresAt =
      now + SESSION_SECONDS;

    await env.DB.prepare(`
      INSERT INTO admin_sessions
        (id, username, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        sessionId,
        username,
        expiresAt,
        now
      )
      .run();

    return json(
      {
        ok: true,
        username,
        isSuperadmin: true,
        bootstrap: true
      },
      200,
      {
        "Set-Cookie":
          sessionCookie(sessionId)
      }
    );
  }

  /*
   * Ab jetzt muss der Benutzer aus
   * admin_users kommen.
   */

  if (!user || !user.active) {
    return json(
      {
        ok: false,
        error:
          "Benutzername oder Passwort ist falsch."
      },
      401
    );
  }

  const passwordValid =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!passwordValid) {
    return json(
      {
        ok: false,
        error:
          "Benutzername oder Passwort ist falsch."
      },
      401
    );
  }

  const sessionId =
    await createSession(
      env,
      user
    );

  return json(
    {
      ok: true,
      username: user.username,
      isSuperadmin:
        Number(user.is_superadmin) === 1
    },
    200,
    {
      "Set-Cookie":
        sessionCookie(sessionId)
    }
  );
}

/* =========================================================
   LOGOUT
   ========================================================= */

async function handleLogout(
  request,
  env
) {
  const sessionId =
    getCookie(
      request,
      "jackal_admin_session"
    );

  if (sessionId) {
    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE id = ?
    `)
      .bind(sessionId)
      .run();
  }

  return json(
    {
      ok: true
    },
    200,
    {
      "Set-Cookie":
        sessionCookie("", 0)
    }
  );
}

/* =========================================================
   ME
   ========================================================= */

async function handleMe(
  request,
  env
) {
  const auth =
    await getSession(
      request,
      env
    );

  if (!auth) {
    return json(
      {
        ok: false
      },
      401
    );
  }

  const permissions =
    await getUserPermissions(
      env,
      auth.user.id
    );

  return json({
    ok: true,

    user: {
      id: auth.user.id,
      username: auth.user.username,
      active: Boolean(auth.user.active),
      isSuperadmin:
        Number(auth.user.is_superadmin) === 1
    },

    permissions:
      permissionObject(
        permissions
      ),

    expiresAt:
      auth.session.expires_at
  });
}

/* =========================================================
   TEST PERMISSION
   ========================================================= */

async function handlePermissionTest(
  request,
  env
) {
  const url =
    new URL(request.url);

  const resource =
    url.searchParams.get(
      "resource"
    );

  const action =
    url.searchParams.get(
      "action"
    );

  if (!resource || !action) {
    return json(
      {
        ok: false,
        error:
          "resource und action fehlen."
      },
      400
    );
  }

  const auth =
    await requireSession(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  const allowed =
    await hasPermission(
      env,
      auth.user,
      resource,
      action
    );

  return json({
    ok: true,
    resource,
    action,
    allowed
  });
}

/* =========================================================
   WORKER
   ========================================================= */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    try {

      /* LOGIN */

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }

      /* LOGOUT */

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }

      /* CURRENT USER */

      if (
        url.pathname === "/api/me" &&
        request.method === "GET"
      ) {
        return await handleMe(
          request,
          env
        );
      }

      /*
       * TEMPORÄRER TEST-ENDPUNKT
       *
       * Beispiel:
       *
       * /api/test-permission?resource=drivers&action=edit
       */

      if (
        url.pathname ===
          "/api/test-permission" &&
        request.method === "GET"
      ) {
        return await handlePermissionTest(
          request,
          env
        );
      }

      /*
       * Alle normalen Webseiten-Dateien
       * kommen aus /public.
       */

      return env.ASSETS.fetch(
        request
      );

    } catch (error) {

      console.error(
        "Worker Error:",
        error
      );

      return json(
        {
          ok: false,
          error:
            "Interner Serverfehler."
        },
        500
      );
    }
  }
};
