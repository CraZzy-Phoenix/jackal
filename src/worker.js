const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

const PASSWORD_ITERATIONS = 100000;

/*
 * Alle Bereiche, die später Rechte bekommen können.
 */
const RESOURCES = [
  "dashboard",
  "races",
  "drivers",
  "results",
  "news",
  "blacklist",
  "gallery",
  "settings"
];

/* =========================================================
   HILFSFUNKTIONEN
========================================================= */

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

function safeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/* =========================================================
   PASSWORT-HASH
========================================================= */

async function hashPassword(password, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));

  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
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
      salt,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  const hashBytes = new Uint8Array(derivedBits);

  return {
    hash: bytesToBase64(hashBytes),
    salt: bytesToBase64(salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const salt = base64ToBytes(storedSalt);

  const result = await hashPassword(password, salt);

  return safeEqual(result.hash, storedHash);
}

/* =========================================================
   SESSIONEN
========================================================= */

async function createSession(env, username) {
  const sessionId = crypto.randomUUID();

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO admin_sessions (
      id,
      username,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      sessionId,
      username,
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

  const row = await env.DB.prepare(`
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

  if (!row) {
    return null;
  }

  return row;
}

async function requireSession(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return json(
      {
        ok: false,
        error: "Nicht angemeldet."
      },
      401
    );
  }

  return session;
}

/* =========================================================
   BENUTZER
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

async function getUserById(env, id) {
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
    .bind(id)
    .first();
}

/*
 * Dein bisheriger ADMIN_USERNAME / ADMIN_PASSWORD Zugang
 * wird beim ersten erfolgreichen Login automatisch in
 * admin_users übernommen.
 *
 * Brian Jäger wird dadurch zum Superadmin.
 */
async function bootstrapSuperadmin(env, username, password) {
  if (
    username !== env.ADMIN_USERNAME ||
    password !== env.ADMIN_PASSWORD
  ) {
    return null;
  }

  let user = await getUserByUsername(env, username);

  /*
   * Benutzer existiert bereits.
   * Nicht überschreiben.
   */
  if (user) {
    return user;
  }

  const passwordData = await hashPassword(password);

  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO admin_users (
      id,
      username,
      password_hash,
      password_salt,
      active,
      is_superadmin,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, 1, 1, ?, ?)
  `)
    .bind(
      id,
      username,
      passwordData.hash,
      passwordData.salt,
      now,
      now
    )
    .run();

  return await getUserByUsername(env, username);
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
        error: "Bitte Benutzername und Passwort eingeben."
      },
      400
    );
  }

  /*
   * Zuerst versuchen wir den alten Cloudflare-Secret-Login.
   * Dadurch wird Brian Jäger automatisch angelegt.
   */
  const bootstrapUser = await bootstrapSuperadmin(
    env,
    username,
    password
  );

  if (bootstrapUser) {
    const sessionId = await createSession(
      env,
      bootstrapUser.username
    );

    return json(
      {
        ok: true,
        username: bootstrapUser.username,
        isSuperadmin: true
      },
      200,
      {
        "Set-Cookie": sessionCookie(sessionId)
      }
    );
  }

  /*
   * Danach normale Benutzer aus admin_users.
   */
  const user = await getUserByUsername(
    env,
    username
  );

  if (!user) {
    return json(
      {
        ok: false,
        error: "Benutzername oder Passwort ist falsch."
      },
      401
    );
  }

  if (!user.active) {
    return json(
      {
        ok: false,
        error: "Dieser Benutzer ist deaktiviert."
      },
      403
    );
  }

  const validPassword = await verifyPassword(
    password,
    user.password_hash,
    user.password_salt
  );

  if (!validPassword) {
    return json(
      {
        ok: false,
        error: "Benutzername oder Passwort ist falsch."
      },
      401
    );
  }

  const sessionId = await createSession(
    env,
    user.username
  );

  return json(
    {
      ok: true,
      username: user.username,
      isSuperadmin: Boolean(user.is_superadmin)
    },
    200,
    {
      "Set-Cookie": sessionCookie(sessionId)
    }
  );
}

/* =========================================================
   LOGOUT
========================================================= */

async function handleLogout(request, env) {
  const sessionId = getCookie(
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
      "Set-Cookie": sessionCookie("", 0)
    }
  );
}

/* =========================================================
   ME
========================================================= */

async function handleMe(request, env) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return json(
      {
        ok: false
      },
      401
    );
  }

  const user = await getUserByUsername(
    env,
    session.username
  );

  if (!user || !user.active) {
    return json(
      {
        ok: false
      },
      401
    );
  }

  return json({
    ok: true,
    username: user.username,
    isSuperadmin: Boolean(user.is_superadmin),
    expiresAt: session.expires_at
  });
}

/* =========================================================
   RECHTE
========================================================= */

async function getPermissions(env, userId) {
  const result = await env.DB.prepare(`
    SELECT
      id,
      user_id,
      resource,
      can_view,
      can_create,
      can_edit,
      can_delete,
      created_at,
      updated_at
    FROM admin_permissions
    WHERE user_id = ?
    ORDER BY resource
  `)
    .bind(userId)
    .all();

  return result.results || [];
}

async function userHasPermission(
  env,
  user,
  resource,
  permission
) {
  /*
   * Superadmin darf alles.
   */
  if (user.is_superadmin) {
    return true;
  }

  const allowedResources = RESOURCES;

  if (!allowedResources.includes(resource)) {
    return false;
  }

  const row = await env.DB.prepare(`
    SELECT ${permission} AS allowed
    FROM admin_permissions
    WHERE user_id = ?
      AND resource = ?
    LIMIT 1
  `)
    .bind(
      user.id,
      resource
    )
    .first();

  return Boolean(row?.allowed);
}

/* =========================================================
   ADMIN USER LISTE
========================================================= */

async function handleAdminUsers(request, env) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Benutzer verwalten."
      },
      403
    );
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      username,
      active,
      is_superadmin,
      created_at,
      updated_at
    FROM admin_users
    ORDER BY username COLLATE NOCASE
  `).all();

  return json({
    ok: true,
    users: result.results || []
  });
}

/* =========================================================
   BENUTZER ERSTELLEN
========================================================= */

async function handleCreateUser(request, env) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Benutzer erstellen."
      },
      403
    );
  }

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

  const isSuperadmin = Boolean(
    body?.is_superadmin
  );

  if (!username || !password) {
    return json(
      {
        ok: false,
        error: "Benutzername und Passwort sind erforderlich."
      },
      400
    );
  }

  if (username.length < 2) {
    return json(
      {
        ok: false,
        error: "Der Benutzername ist zu kurz."
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        ok: false,
        error: "Das Passwort muss mindestens 8 Zeichen haben."
      },
      400
    );
  }

  const existing = await getUserByUsername(
    env,
    username
  );

  if (existing) {
    return json(
      {
        ok: false,
        error: "Dieser Benutzer existiert bereits."
      },
      409
    );
  }

  const passwordData = await hashPassword(
    password
  );

  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO admin_users (
      id,
      username,
      password_hash,
      password_salt,
      active,
      is_superadmin,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, 1, ?, ?, ?)
  `)
    .bind(
      id,
      username,
      passwordData.hash,
      passwordData.salt,
      isSuperadmin ? 1 : 0,
      now,
      now
    )
    .run();

  return json(
    {
      ok: true,
      user: {
        id,
        username,
        active: 1,
        is_superadmin: isSuperadmin ? 1 : 0,
        created_at: now,
        updated_at: now
      }
    },
    201
  );
}

/* =========================================================
   BENUTZER BEARBEITEN
========================================================= */

async function handleUpdateUser(
  request,
  env,
  userId
) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Benutzer bearbeiten."
      },
      403
    );
  }

  const targetUser = await getUserById(
    env,
    userId
  );

  if (!targetUser) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

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

  const username =
    body?.username !== undefined
      ? String(body.username).trim()
      : targetUser.username;

  const password =
    body?.password !== undefined
      ? String(body.password)
      : null;

  const active =
    body?.active !== undefined
      ? Boolean(body.active)
      : Boolean(targetUser.active);

  const isSuperadmin =
    body?.is_superadmin !== undefined
      ? Boolean(body.is_superadmin)
      : Boolean(targetUser.is_superadmin);

  /*
   * Der letzte Superadmin darf nicht versehentlich
   * zu einem normalen Benutzer gemacht werden.
   */
  if (
    targetUser.is_superadmin &&
    !isSuperadmin
  ) {
    const countRow = await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM admin_users
      WHERE is_superadmin = 1
        AND active = 1
    `).first();

    if (Number(countRow?.count || 0) <= 1) {
      return json(
        {
          ok: false,
          error: "Der letzte aktive Superadmin kann nicht entfernt werden."
        },
        400
      );
    }
  }

  if (password !== null && password.length < 8) {
    return json(
      {
        ok: false,
        error: "Das neue Passwort muss mindestens 8 Zeichen haben."
      },
      400
    );
  }

  const duplicate = await env.DB.prepare(`
    SELECT id
    FROM admin_users
    WHERE username = ?
      AND id != ?
    LIMIT 1
  `)
    .bind(username, userId)
    .first();

  if (duplicate) {
    return json(
      {
        ok: false,
        error: "Dieser Benutzername wird bereits verwendet."
      },
      409
    );
  }

  const now = Math.floor(Date.now() / 1000);

  if (password !== null) {
    const passwordData = await hashPassword(
      password
    );

    await env.DB.prepare(`
      UPDATE admin_users
      SET
        username = ?,
        password_hash = ?,
        password_salt = ?,
        active = ?,
        is_superadmin = ?,
        updated_at = ?
      WHERE id = ?
    `)
      .bind(
        username,
        passwordData.hash,
        passwordData.salt,
        active ? 1 : 0,
        isSuperadmin ? 1 : 0,
        now,
        userId
      )
      .run();
  } else {
    await env.DB.prepare(`
      UPDATE admin_users
      SET
        username = ?,
        active = ?,
        is_superadmin = ?,
        updated_at = ?
      WHERE id = ?
    `)
      .bind(
        username,
        active ? 1 : 0,
        isSuperadmin ? 1 : 0,
        now,
        userId
      )
      .run();
  }

  return json({
    ok: true,
    user: await getUserById(
      env,
      userId
    )
  });
}

/* =========================================================
   BENUTZER LÖSCHEN
========================================================= */

async function handleDeleteUser(
  request,
  env,
  userId
) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Benutzer löschen."
      },
      403
    );
  }

  if (currentUser.id === userId) {
    return json(
      {
        ok: false,
        error: "Du kannst deinen eigenen Benutzer nicht löschen."
      },
      400
    );
  }

  const targetUser = await getUserById(
    env,
    userId
  );

  if (!targetUser) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  await env.DB.prepare(`
    DELETE FROM admin_users
    WHERE id = ?
  `)
    .bind(userId)
    .run();

  return json({
    ok: true
  });
}

/* =========================================================
   BENUTZER-RECHTE LADEN
========================================================= */

async function handleGetPermissions(
  request,
  env,
  userId
) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Rechte verwalten."
      },
      403
    );
  }

  const user = await getUserById(
    env,
    userId
  );

  if (!user) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

  const permissions = await getPermissions(
    env,
    userId
  );

  return json({
    ok: true,
    resources: RESOURCES,
    permissions
  });
}

/* =========================================================
   BENUTZER-RECHTE SPEICHERN
========================================================= */

async function handleSavePermissions(
  request,
  env,
  userId
) {
  const session = await requireSession(
    request,
    env
  );

  if (session instanceof Response) {
    return session;
  }

  const currentUser = await getUserByUsername(
    env,
    session.username
  );

  if (!currentUser?.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen Rechte verwalten."
      },
      403
    );
  }

  const user = await getUserById(
    env,
    userId
  );

  if (!user) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

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

  const permissions = Array.isArray(
    body?.permissions
  )
    ? body.permissions
    : [];

  const now = Math.floor(Date.now() / 1000);

  /*
   * Bestehende Rechte des Benutzers entfernen.
   */
  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  /*
   * Neue Rechte speichern.
   */
  for (const permission of permissions) {
    const resource = String(
      permission?.resource || ""
    );

    if (!RESOURCES.includes(resource)) {
      continue;
    }

    const id = crypto.randomUUID();

    await env.DB.prepare(`
      INSERT INTO admin_permissions (
        id,
        user_id,
        resource,
        can_view,
        can_create,
        can_edit,
        can_delete,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        id,
        userId,
        resource,
        permission?.can_view ? 1 : 0,
        permission?.can_create ? 1 : 0,
        permission?.can_edit ? 1 : 0,
        permission?.can_delete ? 1 : 0,
        now,
        now
      )
      .run();
  }

  return json({
    ok: true,
    permissions: await getPermissions(
      env,
      userId
    )
  });
}

/* =========================================================
   API ROUTER
========================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      /* -------------------------
         LOGIN
      ------------------------- */

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }

      /* -------------------------
         LOGOUT
      ------------------------- */

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }

      /* -------------------------
         AKTUELLER BENUTZER
      ------------------------- */

      if (
        url.pathname === "/api/me" &&
        request.method === "GET"
      ) {
        return await handleMe(
          request,
          env
        );
      }

      /* -------------------------
         BENUTZER LISTE
      ------------------------- */

      if (
        url.pathname === "/api/admin/users" &&
        request.method === "GET"
      ) {
        return await handleAdminUsers(
          request,
          env
        );
      }

      /* -------------------------
         BENUTZER ERSTELLEN
      ------------------------- */

      if (
        url.pathname === "/api/admin/users" &&
        request.method === "POST"
      ) {
        return await handleCreateUser(
          request,
          env
        );
      }

      /*
       * /api/admin/users/:id
       */
      const userMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)$/
        );

      if (userMatch) {
        const userId = userMatch[1];

        if (request.method === "PATCH") {
          return await handleUpdateUser(
            request,
            env,
            userId
          );
        }

        if (request.method === "DELETE") {
          return await handleDeleteUser(
            request,
            env,
            userId
          );
        }
      }

      /*
       * /api/admin/users/:id/permissions
       */
      const permissionMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/permissions$/
        );

      if (permissionMatch) {
        const userId =
          permissionMatch[1];

        if (request.method === "GET") {
          return await handleGetPermissions(
            request,
            env,
            userId
          );
        }

        if (request.method === "PUT") {
          return await handleSavePermissions(
            request,
            env,
            userId
          );
        }
      }

      /* -------------------------
         ÖFFENTLICHE DATEIEN
      ------------------------- */

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error(error);

      return json(
        {
          ok: false,
          error: "Interner Serverfehler."
        },
        500
      );
    }
  }
};
