const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;


/* =========================================================
   JSON RESPONSE
========================================================= */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...extraHeaders
      }
    }
  );
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

  return match
    ? decodeURIComponent(match[1])
    : null;
}


function sessionCookie(
  value,
  maxAge = SESSION_SECONDS
) {
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
   SESSION
========================================================= */

async function createSession(
  env,
  username
) {
  const sessionId =
    crypto.randomUUID();

  const now =
    Math.floor(Date.now() / 1000);

  const expiresAt =
    now + SESSION_SECONDS;

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


async function getSession(
  request,
  env
) {
  const sessionId =
    getCookie(
      request,
      "jackal_admin_session"
    );

  if (!sessionId) {
    return null;
  }

  const now =
    Math.floor(Date.now() / 1000);

  const row =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        expires_at
      FROM admin_sessions
      WHERE id = ?
        AND expires_at > ?
      LIMIT 1
    `)
      .bind(
        sessionId,
        now
      )
      .first();

  if (!row) {
    return null;
  }

  return row;
}


async function requireSession(
  request,
  env
) {
  const session =
    await getSession(
      request,
      env
    );

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
   PASSWORD HASHING
========================================================= */

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


function hexToBytes(hex) {
  const bytes =
    new Uint8Array(
      hex.length / 2
    );

  for (
    let i = 0;
    i < bytes.length;
    i++
  ) {
    bytes[i] =
      parseInt(
        hex.substr(i * 2, 2),
        16
      );
  }

  return bytes;
}


async function hashPassword(
  password,
  saltHex = null
) {
  const encoder =
    new TextEncoder();

  const salt =
    saltHex
      ? hexToBytes(saltHex)
      : crypto.getRandomValues(
          new Uint8Array(16)
        );

  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const derivedBits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );

  return {
    hash: bytesToHex(
      new Uint8Array(
        derivedBits
      )
    ),

    salt: bytesToHex(
      salt
    )
  };
}


/*
 * Passwort prüfen
 *
 * Der gespeicherte Salt wird erneut verwendet.
 */
async function verifyPassword(
  password,
  storedHash,
  storedSalt
) {
  const passwordData =
    await hashPassword(
      password,
      storedSalt
    );

  return (
    passwordData.hash ===
    storedHash
  );
}


/* =========================================================
   ADMIN USER
========================================================= */

async function getAdminUserByUsername(
  env,
  username
) {
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


async function getAdminUserById(
  env,
  userId
) {
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
    WHERE id = ?
    LIMIT 1
  `)
    .bind(userId)
    .first();
}


/* =========================================================
   REQUIRE SUPERADMIN
========================================================= */

async function requireSuperadmin(
  request,
  env
) {
  const session =
    await getSession(
      request,
      env
    );

  if (!session) {
    return json(
      {
        ok: false,
        error: "Nicht angemeldet."
      },
      401
    );
  }

  const user =
    await getAdminUserByUsername(
      env,
      session.username
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Benutzerkonto wurde nicht gefunden."
      },
      403
    );
  }

  if (!user.active) {
    return json(
      {
        ok: false,
        error:
          "Benutzerkonto ist deaktiviert."
      },
      403
    );
  }

  if (!user.is_superadmin) {
    return json(
      {
        ok: false,
        error:
          "Keine Berechtigung."
      },
      403
    );
  }

  return {
    session,
    user
  };
}


/* =========================================================
   LOGIN
========================================================= */

async function handleLogin(
  request,
  env
) {
  let body;

  try {
    body =
      await request.json();
  } catch {
    return json(
      {
        ok: false,
        error:
          "Ungültige Anfrage."
      },
      400
    );
  }

  const username =
    String(
      body?.username || ""
    ).trim();

  const password =
    String(
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
   * Benutzer aus Datenbank laden
   */
  const user =
    await getAdminUserByUsername(
      env,
      username
    );

  if (!user) {
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
   * Prüfen ob Benutzer aktiv ist
   */
  if (!user.active) {
    return json(
      {
        ok: false,
        error:
          "Dieses Benutzerkonto ist deaktiviert."
      },
      403
    );
  }

  /*
   * Passwort prüfen
   */
  const passwordCorrect =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!passwordCorrect) {
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
   * Neue Session erstellen
   */
  const sessionId =
    await createSession(
      env,
      user.username
    );

  return json(
    {
      ok: true,
      username: user.username,
      is_superadmin:
        Boolean(user.is_superadmin)
    },
    200,
    {
      "Set-Cookie":
        sessionCookie(
          sessionId
        )
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
        sessionCookie(
          "",
          0
        )
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
  const session =
    await getSession(
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

  const user =
    await getAdminUserByUsername(
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
    username:
      user.username,

    is_superadmin:
      Boolean(
        user.is_superadmin
      ),

    expiresAt:
      session.expires_at
  });
}


/* =========================================================
   GET USERS
========================================================= */

async function handleAdminUsersGet(
  request,
  env
) {
  const auth =
    await requireSuperadmin(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  const users =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        active,
        is_superadmin,
        created_at,
        updated_at
      FROM admin_users
      ORDER BY username COLLATE NOCASE ASC
    `).all();

  const result =
    users.results || [];

  /*
   * Berechtigungen laden
   */
  for (
    const user of result
  ) {
    const permissions =
      await env.DB.prepare(`
        SELECT
          id,
          resource,
          can_view,
          can_create,
          can_edit,
          can_delete,
          created_at,
          updated_at
        FROM admin_permissions
        WHERE user_id = ?
        ORDER BY resource ASC
      `)
        .bind(user.id)
        .all();

    user.permissions =
      permissions.results || [];
  }

  return json({
    ok: true,
    users: result
  });
}


/* =========================================================
   CREATE USER
========================================================= */

async function handleAdminUserCreate(
  request,
  env
) {
  const auth =
    await requireSuperadmin(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return json(
      {
        ok: false,
        error:
          "Ungültige Anfrage."
      },
      400
    );
  }

  const username =
    String(
      body?.username || ""
    ).trim();

  const password =
    String(
      body?.password || ""
    );

  const active =
    body?.active === false
      ? 0
      : 1;

  const isSuperadmin =
    body?.is_superadmin === true
      ? 1
      : 0;

  if (!username) {
    return json(
      {
        ok: false,
        error:
          "Benutzername fehlt."
      },
      400
    );
  }

  if (username.length < 2) {
    return json(
      {
        ok: false,
        error:
          "Der Benutzername muss mindestens 2 Zeichen lang sein."
      },
      400
    );
  }

  if (!password) {
    return json(
      {
        ok: false,
        error:
          "Passwort fehlt."
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        ok: false,
        error:
          "Das Passwort muss mindestens 8 Zeichen lang sein."
      },
      400
    );
  }

  /*
   * Prüfen ob Benutzer existiert
   */
  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM admin_users
      WHERE username = ?
      LIMIT 1
    `)
      .bind(username)
      .first();

  if (existing) {
    return json(
      {
        ok: false,
        error:
          "Dieser Benutzername existiert bereits."
      },
      409
    );
  }

  /*
   * Passwort hashen
   */
  const passwordData =
    await hashPassword(
      password
    );

  const userId =
    crypto.randomUUID();

  const now =
    Math.floor(
      Date.now() / 1000
    );

  /*
   * Benutzer speichern
   */
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
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      userId,
      username,
      passwordData.hash,
      passwordData.salt,
      active,
      isSuperadmin,
      now,
      now
    )
    .run();

  /*
   * Optional mitgelieferte Rechte speichern
   */
  const permissions =
    Array.isArray(
      body?.permissions
    )
      ? body.permissions
      : [];

  for (
    const permission of permissions
  ) {
    const resource =
      String(
        permission?.resource || ""
      ).trim();

    if (!resource) {
      continue;
    }

    const permissionId =
      crypto.randomUUID();

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
        permissionId,
        userId,
        resource,
        permission?.can_view
          ? 1
          : 0,
        permission?.can_create
          ? 1
          : 0,
        permission?.can_edit
          ? 1
          : 0,
        permission?.can_delete
          ? 1
          : 0,
        now,
        now
      )
      .run();
  }

  return json(
    {
      ok: true,

      user: {
        id: userId,
        username,
        active,
        is_superadmin:
          isSuperadmin,
        created_at: now,
        updated_at: now
      }
    },
    201
  );
}


/* =========================================================
   UPDATE PERMISSIONS
========================================================= */

async function handleAdminPermissionsUpdate(
  request,
  env,
  userId
) {
  const auth =
    await requireSuperadmin(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  if (!userId) {
    return json(
      {
        ok: false,
        error:
          "Benutzer-ID fehlt."
      },
      400
    );
  }

  const user =
    await getAdminUserById(
      env,
      userId
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Benutzer nicht gefunden."
      },
      404
    );
  }

  /*
   * Superadmins brauchen keine
   * individuellen Rechte.
   */
  if (user.is_superadmin) {
    return json({
      ok: true,
      message:
        "Superadmins besitzen automatisch alle Rechte."
    });
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return json(
      {
        ok: false,
        error:
          "Ungültige Anfrage."
      },
      400
    );
  }

  const permissions =
    Array.isArray(
      body?.permissions
    )
      ? body.permissions
      : [];

  const now =
    Math.floor(
      Date.now() / 1000
    );

  /*
   * Alte Rechte löschen
   */
  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  /*
   * Neue Rechte speichern
   */
  for (
    const permission of permissions
  ) {
    const resource =
      String(
        permission?.resource || ""
      ).trim();

    if (!resource) {
      continue;
    }

    const permissionId =
      crypto.randomUUID();

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
        permissionId,
        userId,
        resource,
        permission?.can_view
          ? 1
          : 0,
        permission?.can_create
          ? 1
          : 0,
        permission?.can_edit
          ? 1
          : 0,
        permission?.can_delete
          ? 1
          : 0,
        now,
        now
      )
      .run();
  }

  return json({
    ok: true
  });
}


/* =========================================================
   RESET PASSWORD
========================================================= */

async function handleAdminPasswordReset(
  request,
  env,
  userId
) {
  const auth =
    await requireSuperadmin(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  if (!userId) {
    return json(
      {
        ok: false,
        error:
          "Benutzer-ID fehlt."
      },
      400
    );
  }

  const user =
    await getAdminUserById(
      env,
      userId
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Benutzer nicht gefunden."
      },
      404
    );
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return json(
      {
        ok: false,
        error:
          "Ungültige Anfrage."
      },
      400
    );
  }

  const password =
    String(
      body?.password || ""
    );

  if (!password) {
    return json(
      {
        ok: false,
        error:
          "Neues Passwort fehlt."
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        ok: false,
        error:
          "Das Passwort muss mindestens 8 Zeichen lang sein."
      },
      400
    );
  }

  /*
   * Neues Passwort hashen
   */
  const passwordData =
    await hashPassword(
      password
    );

  const now =
    Math.floor(
      Date.now() / 1000
    );

  /*
   * Passwort aktualisieren
   */
  await env.DB.prepare(`
    UPDATE admin_users
    SET
      password_hash = ?,
      password_salt = ?,
      updated_at = ?
    WHERE id = ?
  `)
    .bind(
      passwordData.hash,
      passwordData.salt,
      now,
      userId
    )
    .run();

  /*
   * Alle bestehenden Sessions
   * des Benutzers löschen.
   *
   * Dadurch muss er sich mit
   * dem neuen Passwort neu anmelden.
   */
  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(user.username)
    .run();

  return json({
    ok: true,
    message:
      "Passwort wurde erfolgreich zurückgesetzt."
  });
}


/* =========================================================
   DELETE USER
========================================================= */

async function handleAdminUserDelete(
  request,
  env,
  userId
) {
  const auth =
    await requireSuperadmin(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  if (!userId) {
    return json(
      {
        ok: false,
        error:
          "Benutzer-ID fehlt."
      },
      400
    );
  }

  /*
   * Sich selbst nicht löschen
   */
  if (
    userId === auth.user.id
  ) {
    return json(
      {
        ok: false,
        error:
          "Du kannst deinen eigenen Superadmin-Account nicht löschen."
      },
      400
    );
  }

  const user =
    await getAdminUserById(
      env,
      userId
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Benutzer nicht gefunden."
      },
      404
    );
  }

  /*
   * Berechtigungen löschen
   */
  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  /*
   * Sessions löschen
   */
  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(user.username)
    .run();

  /*
   * Benutzer löschen
   */
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
   ROUTER
========================================================= */

export default {
  async fetch(
    request,
    env
  ) {
    const url =
      new URL(request.url);

    try {

      /* ---------------------------------------------
         LOGIN
      --------------------------------------------- */

      if (
        url.pathname ===
          "/api/login" &&
        request.method ===
          "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }


      /* ---------------------------------------------
         LOGOUT
      --------------------------------------------- */

      if (
        url.pathname ===
          "/api/logout" &&
        request.method ===
          "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }


      /* ---------------------------------------------
         ME
      --------------------------------------------- */

      if (
        url.pathname ===
          "/api/me" &&
        request.method ===
          "GET"
      ) {
        return await handleMe(
          request,
          env
        );
      }


      /* ---------------------------------------------
         ADMIN USERS - LIST
      --------------------------------------------- */

      if (
        url.pathname ===
          "/api/admin/users" &&
        request.method ===
          "GET"
      ) {
        return await handleAdminUsersGet(
          request,
          env
        );
      }


      /* ---------------------------------------------
         ADMIN USERS - CREATE
      --------------------------------------------- */

      if (
        url.pathname ===
          "/api/admin/users" &&
        request.method ===
          "POST"
      ) {
        return await handleAdminUserCreate(
          request,
          env
        );
      }


      /* ---------------------------------------------
         ADMIN USERS - DELETE
      --------------------------------------------- */

      const userDeleteMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)$/
        );

      if (
        userDeleteMatch &&
        request.method ===
          "DELETE"
      ) {
        return await handleAdminUserDelete(
          request,
          env,
          userDeleteMatch[1]
        );
      }


      /* ---------------------------------------------
         ADMIN USERS - PERMISSIONS
      --------------------------------------------- */

      const permissionMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/permissions$/
        );

      if (
        permissionMatch &&
        request.method ===
          "PUT"
      ) {
        return await handleAdminPermissionsUpdate(
          request,
          env,
          permissionMatch[1]
        );
      }


      /* ---------------------------------------------
         ADMIN USERS - PASSWORD RESET
      --------------------------------------------- */

      const passwordResetMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/password$/
        );

      if (
        passwordResetMatch &&
        request.method ===
          "POST"
      ) {
        return await handleAdminPasswordReset(
          request,
          env,
          passwordResetMatch[1]
        );
      }


      /* ---------------------------------------------
         STATIC WEBSITE
      --------------------------------------------- */

      return env.ASSETS.fetch(
        request
      );

    } catch (error) {

      console.error(
        "Worker error:",
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
