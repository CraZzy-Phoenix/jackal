const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;


/* =========================================================
   RESSOURCEN
========================================================= */

const RESOURCES = {
  races: "races",
  drivers: "drivers",
  results: "race_results",
  news: "news",
  blacklist: "blacklist",
  gallery: "gallery",
  settings: "site_settings"
};

const RESOURCE_LABELS = {
  dashboard: "Dashboard",
  races: "Rennen",
  drivers: "Fahrer",
  results: "Ergebnisse",
  news: "News",
  blacklist: "Fahrzeug-Blacklist",
  gallery: "Gallery",
  settings: "Einstellungen"
};


/* =========================================================
   JSON RESPONSE
========================================================= */

function json(
  data,
  status = 200,
  extraHeaders = {}
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control":
          "no-store",
        ...extraHeaders
      }
    }
  );
}


/* =========================================================
   COOKIE
========================================================= */

function getCookie(
  request,
  name
) {
  const cookie =
    request.headers.get("Cookie") || "";

  const escapedName =
    name.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );

  const match =
    cookie.match(
      new RegExp(
        "(?:^|;\\s*)" +
        escapedName +
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
    Math.floor(
      Date.now() / 1000
    );

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
    Math.floor(
      Date.now() / 1000
    );

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

  return row || null;
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
   SESSION CHECK
========================================================= */

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
        error:
          "Nicht angemeldet."
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

  return {
    session,
    user
  };
}


/* =========================================================
   SUPERADMIN CHECK
========================================================= */

async function requireSuperadmin(
  request,
  env
) {
  const auth =
    await requireSession(
      request,
      env
    );

  if (
    auth instanceof Response
  ) {
    return auth;
  }

  if (
    !auth.user.is_superadmin
  ) {
    return json(
      {
        ok: false,
        error:
          "Keine Superadmin-Berechtigung."
      },
      403
    );
  }

  return auth;
}


/* =========================================================
   PASSWORD HASHING
========================================================= */

function bytesToHex(
  bytes
) {
  return Array.from(bytes)
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


function hexToBytes(
  hex
) {
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
        hex.substr(
          i * 2,
          2
        ),
        16
      );
  }

  return bytes;
}


function base64ToBytes(
  value
) {
  const binary =
    atob(value);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}


function bytesToBase64(
  bytes
) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(binary);
}


async function derivePasswordHash(
  password,
  salt
) {
  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
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

  return new Uint8Array(bits);
}


async function hashPassword(
  password,
  saltHex = null
) {
  const salt =
    saltHex
      ? hexToBytes(saltHex)
      : crypto.getRandomValues(
          new Uint8Array(16)
        );

  const derived =
    await derivePasswordHash(
      password,
      salt
    );

  return {
    hash:
      bytesToHex(
        derived
      ),

    salt:
      bytesToHex(
        salt
      )
  };
}


/* =========================================================
   PASSWORD VERIFY
   Neues + altes Format
========================================================= */

async function verifyPassword(
  password,
  storedHash,
  storedSalt
) {
  if (
    !storedHash ||
    !storedSalt
  ) {
    return {
      valid: false,
      legacy: false
    };
  }


  /*
   * NEUES HEX-FORMAT
   *
   * Hash = 64 Zeichen
   * Salt = 32 Zeichen
   */

  if (
    storedHash.length === 64 &&
    storedSalt.length === 32 &&
    /^[0-9a-fA-F]+$/.test(
      storedHash
    ) &&
    /^[0-9a-fA-F]+$/.test(
      storedSalt
    )
  ) {
    const derived =
      await derivePasswordHash(
        password,
        hexToBytes(
          storedSalt
        )
      );

    return {
      valid:
        bytesToHex(
          derived
        ).toLowerCase() ===
        storedHash.toLowerCase(),

      legacy: false
    };
  }


  /*
   * ALTES BASE64-FORMAT
   */

  try {
    const derived =
      await derivePasswordHash(
        password,
        base64ToBytes(
          storedSalt
        )
      );

    return {
      valid:
        bytesToBase64(
          derived
        ) ===
        storedHash,

      legacy: true
    };

  } catch {
    return {
      valid: false,
      legacy: false
    };
  }
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


  if (
    !username ||
    !password
  ) {
    return json(
      {
        ok: false,
        error:
          "Bitte Benutzername und Passwort eingeben."
      },
      400
    );
  }


  const user =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        password_hash,
        password_salt,
        active,
        is_superadmin
      FROM admin_users
      WHERE username = ?
      LIMIT 1
    `)
      .bind(
        username
      )
      .first();


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


  const passwordResult =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );


  if (
    !passwordResult.valid
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
   * Altes Passwortformat automatisch
   * beim ersten erfolgreichen Login
   * in das neue Format umwandeln.
   */

  if (
    passwordResult.legacy
  ) {
    const upgraded =
      await hashPassword(
        password
      );

    const now =
      Math.floor(
        Date.now() / 1000
      );

    await env.DB.prepare(`
      UPDATE admin_users
      SET
        password_hash = ?,
        password_salt = ?,
        updated_at = ?
      WHERE id = ?
    `)
      .bind(
        upgraded.hash,
        upgraded.salt,
        now,
        user.id
      )
      .run();
  }


  const sessionId =
    await createSession(
      env,
      user.username
    );


  return json(
    {
      ok: true,
      username:
        user.username,
      is_superadmin:
        !!user.is_superadmin
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
      .bind(
        sessionId
      )
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
   /API/ME
========================================================= */

async function handleMe(
  request,
  env
) {
  const auth =
    await requireSession(
      request,
      env
    );

  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const permissions = {};


  for (
    const resource of
      Object.keys(
        RESOURCE_LABELS
      )
  ) {

    if (
      resource ===
      "dashboard"
    ) {
      permissions[
        resource
      ] = {
        can_view: 1,
        can_create: 0,
        can_edit: 0,
        can_delete: 0
      };

      continue;
    }


    const row =
      await env.DB.prepare(`
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
        .bind(
          auth.user.id,
          resource
        )
        .first();


    permissions[
      resource
    ] =
      auth.user.is_superadmin
        ? {
            can_view: 1,
            can_create: 1,
            can_edit: 1,
            can_delete: 1
          }
        : {
            can_view:
              Number(
                row?.can_view || 0
              ),

            can_create:
              Number(
                row?.can_create || 0
              ),

            can_edit:
              Number(
                row?.can_edit || 0
              ),

            can_delete:
              Number(
                row?.can_delete || 0
              )
          };
  }


  return json({
    ok: true,

    username:
      auth.user.username,

    is_superadmin:
      !!auth.user.is_superadmin,

    expiresAt:
      auth.session.expires_at,

    permissions
  });
}


/* =========================================================
   ADMIN USERS - LIST
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

  if (
    auth instanceof Response
  ) {
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
        .bind(
          user.id
        )
        .all();


    user.permissions =
      permissions.results ||
      [];
  }


  return json({
    ok: true,
    users:
      result
  });
}


/* =========================================================
   ADMIN USER - CREATE
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

  if (
    auth instanceof Response
  ) {
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


  if (
    username.length < 2
  ) {
    return json(
      {
        ok: false,
        error:
          "Der Benutzername muss mindestens 2 Zeichen lang sein."
      },
      400
    );
  }


  if (
    password.length < 8
  ) {
    return json(
      {
        ok: false,
        error:
          "Das Passwort muss mindestens 8 Zeichen lang sein."
      },
      400
    );
  }


  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM admin_users
      WHERE username = ?
      LIMIT 1
    `)
      .bind(
        username
      )
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


  return json(
    {
      ok: true,

      user: {
        id:
          userId,

        username:
          username,

        active:
          active,

        is_superadmin:
          isSuperadmin,

        created_at:
          now,

        updated_at:
          now,

        permissions: []
      }
    },
    201
  );
}


/* =========================================================
   ADMIN USER - DELETE
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

  if (
    auth instanceof Response
  ) {
    return auth;
  }


  if (
    userId ===
    auth.user.id
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
    await env.DB.prepare(`
      SELECT
        id,
        username
      FROM admin_users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(
        userId
      )
      .first();


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


  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(
      userId
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(
      user.username
    )
    .run();


  await env.DB.prepare(`
    DELETE FROM admin_users
    WHERE id = ?
  `)
    .bind(
      userId
    )
    .run();


  return json({
    ok: true
  });
}


/* =========================================================
   ADMIN USER - PERMISSIONS
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

  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const user =
    await env.DB.prepare(`
      SELECT
        id,
        is_superadmin
      FROM admin_users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(
        userId
      )
      .first();


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


  if (
    user.is_superadmin
  ) {
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
   * Alte Rechte vollständig löschen
   */
  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(
      userId
    )
    .run();


  /*
   * Neue Rechte speichern
   */
  for (
    const permission
    of permissions
  ) {

    const resource =
      String(
        permission?.resource || ""
      ).trim();


    if (
      !RESOURCE_LABELS[
        resource
      ] ||
      resource ===
        "dashboard"
    ) {
      continue;
    }


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
        crypto.randomUUID(),
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
   PASSWORD RESET
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

  if (
    auth instanceof Response
  ) {
    return auth;
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


  if (
    password.length < 8
  ) {
    return json(
      {
        ok: false,
        error:
          "Das Passwort muss mindestens 8 Zeichen lang sein."
      },
      400
    );
  }


  const passwordData =
    await hashPassword(
      password
    );


  const now =
    Math.floor(
      Date.now() / 1000
    );


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
   * Alte Sessions beenden.
   */
  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(
      user.username
    )
    .run();


  return json({
    ok: true,
    message:
      "Passwort wurde erfolgreich zurückgesetzt."
  });
}


/* =========================================================
   TABLE SCHEMA
========================================================= */

async function getTableSchema(
  env,
  table
) {
  return await env.DB.prepare(
    `PRAGMA table_info("${table}")`
  ).all();
}


function getIdentityColumn(
  schema
) {
  const columns =
    schema.results || [];


  /*
   * Primärschlüssel bevorzugen
   */
  const primary =
    columns.filter(
      column =>
        Number(
          column.pk
        ) === 1
    );


  if (
    primary.length === 1
  ) {
    return primary[0];
  }


  /*
   * Fallback auf "id"
   */
  return (
    columns.find(
      column =>
        column.name ===
        "id"
    ) || null
  );
}


function quoteIdentifier(
  value
) {
  if (
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(
      value
    )
  ) {
    throw new Error(
      "Ungültiger Datenbank-Bezeichner."
    );
  }

  return `"${value}"`;
}


/* =========================================================
   ADMIN SCHEMA
========================================================= */

async function handleAdminSchema(
  request,
  env,
  resource
) {
  const auth =
    await requirePermission(
      request,
      env,
      resource,
      "view"
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const table =
    RESOURCES[
      resource
    ];


  if (!table) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const schema =
    await getTableSchema(
      env,
      table
    );


  return json({
    ok: true,

    resource,

    label:
      RESOURCE_LABELS[
        resource
      ],

    table,

    identity:
      getIdentityColumn(
        schema
      )?.name || null,

    columns:
      schema.results || []
  });
}


/* =========================================================
   PERMISSION CHECK
========================================================= */

async function requirePermission(
  request,
  env,
  resource,
  action
) {
  const auth =
    await requireSession(
      request,
      env
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  /*
   * Superadmin darf alles.
   */
  if (
    auth.user.is_superadmin
  ) {
    return auth;
  }


  /*
   * Dashboard darf grundsätzlich
   * angezeigt werden.
   */
  if (
    resource ===
      "dashboard" &&
    action ===
      "view"
  ) {
    return auth;
  }


  if (
    !RESOURCE_LABELS[
      resource
    ]
  ) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const permission =
    await env.DB.prepare(`
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
      .bind(
        auth.user.id,
        resource
      )
      .first();


  const permissionField =
    `can_${action}`;


  if (
    Number(
      permission?.[
        permissionField
      ] || 0
    ) !== 1
  ) {
    return json(
      {
        ok: false,
        error:
          "Keine Berechtigung für diesen Bereich."
      },
      403
    );
  }


  return auth;
}


/* =========================================================
   ADMIN DATA - GET
========================================================= */

async function handleAdminDataGet(
  request,
  env,
  resource
) {
  const auth =
    await requirePermission(
      request,
      env,
      resource,
      "view"
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const table =
    RESOURCES[
      resource
    ];


  if (!table) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const result =
    await env.DB.prepare(
      `SELECT * FROM ${quoteIdentifier(table)}`
    ).all();


  return json({
    ok: true,

    resource,

    rows:
      result.results || []
  });
}


/* =========================================================
   ADMIN DATA - CREATE
========================================================= */

async function handleAdminDataCreate(
  request,
  env,
  resource
) {
  const auth =
    await requirePermission(
      request,
      env,
      resource,
      "create"
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const table =
    RESOURCES[
      resource
    ];


  if (!table) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const schema =
    await getTableSchema(
      env,
      table
    );


  const columns =
    schema.results || [];


  if (!columns.length) {
    return json(
      {
        ok: false,
        error:
          "Tabelle wurde nicht gefunden."
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


  if (
    !body ||
    typeof body !==
      "object" ||
    Array.isArray(body)
  ) {
    return json(
      {
        ok: false,
        error:
          "Ungültige Daten."
      },
      400
    );
  }


  const data = {};


  /*
   * Nur tatsächlich vorhandene Spalten
   * übernehmen.
   */
  for (
    const column of
      columns
  ) {

    const name =
      column.name;


    /*
     * Zeitfelder werden unten
     * automatisch gesetzt.
     */
    if (
      name ===
        "created_at" ||
      name ===
        "updated_at"
    ) {
      continue;
    }


    if (
      Object.prototype.hasOwnProperty.call(
        body,
        name
      )
    ) {
      data[name] =
        body[name];
    }
  }


  /*
   * AUTOMATISCHE ID
   *
   * Wichtig:
   * D1 verwendet bei uns TEXT-IDs.
   *
   * Deshalb wird eine UUID erzeugt,
   * sobald die Tabelle eine id-Spalte
   * besitzt und keine ID vom Frontend
   * geliefert wurde.
   */
  const identity =
    getIdentityColumn(
      schema
    );


  if (
    identity &&
    identity.name ===
      "id" &&
    !Object.prototype.hasOwnProperty.call(
      data,
      "id"
    )
  ) {

    const identityType =
      String(
        identity.type || ""
      ).toUpperCase();


    if (
      identityType.includes(
        "TEXT"
      ) ||
      identityType.includes(
        "CHAR"
      ) ||
      identityType.includes(
        "CLOB"
      )
    ) {
      data.id =
        crypto.randomUUID();
    }
  }


  /*
   * Zeitstempel
   */
  const now =
    Math.floor(
      Date.now() / 1000
    );


  if (
    columns.some(
      column =>
        column.name ===
        "created_at"
    )
  ) {
    data.created_at =
      now;
  }


  if (
    columns.some(
      column =>
        column.name ===
        "updated_at"
    )
  ) {
    data.updated_at =
      now;
  }


  /*
   * Pflichtfelder prüfen.
   */
  for (
    const column of
      columns
  ) {

    const present =
      Object.prototype.hasOwnProperty.call(
        data,
        column.name
      );


    if (
      Number(
        column.notnull
      ) === 1 &&

      Number(
        column.pk
      ) === 0 &&

      column.dflt_value ===
        null &&

      !present
    ) {
      return json(
        {
          ok: false,
          error:
            `Pflichtfeld fehlt: ${column.name}`
        },
        400
      );
    }
  }


  const keys =
    Object.keys(
      data
    );


  if (!keys.length) {
    return json(
      {
        ok: false,
        error:
          "Keine Daten zum Speichern."
      },
      400
    );
  }


  const columnList =
    keys
      .map(
        quoteIdentifier
      )
      .join(", ");


  const placeholders =
    keys
      .map(
        () => "?"
      )
      .join(", ");


  const values =
    keys.map(
      key =>
        data[key]
    );


  await env.DB.prepare(`
    INSERT INTO ${quoteIdentifier(table)}
      (${columnList})
    VALUES
      (${placeholders})
  `)
    .bind(
      ...values
    )
    .run();


  return json(
    {
      ok: true,
      row:
        data
    },
    201
  );
}


/* =========================================================
   ADMIN DATA - UPDATE
========================================================= */

async function handleAdminDataUpdate(
  request,
  env,
  resource,
  recordId
) {
  const auth =
    await requirePermission(
      request,
      env,
      resource,
      "edit"
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const table =
    RESOURCES[
      resource
    ];


  if (!table) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const schema =
    await getTableSchema(
      env,
      table
    );


  const columns =
    schema.results || [];


  const identity =
    getIdentityColumn(
      schema
    );


  if (!identity) {
    return json(
      {
        ok: false,
        error:
          "Diese Tabelle besitzt keinen eindeutigen Identifikator."
      },
      400
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


  const allowed =
    new Set(
      columns.map(
        column =>
          column.name
      )
    );


  const data = {};


  for (
    const [
      key,
      value
    ] of Object.entries(
      body || {}
    )
  ) {

    if (
      !allowed.has(
        key
      )
    ) {
      continue;
    }


    /*
     * Primärschlüssel nicht verändern.
     */
    if (
      key ===
      identity.name
    ) {
      continue;
    }


    /*
     * created_at niemals überschreiben.
     */
    if (
      key ===
        "created_at"
    ) {
      continue;
    }


    /*
     * updated_at wird automatisch
     * gesetzt.
     */
    if (
      key ===
        "updated_at"
    ) {
      continue;
    }


    data[key] =
      value;
  }


  if (
    allowed.has(
      "updated_at"
    )
  ) {
    data.updated_at =
      Math.floor(
        Date.now() / 1000
      );
  }


  const keys =
    Object.keys(
      data
    );


  if (!keys.length) {
    return json(
      {
        ok: false,
        error:
          "Keine Änderungen übergeben."
      },
      400
    );
  }


  const setList =
    keys
      .map(
        key =>
          `${quoteIdentifier(
            key
          )} = ?`
      )
      .join(", ");


  const values =
    keys.map(
      key =>
        data[key]
    );


  await env.DB.prepare(`
    UPDATE ${quoteIdentifier(table)}
    SET ${setList}
    WHERE ${quoteIdentifier(
      identity.name
    )} = ?
  `)
    .bind(
      ...values,
      recordId
    )
    .run();


  return json({
    ok: true
  });
}


/* =========================================================
   ADMIN DATA - DELETE
========================================================= */

async function handleAdminDataDelete(
  request,
  env,
  resource,
  recordId
) {
  const auth =
    await requirePermission(
      request,
      env,
      resource,
      "delete"
    );


  if (
    auth instanceof Response
  ) {
    return auth;
  }


  const table =
    RESOURCES[
      resource
    ];


  if (!table) {
    return json(
      {
        ok: false,
        error:
          "Unbekannter Bereich."
      },
      404
    );
  }


  const schema =
    await getTableSchema(
      env,
      table
    );


  const identity =
    getIdentityColumn(
      schema
    );


  if (!identity) {
    return json(
      {
        ok: false,
        error:
          "Diese Tabelle besitzt keinen eindeutigen Identifikator."
      },
      400
    );
  }


  await env.DB.prepare(`
    DELETE FROM ${quoteIdentifier(table)}
    WHERE ${quoteIdentifier(
      identity.name
    )} = ?
  `)
    .bind(
      recordId
    )
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
      new URL(
        request.url
      );


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
         ADMIN USERS - GET
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

      const permissionsMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/permissions$/
        );


      if (
        permissionsMatch &&
        request.method ===
          "PUT"
      ) {

        return await handleAdminPermissionsUpdate(
          request,
          env,
          permissionsMatch[1]
        );

      }


      /* ---------------------------------------------
         ADMIN USERS - PASSWORD RESET
      --------------------------------------------- */

      const passwordMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/password$/
        );


      if (
        passwordMatch &&
        request.method ===
          "POST"
      ) {

        return await handleAdminPasswordReset(
          request,
          env,
          passwordMatch[1]
        );

      }


      /* ---------------------------------------------
         ADMIN SCHEMA
      --------------------------------------------- */

      const schemaMatch =
        url.pathname.match(
          /^\/api\/admin\/schema\/([^/]+)$/
        );


      if (
        schemaMatch &&
        request.method ===
          "GET"
      ) {

        return await handleAdminSchema(
          request,
          env,
          schemaMatch[1]
        );

      }


      /* ---------------------------------------------
         ADMIN DATA - GET / CREATE
      --------------------------------------------- */

      const dataMatch =
        url.pathname.match(
          /^\/api\/admin\/data\/([^/]+)$/
        );


      if (dataMatch) {

        const resource =
          dataMatch[1];


        if (
          request.method ===
          "GET"
        ) {

          return await handleAdminDataGet(
            request,
            env,
            resource
          );

        }


        if (
          request.method ===
          "POST"
        ) {

          return await handleAdminDataCreate(
            request,
            env,
            resource
          );

        }

      }


      /* ---------------------------------------------
         ADMIN DATA - UPDATE / DELETE
      --------------------------------------------- */

      const dataIdMatch =
        url.pathname.match(
          /^\/api\/admin\/data\/([^/]+)\/([^/]+)$/
        );


      if (dataIdMatch) {

        const resource =
          dataIdMatch[1];

        const recordId =
          decodeURIComponent(
            dataIdMatch[2]
          );


        if (
          request.method ===
          "PUT"
        ) {

          return await handleAdminDataUpdate(
            request,
            env,
            resource,
            recordId
          );

        }


        if (
          request.method ===
          "DELETE"
        ) {

          return await handleAdminDataDelete(
            request,
            env,
            resource,
            recordId
          );

        }

      }


      /* ---------------------------------------------
         WEBSITE / PUBLIC FILES
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
