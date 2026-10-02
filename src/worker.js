const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

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
        name.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&") +
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

async function createSession(env, username) {
  const sessionId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO admin_sessions (id, username, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionId, username, expiresAt, now).run();

  return sessionId;
}

async function getSession(request, env) {
  const sessionId = getCookie(request, "jackal_admin_session");
  if (!sessionId) return null;

  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`
    SELECT id, username, expires_at
    FROM admin_sessions
    WHERE id = ? AND expires_at > ?
    LIMIT 1
  `).bind(sessionId, now).first();

  return row || null;
}

async function getAdminUserByUsername(env, username) {
  return await env.DB.prepare(`
    SELECT id, username, active, is_superadmin, created_at, updated_at
    FROM admin_users
    WHERE username = ?
    LIMIT 1
  `).bind(username).first();
}

async function requireSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ ok: false, error: "Nicht angemeldet." }, 401);

  const user = await getAdminUserByUsername(env, session.username);
  if (!user || !user.active) {
    return json({ ok: false, error: "Benutzerkonto ist nicht aktiv." }, 403);
  }

  return { session, user };
}

async function requirePermission(request, env, resource, action) {
  const auth = await requireSession(request, env);
  if (auth instanceof Response) return auth;

  if (auth.user.is_superadmin) return auth;

  if (resource === "dashboard" && action === "view") return auth;

  const permission = await env.DB.prepare(`
    SELECT can_view, can_create, can_edit, can_delete
    FROM admin_permissions
    WHERE user_id = ? AND resource = ?
    LIMIT 1
  `).bind(auth.user.id, resource).first();

  const allowed = Boolean(
    permission &&
    Number(permission[`can_${action}`]) === 1
  );

  if (!allowed) {
    return json(
      {
        ok: false,
        error: "Keine Berechtigung für diesen Bereich."
      },
      403
    );
  }

  return auth;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(
      hex.substr(i * 2, 2),
      16
    );
  }

  return bytes;
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

async function derivePasswordHash(password, salt) {
  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
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
  const salt = saltHex
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
      bytesToHex(derived),

    salt:
      bytesToHex(salt)
  };
}

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
   * NEUES FORMAT
   *
   * Hash = 64 Hex-Zeichen
   * Salt = 32 Hex-Zeichen
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
        hexToBytes(storedSalt)
      );

    return {
      valid:
        bytesToHex(derived).toLowerCase() ===
        storedHash.toLowerCase(),

      legacy: false
    };
  }

  /*
   * ALTES FORMAT
   *
   * Frühe Benutzer wurden mit
   * Base64 Hash + Base64 Salt gespeichert.
   */
  try {
    const derived =
      await derivePasswordHash(
        password,
        base64ToBytes(storedSalt)
      );

    return {
      valid:
        bytesToBase64(derived) ===
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

  /*
   * Benutzer aus admin_users laden
   */
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
      .bind(username)
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
   * Alten Passwortdatensatz
   * automatisch auf das neue
   * Format migrieren.
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

  /*
   * Session erstellen
   */
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
      .bind(userId)
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
    .bind(userId)
    .run();

  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(user.username)
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
      .bind(userId)
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

  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  for (
    const permission
    of permissions
  ) {
    const resource =
      String(
        permission?.resource || ""
      ).trim();

    /*
     * Dashboard wird nicht als
     * normale Berechtigung gespeichert.
     */
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

async function getTableSchema(
  env,
  table
) {
  return await env.DB.prepare(
    `PRAGMA table_info(${table})`
  ).all();
}

function getIdentityColumn(
  schema
) {
  const columns =
    schema.results || [];

  const primary =
    columns.filter(
      col =>
        Number(col.pk) === 1
    );

  if (
    primary.length === 1
  ) {
    return primary[0];
  }

  const id =
    columns.find(
      col =>
        col.name ===
        "id"
    );

  if (id) {
    return id;
  }

  const key =
    columns.find(
      col =>
        col.name ===
        "key"
    );

  if (key) {
    return key;
  }

  return null;
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
      "Ungültiger Bezeichner."
    );
  }

  return `"${value.replaceAll(
    '"',
    '""'
  )}"`;
}

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
    RESOURCES[resource];

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
    (schema.results || [])
      .map(
        col => ({
          name:
            col.name,

          type:
            col.type,

          notnull:
            Number(
              col.notnull
            ),

          default:
            col.dflt_value,

          pk:
            Number(
              col.pk
            )
        })
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

    columns
  });
}

function sanitizeData(
  data,
  schemaColumns,
  {
    includeIdentity = true
  } = {}
) {
  const out = {};

  const allowed =
    new Set(
      schemaColumns.map(
        col =>
          col.name
      )
    );

  if (
    !data ||
    typeof data !==
      "object" ||
    Array.isArray(data)
  ) {
    throw new Error(
      "Ungültige Daten."
    );
  }

  for (
    const [
      key,
      value
    ] of Object.entries(data)
  ) {
    if (
      !allowed.has(
        key
      )
    ) {
      continue;
    }

    if (
      !includeIdentity &&
      key === "id"
    ) {
      continue;
    }

    if (
      [
        "created_at",
        "updated_at"
      ].includes(key)
    ) {
      continue;
    }

    out[key] = value;
  }

  return out;
}

function normalizeDbValue(
  value,
  column
) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const type =
    String(
      column.type || ""
    ).toUpperCase();

  if (
    type.includes("INT")
  ) {
    if (
      typeof value ===
      "boolean"
    ) {
      return value
        ? 1
        : 0;
    }

    if (
      value === "true"
    ) {
      return 1;
    }

    if (
      value === "false"
    ) {
      return 0;
    }

    if (
      value === ""
    ) {
      return null;
    }

    const number =
      Number(value);

    return Number.isFinite(
      number
    )
      ? number
      : value;
  }

  return String(value);
}

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
    RESOURCES[resource];

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
    RESOURCES[resource];

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
          "Tabelle nicht gefunden."
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

  const data =
    sanitizeData(
      body,
      columns,
      {
        includeIdentity:
          true
      }
    );

  const identity =
    getIdentityColumn(
      schema
    );

  /*
   * Falls die ID TEXT ist
   * und nicht mitgegeben wurde,
   * automatisch UUID erzeugen.
   */
  if (
    identity &&
    identity.name === "id" &&
    !("id" in data) &&
    String(
      identity.type || ""
    )
      .toUpperCase()
      .includes("CHAR")
  ) {
    data.id =
      crypto.randomUUID();
  }

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    columns.some(
      c =>
        c.name ===
        "created_at"
    ) &&
    data.created_at ===
      undefined
  ) {
    data.created_at =
      now;
  }

  if (
    columns.some(
      c =>
        c.name ===
        "updated_at"
    ) &&
    data.updated_at ===
      undefined
  ) {
    data.updated_at =
      now;
  }

  /*
   * Pflichtfelder prüfen
   */
  for (
    const col of columns
  ) {
    if (
      data[col.name] ===
        undefined &&
      Number(
        col.notnull
      ) === 1 &&
      col.dflt_value ===
        null &&
      Number(
        col.pk
      ) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            `Pflichtfeld fehlt: ${col.name}`
        },
        400
      );
    }
  }

  const keys =
    Object.keys(data);

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

  const values =
    keys.map(
      key =>
        normalizeDbValue(
          data[key],
          columns.find(
            c =>
              c.name ===
              key
          )
        )
    );

  const placeholders =
    keys
      .map(
        () => "?"
      )
      .join(", ");

  const quotedKeys =
    keys
      .map(
        quoteIdentifier
      )
      .join(", ");

  await env.DB.prepare(`
    INSERT INTO ${quoteIdentifier(table)}
      (${quotedKeys})
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
      row: data
    },
    201
  );
}

async function handleAdminDataUpdate(
  request,
  env,
  resource,
  value
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
    RESOURCES[resource];

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
          "Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht bearbeitet werden."
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

  const data =
    sanitizeData(
      body,
      columns,
      {
        includeIdentity:
          true
      }
    );

  /*
   * Primärschlüssel nie bearbeiten.
   */
  delete data[
    identity.name
  ];

  if (
    columns.some(
      c =>
        c.name ===
        "updated_at"
    )
  ) {
    data.updated_at =
      Math.floor(
        Date.now() / 1000
      );
  }

  const keys =
    Object.keys(data);

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

  const sets =
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
        normalizeDbValue(
          data[key],
          columns.find(
            c =>
              c.name ===
              key
          )
        )
    );

  const identityColumn =
    quoteIdentifier(
      identity.name
    );

  const identityValue =
    normalizeDbValue(
      value,
      identity
    );

  const result =
    await env.DB.prepare(`
      UPDATE ${quoteIdentifier(table)}
      SET ${sets}
      WHERE ${identityColumn} = ?
    `)
      .bind(
        ...values,
        identityValue
      )
      .run();

  if (
    !result.success ||
    Number(
      result.meta?.changes || 0
    ) === 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Datensatz wurde nicht gefunden oder nicht geändert."
      },
      404
    );
  }

  return json({
    ok: true
  });
}

async function handleAdminDataDelete(
  request,
  env,
  resource,
  value
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
    RESOURCES[resource];

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
          "Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht gelöscht werden."
      },
      400
    );
  }

  const identityValue =
    normalizeDbValue(
      value,
      identity
    );

  const result =
    await env.DB.prepare(`
      DELETE FROM ${quoteIdentifier(table)}
      WHERE ${quoteIdentifier(identity.name)} = ?
    `)
      .bind(
        identityValue
      )
      .run();

  if (
    !result.success ||
    Number(
      result.meta?.changes || 0
    ) === 0
  ) {
    return json(
      {
        ok: false,
        error:
          "Datensatz wurde nicht gefunden."
      },
      404
    );
  }

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

        const value =
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
            value
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
            value
          );
        }
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
