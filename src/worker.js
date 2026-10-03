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

const IMAGE_RESOURCES = new Set([
  "races",
  "drivers",
  "news",
  "blacklist",
  "gallery"
]);

const IMAGE_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif"
};

const MAX_IMAGE_SIZE = 10 * 1024 * 1024;


/* =========================================================
   RESPONSE
========================================================= */

function json(data, status = 200, extraHeaders = {}) {
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
   COOKIE / SESSION
========================================================= */

function getCookie(request, name) {
  const cookie =
    request.headers.get("Cookie") || "";

  const match = cookie.match(
    new RegExp(
      "(?:^|;\\s*)" +
        name.replace(
          /[.*+?^${}()|[\]\\]/g,
          "\\$&"
        ) +
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

function nowSeconds() {
  return Math.floor(
    Date.now() / 1000
  );
}

async function createSession(
  env,
  username
) {
  const sessionId =
    crypto.randomUUID();

  const now =
    nowSeconds();

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
  `).bind(
    sessionId,
    username,
    expiresAt,
    now
  ).run();

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

  return await env.DB.prepare(`
    SELECT
      id,
      username,
      expires_at
    FROM admin_sessions
    WHERE id = ?
      AND expires_at > ?
    LIMIT 1
  `).bind(
    sessionId,
    nowSeconds()
  ).first();
}

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
  `).bind(
    username
  ).first();
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

  if (!user || !user.active) {
    return json(
      {
        ok: false,
        error:
          "Benutzerkonto ist nicht aktiv."
      },
      403
    );
  }

  return {
    session,
    user
  };
}

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

  if (auth instanceof Response) {
    return auth;
  }

  if (auth.user.is_superadmin) {
    return auth;
  }

  if (
    resource === "dashboard" &&
    action === "view"
  ) {
    return auth;
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
    `).bind(
      auth.user.id,
      resource
    ).first();

  const allowed =
    permission &&
    Number(
      permission[
        `can_${action}`
      ]
    ) === 1;

  if (!allowed) {
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

async function requireSuperadmin(
  request,
  env
) {
  const auth =
    await requireSession(
      request,
      env
    );

  if (auth instanceof Response) {
    return auth;
  }

  if (!auth.user.is_superadmin) {
    return json(
      {
        ok: false,
        error:
          "Nur Superadmins dürfen diese Aktion ausführen."
      },
      403
    );
  }

  return auth;
}


/* =========================================================
   CRYPTO / PASSWÖRTER
========================================================= */

function bytesToHex(bytes) {
  return Array
    .from(bytes)
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
        hex.slice(
          i * 2,
          i * 2 + 2
        ),
        16
      );
  }

  return bytes;
}

function base64ToBytes(value) {
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

function bytesToBase64(bytes) {
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
      [
        "deriveBits"
      ]
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

  return new Uint8Array(
    bits
  );
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
        ) === storedHash,
      legacy: true
    };
  } catch {
    return {
      valid: false,
      legacy: false
    };
  }
}

async function sha256Hex(
  value
) {
  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        String(
          value ?? ""
        )
      )
    );

  return bytesToHex(
    new Uint8Array(
      digest
    )
  );
}


/* =========================================================
   LOGIN / LOGOUT / ME
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
    `).bind(
      username
    ).first();

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

  const result =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!result.valid) {
    return json(
      {
        ok: false,
        error:
          "Benutzername oder Passwort ist falsch."
      },
      401
    );
  }

  if (result.legacy) {
    const upgraded =
      await hashPassword(
        password
      );

    await env.DB.prepare(`
      UPDATE admin_users
      SET
        password_hash = ?,
        password_salt = ?,
        updated_at = ?
      WHERE id = ?
    `).bind(
      upgraded.hash,
      upgraded.salt,
      nowSeconds(),
      user.id
    ).run();
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
    `).bind(
      sessionId
    ).run();
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

  if (auth instanceof Response) {
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
      resource === "dashboard"
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
      `).bind(
        auth.user.id,
        resource
      ).first();

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
   BENUTZERVERWALTUNG
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

  const result =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        active,
        is_superadmin,
        created_at,
        updated_at
      FROM admin_users
      ORDER BY
        username COLLATE NOCASE ASC
    `).all();

  const users =
    result.results || [];

  for (
    const user of users
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
      `).bind(
        user.id
      ).all();

    user.permissions =
      permissions.results || [];
  }

  return json({
    ok: true,
    users
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
    `).bind(
      username
    ).first();

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

  const id =
    crypto.randomUUID();

  const now =
    nowSeconds();

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
  `).bind(
    id,
    username,
    passwordData.hash,
    passwordData.salt,
    active,
    isSuperadmin,
    now,
    now
  ).run();

  return json(
    {
      ok: true,
      user: {
        id,
        username,
        active,
        is_superadmin:
          isSuperadmin,
        created_at: now,
        updated_at: now,
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

  if (auth instanceof Response) {
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
    `).bind(
      userId
    ).first();

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
  `).bind(
    userId
  ).run();

  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `).bind(
    user.username
  ).run();

  await env.DB.prepare(`
    DELETE FROM admin_users
    WHERE id = ?
  `).bind(
    userId
  ).run();

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

  if (auth instanceof Response) {
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
    `).bind(
      userId
    ).first();

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

  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `).bind(
    userId
  ).run();

  const now =
    nowSeconds();

  for (
    const permission of
      permissions
  ) {
    const resource =
      String(
        permission?.resource ||
          ""
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
    `).bind(
      crypto.randomUUID(),
      userId,
      resource,
      permission?.can_view ? 1 : 0,
      permission?.can_create ? 1 : 0,
      permission?.can_edit ? 1 : 0,
      permission?.can_delete ? 1 : 0,
      now,
      now
    ).run();
  }

  return json({
    ok: true
  });
}


/* =========================================================
   D1 SCHEMA / CRUD
========================================================= */

async function getTableSchema(
  env,
  table
) {
  return await env.DB.prepare(
    `PRAGMA table_info(${table})`
  ).all();
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

function getIdentityColumn(
  schema
) {
  const columns =
    schema.results || [];

  const primary =
    columns.filter(
      column =>
        Number(column.pk) === 1
    );

  if (
    primary.length === 1
  ) {
    return primary[0];
  }

  return (
    columns.find(
      column =>
        column.name === "id"
    ) ||
    columns.find(
      column =>
        column.name === "key"
    ) ||
    null
  );
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
      column?.type || ""
    ).toUpperCase();

  if (
    type.includes("INT")
  ) {
    if (
      typeof value ===
      "boolean"
    ) {
      return value ? 1 : 0;
    }

    if (value === "true") {
      return 1;
    }

    if (value === "false") {
      return 0;
    }

    if (value === "") {
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

function sanitizeData(
  data,
  columns
) {
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

  const allowed =
    new Set(
      columns.map(
        column =>
          column.name
      )
    );

  const result = {};

  for (
    const [
      key,
      value
    ] of Object.entries(
      data
    )
  ) {
    if (
      !allowed.has(key)
    ) {
      continue;
    }

    if (
      [
        "created_at",
        "updated_at",
        "access_code_hash"
      ].includes(key)
    ) {
      continue;
    }

    result[key] =
      value;
  }

  return result;
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

  if (auth instanceof Response) {
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
      (schema.results || [])
        .filter(
          column =>
            column.name !==
            "access_code_hash"
        )
        .map(
          column => ({
            name:
              column.name,
            type:
              column.type,
            notnull:
              Number(
                column.notnull
              ),
            default:
              column.dflt_value,
            pk:
              Number(
                column.pk
              )
          })
        )
  });
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

  if (auth instanceof Response) {
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
      `SELECT * FROM ${quoteIdentifier(
        table
      )}`
    ).all();

  const rows =
    (
      result.results || []
    ).map(
      row => {
        const safe =
          {
            ...row
          };

        delete safe.password_hash;
        delete safe.password_salt;
        delete safe.access_code_hash;

        return safe;
      }
    );

  return json({
    ok: true,
    resource,
    rows
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

  if (auth instanceof Response) {
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
      columns
    );

  const identity =
    getIdentityColumn(
      schema
    );

  if (
    identity &&
    identity.name === "id" &&
    !("id" in data)
  ) {
    const type =
      String(
        identity.type || ""
      ).toUpperCase();

    if (
      type.includes("TEXT") ||
      type.includes("CHAR") ||
      type.includes("CLOB")
    ) {
      data.id =
        crypto.randomUUID();
    }
  }

  const now =
    nowSeconds();

  if (
    columns.some(
      column =>
        column.name ===
        "created_at"
    )
  ) {
    data.created_at ??=
      now;
  }

  if (
    columns.some(
      column =>
        column.name ===
        "updated_at"
    )
  ) {
    data.updated_at ??=
      now;
  }

  for (
    const column of columns
  ) {
    if (
      data[column.name] ===
        undefined &&
      Number(
        column.notnull
      ) === 1 &&
      column.dflt_value ===
        null &&
      Number(
        column.pk
      ) === 0
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

  const values =
    keys.map(
      key =>
        normalizeDbValue(
          data[key],
          columns.find(
            column =>
              column.name ===
              key
          )
        )
    );

  await env.DB.prepare(`
    INSERT INTO ${quoteIdentifier(
      table
    )} (
      ${keys
        .map(
          quoteIdentifier
        )
        .join(", ")}
    )
    VALUES (
      ${keys
        .map(
          () => "?"
        )
        .join(", ")}
    )
  `).bind(
    ...values
  ).run();

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

  if (auth instanceof Response) {
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

  const data =
    sanitizeData(
      body,
      columns
    );

  delete data[
    identity.name
  ];

  if (
    columns.some(
      column =>
        column.name ===
        "updated_at"
    )
  ) {
    data.updated_at =
      nowSeconds();
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

  const result =
    await env.DB.prepare(`
      UPDATE ${quoteIdentifier(
        table
      )}
      SET
        ${keys
          .map(
            key =>
              `${quoteIdentifier(
                key
              )} = ?`
          )
          .join(", ")}
      WHERE ${quoteIdentifier(
        identity.name
      )} = ?
    `).bind(
      ...keys.map(
        key =>
          normalizeDbValue(
            data[key],
            columns.find(
              column =>
                column.name ===
                key
            )
          )
      ),
      normalizeDbValue(
        value,
        identity
      )
    ).run();

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

  if (auth instanceof Response) {
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
          "Diese Tabelle besitzt keinen eindeutigen Identifikator."
      },
      400
    );
  }

  const identityValue =
    normalizeDbValue(
      value,
      identity
    );

  const oldImageUrls = [];

  if (
    IMAGE_RESOURCES.has(
      resource
    )
  ) {
    const row =
      await env.DB.prepare(`
        SELECT *
        FROM ${quoteIdentifier(
          table
        )}
        WHERE ${quoteIdentifier(
          identity.name
        )} = ?
        LIMIT 1
      `).bind(
        identityValue
      ).first();

    if (row) {
      for (
        const field of [
          "image_url",
          "image",
          "track_image_url"
        ]
      ) {
        if (
          typeof row[field] ===
            "string" &&
          row[field].trim()
        ) {
          oldImageUrls.push(
            row[field].trim()
          );
        }
      }
    }
  }

  const result =
    await env.DB.prepare(`
      DELETE FROM ${quoteIdentifier(
        table
      )}
      WHERE ${quoteIdentifier(
        identity.name
      )} = ?
    `).bind(
      identityValue
    ).run();

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

  for (
    const imageUrl of
      oldImageUrls
  ) {
    try {
      await deleteImageByUrl(
        env,
        imageUrl
      );
    } catch (error) {
      console.error(
        "R2 cleanup failed:",
        error
      );
    }
  }

  return json({
    ok: true
  });
}


/* =========================================================
   R2 BILDER
========================================================= */

function imageResourceAllowed(
  resource
) {
  return IMAGE_RESOURCES.has(
    String(
      resource || ""
    ).trim()
  );
}

function imageKeyFromUrl(
  value
) {
  try {
    const url =
      new URL(
        String(
          value || ""
        ),
        "https://jackalracing.com"
      );

    if (
      !url.pathname.startsWith(
        "/media/"
      )
    ) {
      return null;
    }

    const key =
      decodeURIComponent(
        url.pathname.slice(
          "/media/".length
        )
      );

    if (
      !key ||
      key.includes("..") ||
      key.includes("\\")
    ) {
      return null;
    }

    if (
      !IMAGE_RESOURCES.has(
        key.split("/")[0]
      )
    ) {
      return null;
    }

    return key;
  } catch {
    return null;
  }
}

function publicImageUrl(
  request,
  key
) {
  const origin =
    new URL(
      request.url
    ).origin;

  return (
    `${origin}/media/` +
    key
      .split("/")
      .map(
        encodeURIComponent
      )
      .join("/")
  );
}

async function deleteImageByUrl(
  env,
  imageUrl
) {
  if (!env.IMAGES) {
    return false;
  }

  const key =
    imageKeyFromUrl(
      imageUrl
    );

  if (!key) {
    return false;
  }

  await env.IMAGES.delete(
    key
  );

  return true;
}

async function handleImageUpload(
  request,
  env
) {
  const url =
    new URL(
      request.url
    );

  const resource =
    String(
      url.searchParams.get(
        "resource"
      ) || ""
    ).trim();

  const action =
    String(
      url.searchParams.get(
        "action"
      ) || "edit"
    )
      .trim()
      .toLowerCase();

  if (
    !imageResourceAllowed(
      resource
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Ungültiger Bildbereich."
      },
      400
    );
  }

  if (
    action !== "create" &&
    action !== "edit"
  ) {
    return json(
      {
        ok: false,
        error:
          "Ungültige Upload-Aktion."
      },
      400
    );
  }

  const auth =
    await requirePermission(
      request,
      env,
      resource,
      action
    );

  if (auth instanceof Response) {
    return auth;
  }

  if (!env.IMAGES) {
    return json(
      {
        ok: false,
        error:
          "R2 ist im Worker nicht verbunden."
      },
      500
    );
  }

  const contentType =
    String(
      request.headers.get(
        "Content-Type"
      ) || ""
    ).toLowerCase();

  if (
    !contentType.startsWith(
      "multipart/form-data"
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Upload muss als multipart/form-data erfolgen."
      },
      400
    );
  }

  let formData;

  try {
    formData =
      await request.formData();
  } catch {
    return json(
      {
        ok: false,
        error:
          "Upload-Daten konnten nicht gelesen werden."
      },
      400
    );
  }

  const file =
    formData.get(
      "file"
    );

  if (
    !(file instanceof File)
  ) {
    return json(
      {
        ok: false,
        error:
          "Keine Bilddatei übergeben."
      },
      400
    );
  }

  if (!file.size) {
    return json(
      {
        ok: false,
        error:
          "Die Bilddatei ist leer."
      },
      400
    );
  }

  if (
    file.size >
    MAX_IMAGE_SIZE
  ) {
    return json(
      {
        ok: false,
        error:
          "Das Bild darf maximal 10 MB groß sein."
      },
      413
    );
  }

  const mimeType =
    String(
      file.type || ""
    ).toLowerCase();

  const extension =
    IMAGE_TYPES[
      mimeType
    ];

  if (!extension) {
    return json(
      {
        ok: false,
        error:
          "Nicht unterstütztes Bildformat. Erlaubt sind JPG, PNG, WEBP und GIF."
      },
      415
    );
  }

  const date =
    new Date();

  const year =
    date.getUTCFullYear();

  const month =
    String(
      date.getUTCMonth() + 1
    ).padStart(
      2,
      "0"
    );

  const key =
    `${resource}/${year}/${month}/${crypto.randomUUID()}.${extension}`;

  await env.IMAGES.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          mimeType,
        cacheControl:
          "public, max-age=31536000, immutable"
      },
      customMetadata: {
        resource,
        originalName:
          file.name ||
          "image"
      }
    }
  );

  return json(
    {
      ok: true,
      key,
      url:
        publicImageUrl(
          request,
          key
        ),
      mime_type:
        mimeType,
      size:
        file.size,
      original_name:
        file.name ||
        "image"
    },
    201
  );
}

async function handleImageDelete(
  request,
  env
) {
  const url =
    new URL(
      request.url
    );

  const resource =
    String(
      url.searchParams.get(
        "resource"
      ) || ""
    ).trim();

  const action =
    String(
      url.searchParams.get(
        "action"
      ) || "edit"
    )
      .trim()
      .toLowerCase();

  const imageUrl =
    String(
      url.searchParams.get(
        "url"
      ) || ""
    ).trim();

  if (
    !imageResourceAllowed(
      resource
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Ungültiger Bildbereich."
      },
      400
    );
  }

  if (
    action !== "delete" &&
    action !== "edit"
  ) {
    return json(
      {
        ok: false,
        error:
          "Ungültige Lösch-Aktion."
      },
      400
    );
  }

  const auth =
    await requirePermission(
      request,
      env,
      resource,
      action
    );

  if (auth instanceof Response) {
    return auth;
  }

  const key =
    imageKeyFromUrl(
      imageUrl
    );

  if (!key) {
    return json(
      {
        ok: false,
        error:
          "Ungültige Bild-URL."
      },
      400
    );
  }

  await env.IMAGES.delete(
    key
  );

  return json({
    ok: true
  });
}

async function handlePublicImage(
  request,
  env
) {
  if (!env.IMAGES) {
    return new Response(
      "R2 ist nicht verbunden.",
      {
        status: 500
      }
    );
  }

  if (
    request.method !== "GET" &&
    request.method !== "HEAD"
  ) {
    return new Response(
      "Method Not Allowed",
      {
        status: 405,
        headers: {
          Allow:
            "GET, HEAD"
        }
      }
    );
  }

  const key =
    imageKeyFromUrl(
      request.url
    );

  if (!key) {
    return new Response(
      "Nicht gefunden.",
      {
        status: 404
      }
    );
  }

  const object =
    await env.IMAGES.get(
      key
    );

  if (!object) {
    return new Response(
      "Nicht gefunden.",
      {
        status: 404
      }
    );
  }

  const headers =
    new Headers();

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "ETag",
    object.httpEtag
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  headers.set(
    "X-Content-Type-Options",
    "nosniff"
  );

  return new Response(
    request.method === "HEAD"
      ? null
      : object.body,
    {
      status: 200,
      headers
    }
  );
}


/* =========================================================
   NEXT RACE
========================================================= */

function validAccessCode(
  code
) {
  const value =
    String(
      code || ""
    ).trim();

  return (
    value.length >= 4 &&
    value.length <= 32
  );
}

async function hashAccessCode(
  code
) {
  return await sha256Hex(
    String(
      code || ""
    ).trim()
  );
}

async function handleAdminNextRaceGet(
  request,
  env
) {
  const auth =
    await requirePermission(
      request,
      env,
      "races",
      "view"
    );

  if (auth instanceof Response) {
    return auth;
  }

  const race =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        location,
        date,
        time,
        description,
        status,
        image_url,
        track_image_url,
        is_next,
        created_at,
        CASE
          WHEN access_code_hash IS NULL
            OR TRIM(access_code_hash) = ''
          THEN 0
          ELSE 1
        END AS has_access_code
      FROM races
      WHERE is_next = 1
      ORDER BY id DESC
      LIMIT 1
    `).first();

  return json({
    ok: true,
    race:
      race || null
  });
}

async function handleAdminNextRaceSave(
  request,
  env
) {
  const auth =
    await requirePermission(
      request,
      env,
      "races",
      "edit"
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

  const raceId =
    String(
      body?.race_id ??
        ""
    ).trim();

  const accessCode =
    String(
      body?.access_code ??
        ""
    ).trim();

  if (!raceId) {
    await env.DB.prepare(
      "UPDATE races SET is_next = 0"
    ).run();

    return json({
      ok: true,
      race: null
    });
  }

  const race =
    await env.DB.prepare(`
      SELECT
        id,
        access_code_hash
      FROM races
      WHERE id = ?
      LIMIT 1
    `).bind(
      raceId
    ).first();

  if (!race) {
    return json(
      {
        ok: false,
        error:
          "Das ausgewählte Rennen wurde nicht gefunden."
      },
      404
    );
  }

  let codeHash =
    String(
      race.access_code_hash ||
        ""
    ).trim();

  if (accessCode) {
    if (
      !validAccessCode(
        accessCode
      )
    ) {
      return json(
        {
          ok: false,
          error:
            "Der Zugangscode muss zwischen 4 und 32 Zeichen lang sein."
        },
        400
      );
    }

    codeHash =
      await hashAccessCode(
        accessCode
      );
  }

  if (!codeHash) {
    return json(
      {
        ok: false,
        error:
          "Für dieses Next Race muss ein Zugangscode gesetzt werden."
      },
      400
    );
  }

  await env.DB.prepare(
    "UPDATE races SET is_next = 0"
  ).run();

  await env.DB.prepare(`
    UPDATE races
    SET
      is_next = 1,
      access_code_hash = ?
    WHERE id = ?
  `).bind(
    codeHash,
    raceId
  ).run();

  const saved =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        location,
        date,
        time,
        description,
        status,
        image_url,
        track_image_url,
        is_next,
        created_at,
        1 AS has_access_code
      FROM races
      WHERE id = ?
      LIMIT 1
    `).bind(
      raceId
    ).first();

  return json({
    ok: true,
    race:
      saved || null
  });
}


/* =========================================================
   GESCHÜTZTE RACE DETAILS
========================================================= */

async function handlePublicRaceDetails(
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

  const accessCode =
    String(
      body?.access_code ||
        ""
    ).trim();

  if (
    !validAccessCode(
      accessCode
    )
  ) {
    return json(
      {
        ok: false,
        error:
          "Bitte einen gültigen Zugangscode eingeben."
      },
      400
    );
  }

  const race =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        location,
        date,
        time,
        description,
        status,
        image_url,
        track_image_url,
        access_code_hash
      FROM races
      WHERE is_next = 1
      LIMIT 1
    `).first();

  if (!race) {
    return json(
      {
        ok: false,
        error:
          "Aktuell ist kein Next Race festgelegt."
      },
      404
    );
  }

  const suppliedHash =
    await hashAccessCode(
      accessCode
    );

  if (
    !race.access_code_hash ||
    suppliedHash !==
      String(
        race.access_code_hash
      )
  ) {
    return json(
      {
        ok: false,
        error:
          "Der Zugangscode ist nicht korrekt."
      },
      403
    );
  }

  return json(
    {
      ok: true,
      race: {
        id: race.id,
        name: race.name,
        location:
          race.location,
        date:
          race.date,
        time:
          race.time,
        description:
          race.description,
        status:
          race.status,
        image_url:
          race.image_url,
        track_image_url:
          race.track_image_url
      }
    },
    200,
    {
      "Cache-Control":
        "no-store"
    }
  );
}


/* =========================================================
   PUBLIC DATA
========================================================= */

async function publicRows(
  env,
  table,
  columns
) {
  const schema =
    await getTableSchema(
      env,
      table
    );

  const available =
    new Set(
      (
        schema.results ||
        []
      ).map(
        column =>
          column.name
      )
    );

  const selected =
    columns.filter(
      column =>
        available.has(
          column
        )
    );

  if (!selected.length) {
    return [];
  }

  const result =
    await env.DB.prepare(`
      SELECT
        ${selected
          .map(
            quoteIdentifier
          )
          .join(", ")}
      FROM ${quoteIdentifier(
        table
      )}
    `).all();

  return (
    result.results || []
  );
}

function normalizePublicStatus(
  value
) {
  return String(
    value ?? ""
  )
    .trim()
    .toLowerCase();
}

function isPublicActive(
  value
) {
  return [
    "active",
    "aktiv",
    "aktive",
    "published",
    "1",
    "true",
    "ja"
  ].includes(
    normalizePublicStatus(
      value
    )
  );
}

async function handlePublicData(
  env
) {
  const [
    races,
    drivers,
    news,
    blacklist,
    gallery,
    results
  ] =
    await Promise.all([
      publicRows(
        env,
        "races",
        [
          "id",
          "name",
          "location",
          "date",
          "time",
          "description",
          "status",
          "image_url",
          "is_next",
          "created_at"
        ]
      ),

      publicRows(
        env,
        "drivers",
        [
          "id",
          "name",
          "nickname",
          "number",
          "team",
          "car",
          "image_url",
          "status",
          "points",
          "wins",
          "created_at"
        ]
      ),

      publicRows(
        env,
        "news",
        [
          "id",
          "date",
          "title",
          "text",
          "content",
          "image",
          "image_url",
          "category",
          "status",
          "active",
          "created_at"
        ]
      ),

      publicRows(
        env,
        "blacklist",
        [
          "id",
          "vehicle_name",
          "reason",
          "image_url",
          "status",
          "created_at"
        ]
      ),

      publicRows(
        env,
        "gallery",
        [
          "id",
          "title",
          "image",
          "image_url",
          "description",
          "category",
          "date",
          "event",
          "car",
          "likes",
          "status",
          "created_at"
        ]
      ),

      publicRows(
        env,
        "race_results",
        [
          "id",
          "race_id",
          "driver_id",
          "position",
          "vehicle",
          "car",
          "time",
          "best_lap",
          "bestlap",
          "points",
          "created_at"
        ]
      )
    ]);

  const publicNews =
    news.filter(
      item => {
        if (
          item.active ===
            undefined &&
          item.status ===
            undefined
        ) {
          return true;
        }

        if (
          item.active !==
            undefined
        ) {
          return isPublicActive(
            item.active
          );
        }

        return isPublicActive(
          item.status
        );
      }
    );

  const publicBlacklist =
    blacklist.filter(
      item =>
        item.status ===
          undefined ||
        isPublicActive(
          item.status
        )
    );

  const racesPerDriver =
    new Map();

  for (
    const result of
      results
  ) {
    if (
      result.driver_id ===
        undefined ||
      result.driver_id ===
        null
    ) {
      continue;
    }

    const driverId =
      String(
        result.driver_id
      );

    if (
      !racesPerDriver.has(
        driverId
      )
    ) {
      racesPerDriver.set(
        driverId,
        new Set()
      );
    }

    if (
      result.race_id !==
        undefined &&
      result.race_id !==
        null &&
      String(
        result.race_id
      ).trim()
    ) {
      racesPerDriver
        .get(
          driverId
        )
        .add(
          String(
            result.race_id
          )
        );
    }
  }

  const publicDrivers =
    drivers.map(
      driver => ({
        ...driver,
        races:
          racesPerDriver.get(
            String(
              driver.id
            )
          )?.size || 0
      })
    );

  const ranking =
    publicDrivers
      .slice()
      .sort(
        (a, b) => {
          const points =
            (
              Number(
                b.points
              ) || 0
            ) -
            (
              Number(
                a.points
              ) || 0
            );

          if (
            points !== 0
          ) {
            return points;
          }

          const wins =
            (
              Number(
                b.wins
              ) || 0
            ) -
            (
              Number(
                a.wins
              ) || 0
            );

          if (
            wins !== 0
          ) {
            return wins;
          }

          return String(
            a.name || ""
          ).localeCompare(
            String(
              b.name || ""
            ),
            "de-DE"
          );
        }
      )
      .map(
        (
          driver,
          index
        ) => ({
          place:
            index + 1,
          ...driver
        })
      );

  const nextRace =
    races.find(
      race =>
        Number(
          race.is_next
        ) === 1
    ) || null;

  return json(
    {
      ok: true,
      generated_at:
        new Date().toISOString(),
      races,
      drivers:
        publicDrivers,
      ranking,
      news:
        publicNews,
      blacklist:
        publicBlacklist,
      gallery,
      results,
      nextRace
    },
    200,
    {
      "Cache-Control":
        "public, max-age=60"
    }
  );
}


/* =========================================================
   CLEAN PUBLIC URLS
========================================================= */

const PUBLIC_PAGES = new Map([
  ["/news", "news"],
  ["/drivers", "drivers"],
  ["/rangliste", "rangliste"],
  ["/races", "races"],
  ["/blacklist", "blacklist"],
  ["/gallery", "gallery"]
]);

async function handlePublicPage(
  request,
  env
) {
  const pathname =
    new URL(
      request.url
    ).pathname;

  const assetName =
    PUBLIC_PAGES.get(
      pathname
    );

  if (!assetName) {
    return null;
  }

  const cleanRequest =
    new Request(
      new URL(
        `/${assetName}`,
        request.url
      ),
      request
    );

  let response =
    await env.ASSETS.fetch(
      cleanRequest
    );

  /*
   * Fallback für den Fall, dass später
   * wieder HTML-Dateien verwendet werden.
   */
  if (
    response.status === 404
  ) {
    response =
      await env.ASSETS.fetch(
        new Request(
          new URL(
            `/${assetName}.html`,
            request.url
          ),
          request
        )
      );
  }

  if (
    response.status === 404
  ) {
    return null;
  }

  const headers =
    new Headers(
      response.headers
    );

  headers.set(
    "Content-Type",
    "text/html; charset=utf-8"
  );

  return new Response(
    response.body,
    {
      status:
        response.status,
      statusText:
        response.statusText,
      headers
    }
  );
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

      /* ===================================================
         AUTH
      =================================================== */

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


      /* ===================================================
         PUBLIC RACE DETAILS
      =================================================== */

      if (
        url.pathname ===
          "/api/public/race-details" &&
        request.method ===
          "POST"
      ) {
        return await handlePublicRaceDetails(
          request,
          env
        );
      }


      /* ===================================================
         PUBLIC DATA
      =================================================== */

      if (
        url.pathname ===
          "/api/public/data" &&
        request.method ===
          "GET"
      ) {
        return await handlePublicData(
          env
        );
      }


      /* ===================================================
         ADMIN NEXT RACE
      =================================================== */

      if (
        url.pathname ===
          "/api/admin/races/next" &&
        request.method ===
          "GET"
      ) {
        return await handleAdminNextRaceGet(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/admin/races/next" &&
        request.method ===
          "POST"
      ) {
        return await handleAdminNextRaceSave(
          request,
          env
        );
      }


      /* ===================================================
         ADMIN MEDIA / R2
      =================================================== */

      if (
        url.pathname ===
          "/api/admin/media/upload" &&
        request.method ===
          "POST"
      ) {
        return await handleImageUpload(
          request,
          env
        );
      }

      if (
        url.pathname ===
          "/api/admin/media" &&
        request.method ===
          "DELETE"
      ) {
        return await handleImageDelete(
          request,
          env
        );
      }


      /* ===================================================
         PUBLIC MEDIA
      =================================================== */

      if (
        url.pathname.startsWith(
          "/media/"
        ) &&
        (
          request.method ===
            "GET" ||
          request.method ===
            "HEAD"
        )
      ) {
        return await handlePublicImage(
          request,
          env
        );
      }


      /* ===================================================
         ADMIN USERS
      =================================================== */

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

      let match =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/permissions$/
        );

      if (
        match &&
        request.method ===
          "PUT"
      ) {
        return await handleAdminPermissionsUpdate(
          request,
          env,
          match[1]
        );
      }

      match =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)$/
        );

      if (
        match &&
        request.method ===
          "DELETE"
      ) {
        return await handleAdminUserDelete(
          request,
          env,
          match[1]
        );
      }


      /* ===================================================
         ADMIN SCHEMA
      =================================================== */

      match =
        url.pathname.match(
          /^\/api\/admin\/schema\/([^/]+)$/
        );

      if (
        match &&
        request.method ===
          "GET"
      ) {
        return await handleAdminSchema(
          request,
          env,
          match[1]
        );
      }


      /* ===================================================
         ADMIN DATA
      =================================================== */

      match =
        url.pathname.match(
          /^\/api\/admin\/data\/([^/]+)$/
        );

      if (match) {
        const resource =
          match[1];

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


      /* ===================================================
         ADMIN DATA + ID
      =================================================== */

      match =
        url.pathname.match(
          /^\/api\/admin\/data\/([^/]+)\/([^/]+)$/
        );

      if (match) {
        const resource =
          match[1];

        const value =
          decodeURIComponent(
            match[2]
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


      /* ===================================================
         CLEAN PUBLIC PAGES
      =================================================== */

      if (
        request.method ===
          "GET"
      ) {
        const page =
          await handlePublicPage(
            request,
            env
          );

        if (page) {
          return page;
        }
      }


      /* ===================================================
         STATIC ASSETS
      =================================================== */

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
