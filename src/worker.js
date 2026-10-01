const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

const RESOURCES = [
  "races",
  "drivers",
  "results",
  "news",
  "blacklist",
  "gallery",
  "settings",
  "users"
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

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function generateId() {
  return crypto.randomUUID();
}

/* =========================================================
   PASSWORT-HASHING
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

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 120000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);

  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  try {
    const salt = base64ToBytes(storedSalt);
    const expectedHash = base64ToBytes(storedHash);

    const actualHash = await hashPassword(password, salt);

    if (actualHash.length !== expectedHash.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actualHash.length; i++) {
      difference |= actualHash[i] ^ expectedHash[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

/* =========================================================
   SESSION
========================================================= */

async function createSession(env, username) {
  const sessionId = generateId();

  const now = nowSeconds();
  const expiresAt = now + SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO admin_sessions
      (id, username, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(sessionId, username, expiresAt, now)
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

  const now = nowSeconds();

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

async function getUserById(env, userId) {
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
   BOOTSTRAP SUPERADMIN
========================================================= */

/*
 * Beim ersten Login mit den Cloudflare-Secrets:
 *
 * ADMIN_USERNAME
 * ADMIN_PASSWORD
 *
 * wird automatisch ein Superadmin in admin_users angelegt.
 *
 * Dadurch können wir deinen bisherigen Zugang weiterverwenden.
 */

async function ensureBootstrapAdmin(env) {
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
    return;
  }

  const existing = await getUserByUsername(
    env,
    env.ADMIN_USERNAME
  );

  if (existing) {
    return;
  }

  const passwordData = await createPasswordHash(
    env.ADMIN_PASSWORD
  );

  const now = nowSeconds();
  const userId = generateId();

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
      userId,
      env.ADMIN_USERNAME,
      passwordData.hash,
      passwordData.salt,
      now,
      now
    )
    .run();
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
   * Falls der erste Login erfolgt:
   * Cloudflare-Secret-Admin automatisch übernehmen.
   */
  await ensureBootstrapAdmin(env);

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

  const valid = await verifyPassword(
    password,
    user.password_hash,
    user.password_salt
  );

  if (!valid) {
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
   AKTUELLER BENUTZER
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
   SESSION + USER CHECK
========================================================= */

async function requireUser(request, env) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return {
      response: json(
        {
          ok: false,
          error: "Nicht angemeldet."
        },
        401
      )
    };
  }

  const user = await getUserByUsername(
    env,
    session.username
  );

  if (!user || !user.active) {
    return {
      response: json(
        {
          ok: false,
          error: "Benutzer ist nicht mehr aktiv."
        },
        401
      )
    };
  }

  return {
    user
  };
}

/* =========================================================
   BERECHTIGUNGEN
========================================================= */

async function getPermission(
  env,
  userId,
  resource
) {
  return await env.DB.prepare(`
    SELECT
      id,
      user_id,
      resource,
      can_view,
      can_create,
      can_edit,
      can_delete
    FROM admin_permissions
    WHERE user_id = ?
      AND resource = ?
    LIMIT 1
  `)
    .bind(userId, resource)
    .first();
}

async function hasPermission(
  env,
  user,
  resource,
  action
) {
  if (user.is_superadmin) {
    return true;
  }

  if (!RESOURCES.includes(resource)) {
    return false;
  }

  const permission = await getPermission(
    env,
    user.id,
    resource
  );

  if (!permission) {
    return false;
  }

  const field = `can_${action}`;

  return Boolean(permission[field]);
}

async function requirePermission(
  request,
  env,
  resource,
  action
) {
  const result = await requireUser(
    request,
    env
  );

  if (result.response) {
    return result.response;
  }

  const allowed = await hasPermission(
    env,
    result.user,
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

  return result.user;
}

/* =========================================================
   EIGENE RECHTE ABRUFEN
========================================================= */

async function handleMyPermissions(
  request,
  env
) {
  const result = await requireUser(
    request,
    env
  );

  if (result.response) {
    return result.response;
  }

  const user = result.user;

  if (user.is_superadmin) {
    return json({
      ok: true,
      superadmin: true,
      permissions: RESOURCES.map(resource => ({
        resource,
        can_view: 1,
        can_create: 1,
        can_edit: 1,
        can_delete: 1
      }))
    });
  }

  const rows = await env.DB.prepare(`
    SELECT
      resource,
      can_view,
      can_create,
      can_edit,
      can_delete
    FROM admin_permissions
    WHERE user_id = ?
    ORDER BY resource
  `)
    .bind(user.id)
    .all();

  return json({
    ok: true,
    superadmin: false,
    permissions: rows.results || []
  });
}

/* =========================================================
   BENUTZER LISTE
========================================================= */

async function handleUsersList(
  request,
  env
) {
  const user = await requirePermission(
    request,
    env,
    "users",
    "view"
  );

  if (user instanceof Response) {
    return user;
  }

  const rows = await env.DB.prepare(`
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
    users: rows.results || []
  });
}

/* =========================================================
   BENUTZER ANLEGEN
========================================================= */

async function handleUserCreate(
  request,
  env
) {
  const user = await requirePermission(
    request,
    env,
    "users",
    "create"
  );

  if (user instanceof Response) {
    return user;
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

  const active =
    body?.active === undefined
      ? 1
      : body.active
        ? 1
        : 0;

  const isSuperadmin =
    body?.is_superadmin ? 1 : 0;

  if (!username || !password) {
    return json(
      {
        ok: false,
        error:
          "Benutzername und Passwort sind erforderlich."
      },
      400
    );
  }

  if (username.length < 3) {
    return json(
      {
        ok: false,
        error:
          "Der Benutzername muss mindestens 3 Zeichen lang sein."
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

  const existing =
    await getUserByUsername(
      env,
      username
    );

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
   * Nur Superadmins dürfen weitere Superadmins erstellen.
   */
  if (
    isSuperadmin &&
    !user.is_superadmin
  ) {
    return json(
      {
        ok: false,
        error:
          "Nur ein Superadmin darf einen weiteren Superadmin erstellen."
      },
      403
    );
  }

  const passwordData =
    await createPasswordHash(password);

  const now = nowSeconds();
  const userId = generateId();

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
        id: userId,
        username,
        active,
        is_superadmin: isSuperadmin
      }
    },
    201
  );
}

/* =========================================================
   BENUTZER BEARBEITEN
========================================================= */

async function handleUserUpdate(
  request,
  env,
  userId
) {
  const currentUser =
    await requirePermission(
      request,
      env,
      "users",
      "edit"
    );

  if (currentUser instanceof Response) {
    return currentUser;
  }

  const targetUser =
    await getUserById(env, userId);

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

  const active =
    body?.active !== undefined
      ? body.active ? 1 : 0
      : targetUser.active;

  const isSuperadmin =
    body?.is_superadmin !== undefined
      ? body.is_superadmin ? 1 : 0
      : targetUser.is_superadmin;

  const password =
    body?.password !== undefined
      ? String(body.password)
      : "";

  if (!username) {
    return json(
      {
        ok: false,
        error: "Benutzername darf nicht leer sein."
      },
      400
    );
  }

  /*
   * Niemand darf seinen eigenen Superadmin-Status
   * entfernen.
   */
  if (
    targetUser.id === currentUser.id &&
    !isSuperadmin
  ) {
    return json(
      {
        ok: false,
        error:
          "Du kannst deinen eigenen Superadmin-Status nicht entfernen."
      },
      400
    );
  }

  /*
   * Nur Superadmins dürfen Superadmin-Rechte verändern.
   */
  if (
    isSuperadmin !== Boolean(
      targetUser.is_superadmin
    ) &&
    !currentUser.is_superadmin
  ) {
    return json(
      {
        ok: false,
        error:
          "Nur Superadmins dürfen Superadmin-Rechte ändern."
      },
      403
    );
  }

  const duplicate =
    await env.DB.prepare(`
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
        error:
          "Dieser Benutzername wird bereits verwendet."
      },
      409
    );
  }

  const now = nowSeconds();

  if (password) {
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

    const passwordData =
      await createPasswordHash(password);

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
        active,
        isSuperadmin,
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
        active,
        isSuperadmin,
        now,
        userId
      )
      .run();
  }

  return json({
    ok: true
  });
}

/* =========================================================
   BENUTZER LÖSCHEN
========================================================= */

async function handleUserDelete(
  request,
  env,
  userId
) {
  const currentUser =
    await requirePermission(
      request,
      env,
      "users",
      "delete"
    );

  if (currentUser instanceof Response) {
    return currentUser;
  }

  if (currentUser.id === userId) {
    return json(
      {
        ok: false,
        error:
          "Du kannst dich nicht selbst löschen."
      },
      400
    );
  }

  const targetUser =
    await getUserById(env, userId);

  if (!targetUser) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

  /*
   * Ein normaler Benutzer darf niemals einen
   * Superadmin löschen.
   */
  if (
    targetUser.is_superadmin &&
    !currentUser.is_superadmin
  ) {
    return json(
      {
        ok: false,
        error:
          "Nur Superadmins dürfen Superadmins löschen."
      },
      403
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
    .bind(targetUser.username)
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
   RECHTE EINES BENUTZERS
========================================================= */

async function handleUserPermissions(
  request,
  env,
  userId
) {
  const currentUser =
    await requirePermission(
      request,
      env,
      "users",
      "view"
    );

  if (currentUser instanceof Response) {
    return currentUser;
  }

  const targetUser =
    await getUserById(env, userId);

  if (!targetUser) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

  const rows = await env.DB.prepare(`
    SELECT
      resource,
      can_view,
      can_create,
      can_edit,
      can_delete
    FROM admin_permissions
    WHERE user_id = ?
    ORDER BY resource
  `)
    .bind(userId)
    .all();

  return json({
    ok: true,
    user: {
      id: targetUser.id,
      username: targetUser.username,
      is_superadmin:
        Boolean(targetUser.is_superadmin)
    },
    resources: RESOURCES,
    permissions: rows.results || []
  });
}

/* =========================================================
   RECHTE SPEICHERN
========================================================= */

async function handleUserPermissionsUpdate(
  request,
  env,
  userId
) {
  const currentUser =
    await requirePermission(
      request,
      env,
      "users",
      "edit"
    );

  if (currentUser instanceof Response) {
    return currentUser;
  }

  const targetUser =
    await getUserById(env, userId);

  if (!targetUser) {
    return json(
      {
        ok: false,
        error: "Benutzer nicht gefunden."
      },
      404
    );
  }

  if (targetUser.is_superadmin) {
    return json(
      {
        ok: false,
        error:
          "Superadmins benötigen keine einzelnen Berechtigungen."
      },
      400
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

  const permissions =
    Array.isArray(body?.permissions)
      ? body.permissions
      : [];

  const now = nowSeconds();

  /*
   * Alte Rechte entfernen.
   */
  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();

  /*
   * Neue Rechte setzen.
   */
  for (const item of permissions) {
    const resource = String(
      item?.resource || ""
    );

    if (!RESOURCES.includes(resource)) {
      continue;
    }

    const canView =
      item?.can_view ? 1 : 0;

    const canCreate =
      item?.can_create ? 1 : 0;

    const canEdit =
      item?.can_edit ? 1 : 0;

    const canDelete =
      item?.can_delete ? 1 : 0;

    /*
     * Wenn überhaupt kein Recht gesetzt wurde,
     * brauchen wir keinen Datensatz.
     */
    if (
      !canView &&
      !canCreate &&
      !canEdit &&
      !canDelete
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
        generateId(),
        userId,
        resource,
        canView,
        canCreate,
        canEdit,
        canDelete,
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
   ROUTER
========================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      /* -----------------------------------------------
         LOGIN
      ------------------------------------------------ */

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }

      /* -----------------------------------------------
         LOGOUT
      ------------------------------------------------ */

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }

      /* -----------------------------------------------
         ME
      ------------------------------------------------ */

      if (
        url.pathname === "/api/me" &&
        request.method === "GET"
      ) {
        return await handleMe(
          request,
          env
        );
      }

      /* -----------------------------------------------
         EIGENE RECHTE
      ------------------------------------------------ */

      if (
        url.pathname === "/api/me/permissions" &&
        request.method === "GET"
      ) {
        return await handleMyPermissions(
          request,
          env
        );
      }

      /* -----------------------------------------------
         BENUTZER LISTE
      ------------------------------------------------ */

      if (
        url.pathname === "/api/admin/users" &&
        request.method === "GET"
      ) {
        return await handleUsersList(
          request,
          env
        );
      }

      /* -----------------------------------------------
         BENUTZER ANLEGEN
      ------------------------------------------------ */

      if (
        url.pathname === "/api/admin/users" &&
        request.method === "POST"
      ) {
        return await handleUserCreate(
          request,
          env
        );
      }

      /* -----------------------------------------------
         BENUTZER EINZELN
         PATCH = bearbeiten
      ------------------------------------------------ */

      const userMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)$/
        );

      if (
        userMatch &&
        request.method === "PATCH"
      ) {
        return await handleUserUpdate(
          request,
          env,
          userMatch[1]
        );
      }

      /* -----------------------------------------------
         BENUTZER LÖSCHEN
      ------------------------------------------------ */

      if (
        userMatch &&
        request.method === "DELETE"
      ) {
        return await handleUserDelete(
          request,
          env,
          userMatch[1]
        );
      }

      /* -----------------------------------------------
         BENUTZER RECHTE ABRUFEN
      ------------------------------------------------ */

      const permissionMatch =
        url.pathname.match(
          /^\/api\/admin\/users\/([^/]+)\/permissions$/
        );

      if (
        permissionMatch &&
        request.method === "GET"
      ) {
        return await handleUserPermissions(
          request,
          env,
          permissionMatch[1]
        );
      }

      /* -----------------------------------------------
         BENUTZER RECHTE SPEICHERN
      ------------------------------------------------ */

      if (
        permissionMatch &&
        request.method === "PUT"
      ) {
        return await handleUserPermissionsUpdate(
          request,
          env,
          permissionMatch[1]
        );
      }

      /* -----------------------------------------------
         WEBSITE / ASSETS
      ------------------------------------------------ */

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
