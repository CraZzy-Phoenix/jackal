const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

const ADMIN_RESOURCES = [
  "dashboard",
  "races",
  "drivers",
  "results",
  "news",
  "blacklist",
  "gallery",
  "settings",
  "users"
];

const PERMISSION_ACTIONS = [
  "view",
  "create",
  "edit",
  "delete"
];


/*******************************************************
 * JSON RESPONSE
 *******************************************************/

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


/*******************************************************
 * COOKIE
 *******************************************************/

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


/*******************************************************
 * PASSWORT HASHING
 *
 * Neue Benutzer werden mit PBKDF2 gespeichert.
 *******************************************************/

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}


function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}


async function hashPassword(password, saltBytes = null) {
  const salt =
    saltBytes ||
    crypto.getRandomValues(new Uint8Array(16));

  const encoder = new TextEncoder();

  const passwordKey =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
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
      passwordKey,
      256
    );

  return {
    hash: bytesToBase64(
      new Uint8Array(bits)
    ),
    salt: bytesToBase64(
      salt
    )
  };
}


async function verifyPassword(
  password,
  storedHash,
  storedSalt
) {
  if (!storedHash || !storedSalt) {
    return false;
  }

  const result =
    await hashPassword(
      password,
      base64ToBytes(storedSalt)
    );

  return result.hash === storedHash;
}


/*******************************************************
 * SESSION
 *******************************************************/

async function createSession(env, username) {
  const sessionId = crypto.randomUUID();

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


async function getSession(request, env) {
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

  if (!row) {
    return null;
  }

  return row;
}


/*******************************************************
 * ADMIN USER LADEN
 *******************************************************/

async function getAdminUser(
  session,
  env
) {
  if (!session) {
    return null;
  }

  const user =
    await env.DB.prepare(`
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
      .bind(
        session.username
      )
      .first();

  return user || null;
}


/*******************************************************
 * SESSION ERFORDERN
 *******************************************************/

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
    await getAdminUser(
      session,
      env
    );

  if (!user) {
    return json(
      {
        ok: false,
        error:
          "Benutzer nicht gefunden."
      },
      403
    );
  }

  if (Number(user.active) !== 1) {
    return json(
      {
        ok: false,
        error:
          "Benutzer ist nicht aktiv."
      },
      403
    );
  }

  return {
    session,
    user
  };
}


/*******************************************************
 * BERECHTIGUNG PRÜFEN
 *******************************************************/

async function hasPermission(
  request,
  env,
  resource,
  action
) {
  const session =
    await getSession(
      request,
      env
    );

  if (!session) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error:
            "Nicht angemeldet."
        },
        401
      )
    };
  }

  const user =
    await getAdminUser(
      session,
      env
    );

  if (!user) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error:
            "Benutzer nicht gefunden."
        },
        403
      )
    };
  }

  if (Number(user.active) !== 1) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error:
            "Benutzer ist nicht aktiv."
        },
        403
      )
    };
  }


  /*
   * Superadmin darf alles.
   */

  if (
    Number(user.is_superadmin) === 1
  ) {
    return {
      allowed: true,
      session,
      user
    };
  }


  /*
   * Rechte des Benutzers laden.
   */

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
        user.id,
        resource
      )
      .first();


  if (!permission) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error:
            "Keine Berechtigung."
        },
        403
      )
    };
  }


  const permissionKey =
    `can_${action}`;

  const allowed =
    Number(
      permission[permissionKey]
    ) === 1;


  if (!allowed) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error:
            `Keine Berechtigung für ${action} auf ${resource}.`
        },
        403
      )
    };
  }


  return {
    allowed: true,
    session,
    user,
    permission
  };
}


async function requirePermission(
  request,
  env,
  resource,
  action
) {
  const result =
    await hasPermission(
      request,
      env,
      resource,
      action
    );

  if (!result.allowed) {
    return result.response;
  }

  return result;
}


/*******************************************************
 * LOGIN
 *******************************************************/

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
   * Benutzer aus Datenbank laden.
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


  if (
    Number(user.active) !== 1
  ) {
    return json(
      {
        ok: false,
        error:
          "Dieser Benutzer ist deaktiviert."
      },
      403
    );
  }


  /*
   * Bestehender Superadmin:
   *
   * Brian Jäger kann weiterhin mit
   * den bereits eingerichteten
   * Cloudflare Secrets einloggen.
   *
   * Dadurch müssen wir seinen bisherigen
   * Login nicht kaputtmachen.
   */

  let passwordValid = false;

  if (
    Number(user.is_superadmin) === 1 &&
    username === env.ADMIN_USERNAME &&
    password === env.ADMIN_PASSWORD
  ) {
    passwordValid = true;
  } else {
    passwordValid =
      await verifyPassword(
        password,
        user.password_hash,
        user.password_salt
      );
  }


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


  /*
   * Alte Sessions dieses Benutzers löschen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(username)
    .run();


  /*
   * Neue Session.
   */

  const sessionId =
    await createSession(
      env,
      username
    );


  return json(
    {
      ok: true,
      username: user.username,
      isSuperadmin:
        Number(
          user.is_superadmin
        ) === 1
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


/*******************************************************
 * LOGOUT
 *******************************************************/

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


/*******************************************************
 * ME
 *******************************************************/

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


  const {
    session,
    user
  } = auth;


  return json({
    ok: true,

    user: {
      id: user.id,
      username: user.username,
      active:
        Number(user.active) === 1,
      isSuperadmin:
        Number(
          user.is_superadmin
        ) === 1
    },

    session: {
      expiresAt:
        session.expires_at
    }
  });
}


/*******************************************************
 * EIGENE RECHTE
 *******************************************************/

async function handleMyPermissions(
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


  const {
    user
  } = auth;


  if (
    Number(user.is_superadmin) === 1
  ) {
    return json({
      ok: true,
      isSuperadmin: true,
      permissions: []
    });
  }


  const permissions =
    await env.DB.prepare(`
      SELECT
        resource,
        can_view,
        can_create,
        can_edit,
        can_delete
      FROM admin_permissions
      WHERE user_id = ?
      ORDER BY resource ASC
    `)
      .bind(user.id)
      .all();


  return json({
    ok: true,
    isSuperadmin: false,
    permissions:
      permissions.results || []
  });
}


/*******************************************************
 * BENUTZERLISTE
 *******************************************************/

async function handleListUsers(
  request,
  env
) {
  const auth =
    await requirePermission(
      request,
      env,
      "users",
      "view"
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
    `)
      .all();


  const result =
    users.results || [];


  for (const user of result) {
    const permissions =
      await env.DB.prepare(`
        SELECT
          resource,
          can_view,
          can_create,
          can_edit,
          can_delete
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


/*******************************************************
 * BENUTZER ERSTELLEN
 *******************************************************/

async function handleCreateUser(
  request,
  env
) {
  const auth =
    await requirePermission(
      request,
      env,
      "users",
      "create"
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

  const isSuperadmin =
    body?.isSuperadmin === true ||
    Number(body?.isSuperadmin) === 1;


  if (!username) {
    return json(
      {
        ok: false,
        error:
          "Bitte einen Benutzernamen eingeben."
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
   * Benutzername prüfen.
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
   * Passwort hashen.
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
      1,
      isSuperadmin ? 1 : 0,
      now,
      now
    )
    .run();


  /*
   * Rechte übernehmen.
   */

  await saveUserPermissions(
    env,
    userId,
    body?.permissions
  );


  return json(
    {
      ok: true,
      message:
        "Benutzer erfolgreich erstellt.",
      userId
    },
    201
  );
}


/*******************************************************
 * BENUTZER BEARBEITEN
 *******************************************************/

async function handleUpdateUser(
  request,
  env,
  userId
) {
  const auth =
    await requirePermission(
      request,
      env,
      "users",
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


  const existing =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        active,
        is_superadmin
      FROM admin_users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(userId)
      .first();


  if (!existing) {
    return json(
      {
        ok: false,
        error:
          "Benutzer nicht gefunden."
      },
      404
    );
  }


  const username =
    body?.username !== undefined
      ? String(
          body.username
        ).trim()
      : existing.username;


  const active =
    body?.active !== undefined
      ? (
          body.active === true ||
          Number(body.active) === 1
            ? 1
            : 0
        )
      : Number(existing.active);


  const isSuperadmin =
    body?.isSuperadmin !== undefined
      ? (
          body.isSuperadmin === true ||
          Number(body.isSuperadmin) === 1
            ? 1
            : 0
        )
      : Number(existing.is_superadmin);


  if (!username) {
    return json(
      {
        ok: false,
        error:
          "Benutzername darf nicht leer sein."
      },
      400
    );
  }


  /*
   * Prüfen, ob der Name bereits
   * von einem anderen Benutzer
   * verwendet wird.
   */

  const duplicate =
    await env.DB.prepare(`
      SELECT id
      FROM admin_users
      WHERE username = ?
        AND id != ?
      LIMIT 1
    `)
      .bind(
        username,
        userId
      )
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


  /*
   * Verhindern, dass der letzte
   * Superadmin entfernt wird.
   */

  if (
    Number(existing.is_superadmin) === 1 &&
    (isSuperadmin === 0 || active === 0)
  ) {
    const count =
      await env.DB.prepare(`
        SELECT COUNT(*) AS count
        FROM admin_users
        WHERE is_superadmin = 1
          AND active = 1
      `)
        .first();


    if (
      Number(count?.count || 0) <= 1
    ) {
      return json(
        {
          ok: false,
          error:
            "Der letzte aktive Superadmin kann nicht deaktiviert oder zum normalen Benutzer gemacht werden."
        },
        400
      );
    }
  }


  /*
   * Benutzer aktualisieren.
   */

  const now =
    Math.floor(
      Date.now() / 1000
    );


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


  /*
   * Optional neues Passwort.
   */

  if (
    body?.password !== undefined &&
    String(body.password).length > 0
  ) {
    const password =
      String(
        body.password
      );

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
    `)
      .bind(
        passwordData.hash,
        passwordData.salt,
        now,
        userId
      )
      .run();
  }


  /*
   * Rechte aktualisieren.
   */

  if (
    body?.permissions !== undefined
  ) {
    await saveUserPermissions(
      env,
      userId,
      body.permissions
    );
  }


  /*
   * Falls Benutzer deaktiviert wurde:
   * alle Sessions entfernen.
   */

  if (active === 0) {
    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE username = ?
    `)
      .bind(
        existing.username
      )
      .run();
  }


  /*
   * Falls Benutzername geändert wurde:
   * Sessions ebenfalls entfernen.
   */

  if (
    username !== existing.username
  ) {
    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE username = ?
    `)
      .bind(
        existing.username
      )
      .run();
  }


  return json({
    ok: true,
    message:
      "Benutzer erfolgreich aktualisiert."
  });
}


/*******************************************************
 * BENUTZER LÖSCHEN
 *******************************************************/

async function handleDeleteUser(
  request,
  env,
  userId
) {
  const auth =
    await requirePermission(
      request,
      env,
      "users",
      "delete"
    );

  if (auth instanceof Response) {
    return auth;
  }


  const existing =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        active,
        is_superadmin
      FROM admin_users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(userId)
      .first();


  if (!existing) {
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
   * Eigene Löschung verhindern.
   */

  if (
    existing.id === auth.user.id
  ) {
    return json(
      {
        ok: false,
        error:
          "Du kannst deinen eigenen Benutzer nicht löschen."
      },
      400
    );
  }


  /*
   * Letzten Superadmin schützen.
   */

  if (
    Number(existing.is_superadmin) === 1
  ) {
    const count =
      await env.DB.prepare(`
        SELECT COUNT(*) AS count
        FROM admin_users
        WHERE is_superadmin = 1
          AND active = 1
      `)
        .first();


    if (
      Number(count?.count || 0) <= 1
    ) {
      return json(
        {
          ok: false,
          error:
            "Der letzte aktive Superadmin kann nicht gelöscht werden."
        },
        400
      );
    }
  }


  /*
   * Sessions entfernen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(
      existing.username
    )
    .run();


  /*
   * Rechte entfernen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();


  /*
   * Benutzer löschen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_users
    WHERE id = ?
  `)
    .bind(userId)
    .run();


  return json({
    ok: true,
    message:
      "Benutzer erfolgreich gelöscht."
  });
}


/*******************************************************
 * BENUTZERRECHTE SPEICHERN
 *******************************************************/

async function saveUserPermissions(
  env,
  userId,
  permissions
) {
  /*
   * Alle alten Rechte dieses
   * Benutzers entfernen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_permissions
    WHERE user_id = ?
  `)
    .bind(userId)
    .run();


  if (
    !Array.isArray(permissions)
  ) {
    return;
  }


  const now =
    Math.floor(
      Date.now() / 1000
    );


  for (
    const permission of permissions
  ) {
    const resource =
      String(
        permission?.resource || ""
      ).trim();


    if (
      !ADMIN_RESOURCES.includes(
        resource
      )
    ) {
      continue;
    }


    const canView =
      permission?.can_view === true ||
      Number(
        permission?.can_view
      ) === 1
        ? 1
        : 0;


    const canCreate =
      permission?.can_create === true ||
      Number(
        permission?.can_create
      ) === 1
        ? 1
        : 0;


    const canEdit =
      permission?.can_edit === true ||
      Number(
        permission?.can_edit
      ) === 1
        ? 1
        : 0;


    const canDelete =
      permission?.can_delete === true ||
      Number(
        permission?.can_delete
      ) === 1
        ? 1
        : 0;


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
        canView,
        canCreate,
        canEdit,
        canDelete,
        now,
        now
      )
      .run();
  }
}


/*******************************************************
 * VERFÜGBARE RESSOURCEN
 *******************************************************/

async function handleResources(
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


  return json({
    ok: true,

    resources:
      ADMIN_RESOURCES,

    actions:
      PERMISSION_ACTIONS
  });
}


/*******************************************************
 * ADMIN API ROUTER
 *******************************************************/

async function handleAdminApi(
  request,
  env,
  url
) {
  /*
   * Ressourcen
   */

  if (
    url.pathname ===
      "/api/admin/resources" &&
    request.method === "GET"
  ) {
    return await handleResources(
      request,
      env
    );
  }


  /*
   * Benutzerliste
   */

  if (
    url.pathname ===
      "/api/admin/users" &&
    request.method === "GET"
  ) {
    return await handleListUsers(
      request,
      env
    );
  }


  /*
   * Benutzer erstellen
   */

  if (
    url.pathname ===
      "/api/admin/users" &&
    request.method === "POST"
  ) {
    return await handleCreateUser(
      request,
      env
    );
  }


  /*
   * Benutzer-ID aus URL
   */

  const userMatch =
    url.pathname.match(
      /^\/api\/admin\/users\/([^/]+)$/
    );


  if (userMatch) {
    const userId =
      decodeURIComponent(
        userMatch[1]
      );


    /*
     * Benutzer bearbeiten
     */

    if (
      request.method === "PUT" ||
      request.method === "PATCH"
    ) {
      return await handleUpdateUser(
        request,
        env,
        userId
      );
    }


    /*
     * Benutzer löschen
     */

    if (
      request.method === "DELETE"
    ) {
      return await handleDeleteUser(
        request,
        env,
        userId
      );
    }
  }


  return json(
    {
      ok: false,
      error:
        "Admin-API nicht gefunden."
    },
    404
  );
}


/*******************************************************
 * WORKER
 *******************************************************/

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);


    try {

      /*************************************************
       * LOGIN
       *************************************************/

      if (
        url.pathname ===
          "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }


      /*************************************************
       * LOGOUT
       *************************************************/

      if (
        url.pathname ===
          "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }


      /*************************************************
       * ME
       *************************************************/

      if (
        url.pathname ===
          "/api/me" &&
        request.method === "GET"
      ) {
        return await handleMe(
          request,
          env
        );
      }


      /*************************************************
       * EIGENE RECHTE
       *************************************************/

      if (
        url.pathname ===
          "/api/my-permissions" &&
        request.method === "GET"
      ) {
        return await handleMyPermissions(
          request,
          env
        );
      }


      /*************************************************
       * ADMIN API
       *************************************************/

      if (
        url.pathname.startsWith(
          "/api/admin/"
        )
      ) {
        return await handleAdminApi(
          request,
          env,
          url
        );
      }


      /*************************************************
       * ÖFFENTLICHE WEBSITE
       *************************************************/

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
