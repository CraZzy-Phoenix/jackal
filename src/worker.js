const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;


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
 * COOKIE AUSLESEN
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


/*******************************************************
 * SESSION COOKIE
 *******************************************************/

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
 * SESSION ERSTELLEN
 *******************************************************/

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


/*******************************************************
 * SESSION AUSLESEN
 *******************************************************/

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
 * ADMIN USER AUS SESSION LADEN
 *******************************************************/

async function getAdminUser(session, env) {
  if (!session) {
    return null;
  }

  const user = await env.DB.prepare(`
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
    .bind(session.username)
    .first();

  return user || null;
}


/*******************************************************
 * SESSION ERFORDERN
 *******************************************************/

async function requireSession(request, env) {
  const session = await getSession(
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

  const user = await getAdminUser(
    session,
    env
  );

  if (!user || !user.active) {
    return json(
      {
        ok: false,
        error: "Benutzer ist nicht aktiv."
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
 *
 * action:
 * view
 * create
 * edit
 * delete
 *******************************************************/

async function hasPermission(
  request,
  env,
  resource,
  action
) {
  const session = await getSession(
    request,
    env
  );

  if (!session) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error: "Nicht angemeldet."
        },
        401
      )
    };
  }

  const user = await getAdminUser(
    session,
    env
  );

  if (!user) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error: "Benutzer nicht gefunden."
        },
        403
      )
    };
  }

  if (!user.active) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error: "Benutzer ist nicht aktiv."
        },
        403
      )
    };
  }


  /*
   * SUPERADMIN
   *
   * Superadmins dürfen alles.
   */

  if (Number(user.is_superadmin) === 1) {
    return {
      allowed: true,
      session,
      user
    };
  }


  /*
   * NORMALE BENUTZER
   *
   * Rechte aus admin_permissions laden.
   */

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
    .bind(
      user.id,
      resource
    )
    .first();


  /*
   * Kein Rechte-Eintrag
   */

  if (!permission) {
    return {
      allowed: false,
      response: json(
        {
          ok: false,
          error: "Keine Berechtigung."
        },
        403
      )
    };
  }


  /*
   * Gewünschtes Recht prüfen
   */

  const permissionKey = `can_${action}`;

  const allowed =
    Number(permission[permissionKey]) === 1;


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


/*******************************************************
 * BERECHTIGUNG ERFORDERN
 *******************************************************/

async function requirePermission(
  request,
  env,
  resource,
  action
) {
  const result = await hasPermission(
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
   * AKTUELLER LOGIN
   *
   * Die Zugangsdaten für den ersten
   * Superadmin kommen aus Cloudflare Secrets:
   *
   * ADMIN_USERNAME
   * ADMIN_PASSWORD
   */

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
   * Prüfen, ob der Benutzer
   * in admin_users existiert.
   */

  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
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
          "Benutzer ist nicht in der Benutzerverwaltung angelegt."
      },
      403
    );
  }


  if (Number(user.active) !== 1) {
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
   * Alte Sessions dieses Benutzers löschen.
   *
   * Dadurch bleiben keine alten Sessions
   * unnötig in der Datenbank liegen.
   */

  await env.DB.prepare(`
    DELETE FROM admin_sessions
    WHERE username = ?
  `)
    .bind(username)
    .run();


  /*
   * Neue Session erstellen
   */

  const sessionId = await createSession(
    env,
    username
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


/*******************************************************
 * LOGOUT
 *******************************************************/

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
      "Set-Cookie":
        sessionCookie("", 0)
    }
  );
}


/*******************************************************
 * AKTUELLER BENUTZER
 *******************************************************/

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


  const user = await getAdminUser(
    session,
    env
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

    user: {
      id: user.id,
      username: user.username,
      active: Number(user.active) === 1,
      isSuperadmin:
        Number(user.is_superadmin) === 1
    },

    session: {
      expiresAt: session.expires_at
    }
  });
}


/*******************************************************
 * RECHTE DES AKTUELLEN BENUTZERS
 *
 * Wird später vom Admin-Frontend benutzt,
 * damit es weiß, welche Bereiche angezeigt
 * bzw. welche Buttons aktiviert werden dürfen.
 *******************************************************/

async function handleMyPermissions(
  request,
  env
) {
  const auth = await requireSession(
    request,
    env
  );

  if (auth instanceof Response) {
    return auth;
  }


  const {
    user
  } = auth;


  /*
   * Superadmin bekommt automatisch
   * alle Rechte.
   */

  if (Number(user.is_superadmin) === 1) {
    return json({
      ok: true,
      isSuperadmin: true,
      permissions: []
    });
  }


  const permissions = await env.DB.prepare(`
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
 * WORKER
 *******************************************************/

export default {
  async fetch(request, env) {
    const url = new URL(
      request.url
    );


    try {

      /*************************************************
       * LOGIN
       *************************************************/

      if (
        url.pathname === "/api/login" &&
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
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return await handleLogout(
          request,
          env
        );
      }


      /*************************************************
       * AKTUELLER BENUTZER
       *************************************************/

      if (
        url.pathname === "/api/me" &&
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
        url.pathname === "/api/my-permissions" &&
        request.method === "GET"
      ) {
        return await handleMyPermissions(
          request,
          env
        );
      }


      /*************************************************
       * SPÄTERE ADMIN-APIS
       *
       * Hier kommen jetzt nach und nach
       * die geschützten CRUD-APIs hin.
       *
       * Beispiel:
       *
       * const auth = await requirePermission(
       *   request,
       *   env,
       *   "news",
       *   "create"
       * );
       *
       * if (auth instanceof Response) {
       *   return auth;
       * }
       *************************************************/


      /*************************************************
       * WEBSITE / PUBLIC FILES
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
