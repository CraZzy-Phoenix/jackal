const SESSION_DAYS = 7;
const SESSION_SECONDS = SESSION_DAYS * 24 * 60 * 60;

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
    new RegExp("(?:^|;\\s*)" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)")
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

  if (!row) return null;
  return row;
}

async function requireSession(request, env) {
  const session = await getSession(request, env);
  if (!session) {
    return json({ ok: false, error: "Nicht angemeldet." }, 401);
  }
  return session;
}

async function handleLogin(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Ungültige Anfrage." }, 400);
  }

  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");

  if (!username || !password) {
    return json({ ok: false, error: "Bitte Benutzername und Passwort eingeben." }, 400);
  }

  /*
   * Zugangsdaten kommen aus Cloudflare Secrets:
   * ADMIN_USERNAME
   * ADMIN_PASSWORD
   *
   * Sie stehen dadurch NICHT im HTML und NICHT im Worker-Code.
   */
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
    return json({ ok: false, error: "Benutzername oder Passwort ist falsch." }, 401);
  }

  const sessionId = await createSession(env, username);

  return json(
    { ok: true, username },
    200,
    { "Set-Cookie": sessionCookie(sessionId) }
  );
}

async function handleLogout(request, env) {
  const sessionId = getCookie(request, "jackal_admin_session");

  if (sessionId) {
    await env.DB.prepare(`
      DELETE FROM admin_sessions
      WHERE id = ?
    `).bind(sessionId).run();
  }

  return json(
    { ok: true },
    200,
    { "Set-Cookie": sessionCookie("", 0) }
  );
}

async function handleMe(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return json({ ok: false }, 401);
  }

  return json({
    ok: true,
    username: session.username,
    expiresAt: session.expires_at
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        return await handleLogout(request, env);
      }

      if (url.pathname === "/api/me" && request.method === "GET") {
        return await handleMe(request, env);
      }

      /*
       * Alle späteren Admin-APIs können hier geschützt werden:
       *
       * const session = await requireSession(request, env);
       * if (session instanceof Response) return session;
       */

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ ok: false, error: "Interner Serverfehler." }, 500);
    }
  }
};
