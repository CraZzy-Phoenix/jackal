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

/* Rechte eines Benutzers für einen Bereich. Ergebnisse (Rennergebnisse /
   Ranglisten der Rennen) erben die Rechte von „Rennen“, solange für
   „Ergebnisse“ nichts eigenes eingetragen ist. */
async function getPermissionRow(env, userId, resource) {
  const load = res => env.DB.prepare(`
    SELECT can_view, can_create, can_edit, can_delete
    FROM admin_permissions
    WHERE user_id = ? AND resource = ?
    LIMIT 1
  `).bind(userId, res).first();

  const row = await load(resource);
  if (!row && resource === "results") return await load("races");
  return row;
}

async function requirePermission(request, env, resource, action) {
  const auth = await requireSession(request, env);
  if (auth instanceof Response) return auth;

  if (auth.user.is_superadmin) return auth;

  if (resource === "dashboard" && action === "view") return auth;

  const permission = await getPermissionRow(env, auth.user.id, resource);

  const allowed = Boolean(permission && Number(permission[`can_${action}`]) === 1);

  if (!allowed) {
    return json(
      { ok: false, error: "Keine Berechtigung für diesen Bereich." },
      403
    );
  }

  return auth;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function derivePasswordHash(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
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

async function hashPassword(password, saltHex = null) {
  const salt = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));

  const derived = await derivePasswordHash(password, salt);

  return {
    hash: bytesToHex(derived),
    salt: bytesToHex(salt)
  };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedHash || !storedSalt) return { valid: false, legacy: false };

  // New hex format.
  if (
    storedHash.length === 64 &&
    storedSalt.length === 32 &&
    /^[0-9a-fA-F]+$/.test(storedHash) &&
    /^[0-9a-fA-F]+$/.test(storedSalt)
  ) {
    const derived = await derivePasswordHash(password, hexToBytes(storedSalt));
    return {
      valid: bytesToHex(derived).toLowerCase() === storedHash.toLowerCase(),
      legacy: false
    };
  }

  // Legacy base64 format used by earlier accounts.
  try {
    const derived = await derivePasswordHash(password, base64ToBytes(storedSalt));
    return {
      valid: bytesToBase64(derived) === storedHash,
      legacy: true
    };
  } catch {
    return { valid: false, legacy: false };
  }
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

  const user = await env.DB.prepare(`
    SELECT id, username, password_hash, password_salt, active, is_superadmin
    FROM admin_users
    WHERE username = ?
    LIMIT 1
  `).bind(username).first();

  if (!user) {
    return json({ ok: false, error: "Benutzername oder Passwort ist falsch." }, 401);
  }

  if (!user.active) {
    return json({ ok: false, error: "Dieses Benutzerkonto ist deaktiviert." }, 403);
  }

  const passwordResult = await verifyPassword(
    password,
    user.password_hash,
    user.password_salt
  );

  if (!passwordResult.valid) {
    return json({ ok: false, error: "Benutzername oder Passwort ist falsch." }, 401);
  }

  // Automatically upgrade old password records after a successful login.
  if (passwordResult.legacy) {
    const upgraded = await hashPassword(password);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(`
      UPDATE admin_users
      SET password_hash = ?, password_salt = ?, updated_at = ?
      WHERE id = ?
    `).bind(upgraded.hash, upgraded.salt, now, user.id).run();
  }

  const sessionId = await createSession(env, user.username);

  return json(
    {
      ok: true,
      username: user.username,
      is_superadmin: !!user.is_superadmin
    },
    200,
    { "Set-Cookie": sessionCookie(sessionId) }
  );
}

async function handleLogout(request, env) {
  const sessionId = getCookie(request, "jackal_admin_session");
  if (sessionId) {
    await env.DB.prepare(`DELETE FROM admin_sessions WHERE id = ?`).bind(sessionId).run();
  }

  return json(
    { ok: true },
    200,
    { "Set-Cookie": sessionCookie("", 0) }
  );
}

async function handleMe(request, env) {
  const auth = await requireSession(request, env);
  if (auth instanceof Response) return auth;

  const permissions = {};

  for (const resource of Object.keys(RESOURCE_LABELS)) {
    if (resource === "dashboard") {
      permissions[resource] = {
        can_view: auth.user.is_superadmin ? 1 : 1,
        can_create: 0,
        can_edit: 0,
        can_delete: 0
      };
      continue;
    }

    const row = await getPermissionRow(env, auth.user.id, resource);

    permissions[resource] = auth.user.is_superadmin
      ? { can_view: 1, can_create: 1, can_edit: 1, can_delete: 1 }
      : {
          can_view: Number(row?.can_view || 0),
          can_create: Number(row?.can_create || 0),
          can_edit: Number(row?.can_edit || 0),
          can_delete: Number(row?.can_delete || 0)
        };
  }

  return json({
    ok: true,
    username: auth.user.username,
    is_superadmin: !!auth.user.is_superadmin,
    expiresAt: auth.session.expires_at,
    permissions
  });
}


async function requireSuperadmin(request, env) {
  const auth = await requireSession(request, env);
  if (auth instanceof Response) return auth;

  if (!auth.user.is_superadmin) {
    return json(
      {
        ok: false,
        error: "Nur Superadmins dürfen diesen Bereich verwalten."
      },
      403
    );
  }

  return auth;
}

async function handleAdminUsersGet(request, env) {
  const auth = await requireSuperadmin(request, env);
  if (auth instanceof Response) return auth;

  const users = await env.DB.prepare(`
    SELECT id, username, active, is_superadmin, created_at, updated_at
    FROM admin_users
    ORDER BY username COLLATE NOCASE ASC
  `).all();

  const result = users.results || [];

  for (const user of result) {
    const permissions = await env.DB.prepare(`
      SELECT id, resource, can_view, can_create, can_edit, can_delete, created_at, updated_at
      FROM admin_permissions
      WHERE user_id = ?
      ORDER BY resource ASC
    `).bind(user.id).all();

    user.permissions = permissions.results || [];
  }

  return json({ ok: true, users: result });
}

async function handleAdminUserCreate(request, env) {
  const auth = await requireSuperadmin(request, env);
  if (auth instanceof Response) return auth;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Ungültige Anfrage." }, 400);
  }

  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");
  const active = body?.active === false ? 0 : 1;
  const isSuperadmin = body?.is_superadmin === true ? 1 : 0;

  if (username.length < 2) return json({ ok: false, error: "Der Benutzername muss mindestens 2 Zeichen lang sein." }, 400);
  if (password.length < 8) return json({ ok: false, error: "Das Passwort muss mindestens 8 Zeichen lang sein." }, 400);

  const existing = await env.DB.prepare(`SELECT id FROM admin_users WHERE username = ? LIMIT 1`).bind(username).first();
  if (existing) return json({ ok: false, error: "Dieser Benutzername existiert bereits." }, 409);

  const passwordData = await hashPassword(password);
  const userId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO admin_users (
      id, username, password_hash, password_salt,
      active, is_superadmin, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    userId,
    username,
    passwordData.hash,
    passwordData.salt,
    active,
    isSuperadmin,
    now,
    now
  ).run();

  return json({
    ok: true,
    user: {
      id: userId,
      username,
      active,
      is_superadmin: isSuperadmin,
      created_at: now,
      updated_at: now,
      permissions: []
    }
  }, 201);
}

async function handleAdminUserDelete(request, env, userId) {
  const auth = await requireSuperadmin(request, env);
  if (auth instanceof Response) return auth;

  if (userId === auth.user.id) {
    return json({ ok: false, error: "Du kannst deinen eigenen Superadmin-Account nicht löschen." }, 400);
  }

  const user = await env.DB.prepare(`SELECT id, username FROM admin_users WHERE id = ? LIMIT 1`).bind(userId).first();
  if (!user) return json({ ok: false, error: "Benutzer nicht gefunden." }, 404);

  await env.DB.prepare(`DELETE FROM admin_permissions WHERE user_id = ?`).bind(userId).run();
  await env.DB.prepare(`DELETE FROM admin_sessions WHERE username = ?`).bind(user.username).run();
  await env.DB.prepare(`DELETE FROM admin_users WHERE id = ?`).bind(userId).run();

  return json({ ok: true });
}

async function handleAdminPermissionsUpdate(request, env, userId) {
  const auth = await requireSuperadmin(request, env);
  if (auth instanceof Response) return auth;

  const user = await env.DB.prepare(`SELECT id, is_superadmin FROM admin_users WHERE id = ? LIMIT 1`).bind(userId).first();
  if (!user) return json({ ok: false, error: "Benutzer nicht gefunden." }, 404);

  if (user.is_superadmin) {
    return json({ ok: true, message: "Superadmins besitzen automatisch alle Rechte." });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Ungültige Anfrage." }, 400);
  }

  const permissions = Array.isArray(body?.permissions) ? body.permissions : [];
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`DELETE FROM admin_permissions WHERE user_id = ?`).bind(userId).run();

  for (const permission of permissions) {
    const resource = String(permission?.resource || "").trim();
    if (!RESOURCE_LABELS[resource] || resource === "dashboard") continue;

    await env.DB.prepare(`
      INSERT INTO admin_permissions (
        id, user_id, resource,
        can_view, can_create, can_edit, can_delete,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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

  return json({ ok: true });
}

async function getTableSchema(env, table) {
  return await env.DB.prepare(`PRAGMA table_info(${table})`).all();
}

function getIdentityColumn(schema) {
  const columns = schema.results || [];
  const primary = columns.filter(col => Number(col.pk) === 1);
  if (primary.length === 1) return primary[0];

  const id = columns.find(col => col.name === "id");
  if (id) return id;

  const key = columns.find(col => col.name === "key");
  if (key) return key;

  return null;
}

function quoteIdentifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error("Ungültiger Bezeichner.");
  }
  return `"${value.replaceAll('"', '""')}"`;
}

async function ensureNewsContentColumns(env) {
  const required = [
    { name: "category", type: "TEXT NOT NULL DEFAULT 'ALLGEMEIN'" },
    { name: "text", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "content", type: "TEXT NOT NULL DEFAULT ''" }
  ];

  const schema = await getTableSchema(env, "news");
  const existing = new Set((schema.results || []).map(col => col.name));

  for (const column of required) {
    if (existing.has(column.name)) continue;
    await env.DB.prepare(
      `ALTER TABLE news ADD COLUMN ${quoteIdentifier(column.name)} ${column.type}`
    ).run();
  }
}

/* Rennen ausblenden: Spalte is_hidden (0 = sichtbar, 1 = ausgeblendet).
   Wird bei Bedarf automatisch angelegt; bestehende Rennen bleiben sichtbar. */
let raceVisibilityColumnReady = false;

async function ensureRaceVisibilityColumn(env) {
  if (raceVisibilityColumnReady) return;
  const schema = await getTableSchema(env, "races");
  const existing = new Set((schema.results || []).map(col => col.name));
  if (existing.size && !existing.has("is_hidden")) {
    await env.DB.prepare(
      `ALTER TABLE races ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0`
    ).run();
  }
  raceVisibilityColumnReady = existing.size > 0;
}

async function handleAdminSchema(request, env, resource) {
  const auth = await requirePermission(request, env, resource, "view");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

  if (resource === "news") await ensureNewsContentColumns(env);

  const schema = await getTableSchema(env, table);
  const columns = (schema.results || []).map(col => ({
    name: col.name,
    type: col.type,
    notnull: Number(col.notnull),
    default: col.dflt_value,
    pk: Number(col.pk)
  }));

  return json({
    ok: true,
    resource,
    label: RESOURCE_LABELS[resource],
    table,
    identity: getIdentityColumn(schema)?.name || null,
    columns
  });
}

function sanitizeData(data, schemaColumns, { includeIdentity = true } = {}) {
  const out = {};
  const allowed = new Set(schemaColumns.map(col => col.name));

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Ungültige Daten.");
  }

  for (const [key, value] of Object.entries(data)) {
    if (!allowed.has(key)) continue;
    if (!includeIdentity && key === "id") continue;
    if (["created_at", "updated_at"].includes(key)) continue;
    out[key] = value;
  }

  return out;
}

function normalizeDbValue(value, column) {
  if (value === null || value === undefined) return null;

  const type = String(column.type || "").toUpperCase();
  if (type.includes("INT")) {
    if (typeof value === "boolean") return value ? 1 : 0;
    if (value === "true") return 1;
    if (value === "false") return 0;
    if (value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : value;
  }

  return String(value);
}

async function handleAdminDataGet(request, env, resource) {
  const auth = await requirePermission(request, env, resource, "view");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

  const result = await env.DB.prepare(`SELECT * FROM ${quoteIdentifier(table)}`).all();
  return json({ ok: true, resource, rows: result.results || [] });
}

async function handleAdminDataCreate(request, env, resource) {
  const auth = await requirePermission(request, env, resource, "create");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

  const schema = await getTableSchema(env, table);
  const columns = schema.results || [];
  if (!columns.length) return json({ ok: false, error: "Tabelle nicht gefunden." }, 404);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }

  const data = sanitizeData(body, columns, { includeIdentity: true });
  const identity = getIdentityColumn(schema);

  if (
    identity &&
    identity.name === "id" &&
    !("id" in data) &&
    Number(identity.pk) === 1 &&
    identity.dflt_value === null &&
    !String(identity.type || "").toUpperCase().includes("INT")
  ) {
    data.id = crypto.randomUUID();
  }

  const now = Math.floor(Date.now() / 1000);
  if (columns.some(c => c.name === "created_at") && data.created_at === undefined) data.created_at = now;
  if (columns.some(c => c.name === "updated_at") && data.updated_at === undefined) data.updated_at = now;

  for (const col of columns) {
    if (data[col.name] === undefined && Number(col.notnull) === 1 && col.dflt_value === null && Number(col.pk) === 0) {
      return json({ ok: false, error: `Pflichtfeld fehlt: ${col.name}` }, 400);
    }
  }

  const keys = Object.keys(data);
  if (!keys.length) return json({ ok: false, error: "Keine Daten zum Speichern." }, 400);

  const values = keys.map(key => normalizeDbValue(data[key], columns.find(c => c.name === key)));
  const placeholders = keys.map(() => "?").join(", ");
  const quotedKeys = keys.map(quoteIdentifier).join(", ");

  try {
    await env.DB.prepare(`
      INSERT INTO ${quoteIdentifier(table)} (${quotedKeys})
      VALUES (${placeholders})
    `).bind(...values).run();
  } catch (error) {
    console.error("Admin create DB error:", error);
    const message = String(error?.message || error || "Speichern fehlgeschlagen.");
    return json({
      ok: false,
      error: message.startsWith("D1_ERROR")
        ? message
        : `Speichern fehlgeschlagen: ${message}`
    }, 400);
  }

  return json({ ok: true, row: data }, 201);
}

async function handleAdminDataUpdate(request, env, resource, value) {
  const auth = await requirePermission(request, env, resource, "edit");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

  const schema = await getTableSchema(env, table);
  const columns = schema.results || [];
  const identity = getIdentityColumn(schema);

  if (!identity) {
    return json({ ok: false, error: "Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht bearbeitet werden." }, 400);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }

  const data = sanitizeData(body, columns, { includeIdentity: true });
  delete data[identity.name];

  if (columns.some(c => c.name === "updated_at")) {
    data.updated_at = Math.floor(Date.now() / 1000);
  }

  const keys = Object.keys(data);
  if (!keys.length) return json({ ok: false, error: "Keine Änderungen übergeben." }, 400);

  const sets = keys.map(key => `${quoteIdentifier(key)} = ?`).join(", ");
  const values = keys.map(key => normalizeDbValue(data[key], columns.find(c => c.name === key)));

  const identityColumn = quoteIdentifier(identity.name);
  const identityValue = normalizeDbValue(value, identity);

  const result = await env.DB.prepare(`
    UPDATE ${quoteIdentifier(table)}
    SET ${sets}
    WHERE ${identityColumn} = ?
  `).bind(...values, identityValue).run();

  if (!result.success || Number(result.meta?.changes || 0) === 0) {
    return json({ ok: false, error: "Datensatz wurde nicht gefunden oder nicht geändert." }, 404);
  }

  return json({ ok: true });
}

async function handleAdminDataDelete(request, env, resource, value) {
  const auth = await requirePermission(request, env, resource, "delete");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

  const schema = await getTableSchema(env, table);
  const identity = getIdentityColumn(schema);
  if (!identity) {
    return json({ ok: false, error: "Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht gelöscht werden." }, 400);
  }

  const identityValue = normalizeDbValue(value, identity);

  let oldImageUrl = null;
  if (imageResourceAllowed(resource)) {
    const row = await env.DB.prepare(`
      SELECT *
      FROM ${quoteIdentifier(table)}
      WHERE ${quoteIdentifier(identity.name)} = ?
      LIMIT 1
    `).bind(identityValue).first();

    if (row && typeof row.image_url === "string") {
      oldImageUrl = row.image_url;
    }
  }

  // Remove dependent race results first so driver/race deletes do not fail on foreign keys.
  if (resource === 'drivers') {
    try {
      await env.DB.prepare(`DELETE FROM race_results WHERE driver_id = ?`).bind(identityValue).run();
    } catch (error) {
      console.error('Driver result cleanup failed:', error);
    }
  }

  if (resource === 'races') {
    try {
      await env.DB.prepare(`DELETE FROM race_results WHERE race_id = ?`).bind(identityValue).run();
    } catch (error) {
      console.error('Race result cleanup failed:', error);
    }
  }

  const result = await env.DB.prepare(`
    DELETE FROM ${quoteIdentifier(table)}
    WHERE ${quoteIdentifier(identity.name)} = ?
  `).bind(identityValue).run();

  if (!result.success || Number(result.meta?.changes || 0) === 0) {
    return json({ ok: false, error: "Datensatz wurde nicht gefunden." }, 404);
  }

  if (oldImageUrl) {
    try {
      await deleteImageByUrl(env, oldImageUrl);
    } catch (error) {
      console.error("R2 cleanup failed after record delete:", error);
    }
  }

  return json({ ok: true });
}


/* =========================================================
   R2 BILDSYSTEM
   Gemeinsames Upload-/Abruf-/Löschsystem für die öffentliche
   Website. Das R2-Bucket bleibt privat; Bilder werden über
   den Worker unter /media/... ausgeliefert.
========================================================= */

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

function imageResourceAllowed(resource) {
  return IMAGE_RESOURCES.has(String(resource || "").trim());
}

function imageExtensionFromType(type) {
  return IMAGE_TYPES[String(type || "").toLowerCase()] || null;
}

function imageKeyFromUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;

  try {
    const parsed = new URL(raw, "https://jackalracing.com");
    if (!parsed.pathname.startsWith("/media/")) return null;

    const key = decodeURIComponent(
      parsed.pathname.slice("/media/".length)
    );

    if (!key || key.includes("..") || key.includes("\\")) {
      return null;
    }

    const firstPart = key.split("/")[0];
    if (!imageResourceAllowed(firstPart)) return null;

    return key;
  } catch {
    return null;
  }
}

async function deleteImageByUrl(env, imageUrl) {
  if (!env.IMAGES) return false;

  const key = imageKeyFromUrl(imageUrl);
  if (!key) return false;

  await env.IMAGES.delete(key);
  return true;
}

function publicImageUrl(request, key) {
  const origin = new URL(request.url).origin;
  return `${origin}/media/${key.split("/").map(encodeURIComponent).join("/")}`;
}

async function handleImageUpload(request, env) {
  const url = new URL(request.url);
  const resource = String(url.searchParams.get("resource") || "").trim();
  const action = String(url.searchParams.get("action") || "edit").trim().toLowerCase();

  if (!imageResourceAllowed(resource)) {
    return json({ ok: false, error: "Ungültiger Bildbereich." }, 400);
  }

  if (action !== "create" && action !== "edit") {
    return json({ ok: false, error: "Ungültige Upload-Aktion." }, 400);
  }

  const auth = await requirePermission(request, env, resource, action);
  if (auth instanceof Response) return auth;

  if (!env.IMAGES) {
    return json({ ok: false, error: "R2 ist im Worker nicht verbunden." }, 500);
  }

  const contentType = String(
    request.headers.get("Content-Type") || ""
  ).toLowerCase();

  if (!contentType.startsWith("multipart/form-data")) {
    return json({ ok: false, error: "Upload muss als multipart/form-data erfolgen." }, 400);
  }

  let formData;
  try {
    formData = await request.formData();
  } catch {
    return json({ ok: false, error: "Upload-Daten konnten nicht gelesen werden." }, 400);
  }

  const file = formData.get("file");

  if (!(file instanceof File)) {
    return json({ ok: false, error: "Keine Bilddatei übergeben." }, 400);
  }

  if (!file.size) {
    return json({ ok: false, error: "Die Bilddatei ist leer." }, 400);
  }

  if (file.size > MAX_IMAGE_SIZE) {
    return json({
      ok: false,
      error: "Das Bild darf maximal 10 MB groß sein."
    }, 413);
  }

  const mimeType = String(file.type || "").toLowerCase();
  const extension = imageExtensionFromType(mimeType);

  if (!extension) {
    return json({
      ok: false,
      error: "Nicht unterstütztes Bildformat. Erlaubt sind JPG, PNG, WEBP und GIF."
    }, 415);
  }

  const now = new Date();
  const year = String(now.getUTCFullYear());
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const key = `${resource}/${year}/${month}/${crypto.randomUUID()}.${extension}`;

  await env.IMAGES.put(key, file.stream(), {
    httpMetadata: {
      contentType: mimeType,
      cacheControl: "public, max-age=31536000, immutable"
    },
    customMetadata: {
      resource,
      originalName: file.name || "image"
    }
  });

  return json({
    ok: true,
    key,
    url: publicImageUrl(request, key),
    mime_type: mimeType,
    size: file.size,
    original_name: file.name || "image"
  }, 201);
}

async function handleImageDelete(request, env) {
  const url = new URL(request.url);
  const resource = String(url.searchParams.get("resource") || "").trim();
  const action = String(url.searchParams.get("action") || "edit").trim().toLowerCase();
  const imageUrl = String(url.searchParams.get("url") || "").trim();

  if (!imageResourceAllowed(resource)) {
    return json({ ok: false, error: "Ungültiger Bildbereich." }, 400);
  }

  if (action !== "delete" && action !== "edit") {
    return json({ ok: false, error: "Ungültige Lösch-Aktion." }, 400);
  }

  const auth = await requirePermission(request, env, resource, action);
  if (auth instanceof Response) return auth;

  if (!env.IMAGES) {
    return json({ ok: false, error: "R2 ist im Worker nicht verbunden." }, 500);
  }

  const key = imageKeyFromUrl(imageUrl);
  if (!key) {
    return json({ ok: false, error: "Ungültige Bild-URL." }, 400);
  }

  await env.IMAGES.delete(key);

  return json({ ok: true });
}

async function handlePublicImage(request, env) {
  if (!env.IMAGES) {
    return new Response("R2 ist nicht verbunden.", { status: 500 });
  }

  const url = new URL(request.url);
  if (!url.pathname.startsWith("/media/")) {
    return new Response("Nicht gefunden.", { status: 404 });
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET, HEAD" }
    });
  }

  const key = imageKeyFromUrl(url.origin + url.pathname);
  if (!key) {
    return new Response("Nicht gefunden.", { status: 404 });
  }

  const object = await env.IMAGES.get(key);
  if (!object) {
    return new Response("Nicht gefunden.", { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Cache-Control", "public, max-age=31536000, immutable");
  headers.set("X-Content-Type-Options", "nosniff");

  return new Response(
    request.method === "HEAD" ? null : object.body,
    {
      status: 200,
      headers
    }
  );
}



/* =========================================================
   RENNEN – NEXT RACE / ZUGANGSCODE
========================================================= */

async function hashAccessCode(code) {
  const normalized = String(code || "").trim();
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(normalized)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function validAccessCode(code) {
  const value = String(code || "").trim();
  return value.length >= 4 && value.length <= 32;
}

async function handleAdminNextRaceGet(request, env) {
  const auth = await requirePermission(request, env, "races", "view");
  if (auth instanceof Response) return auth;

  const nextRace = await env.DB.prepare(`
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
    race: nextRace || null
  });
}

async function handleAdminNextRaceSave(request, env) {
  const auth = await requirePermission(request, env, "races", "edit");
  if (auth instanceof Response) return auth;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Ungültige Anfrage." }, 400);
  }

  const raceId = String(body?.race_id ?? "").trim();
  const accessCode = String(body?.access_code ?? "").trim();

  if (!raceId) {
    await env.DB.prepare(`UPDATE races SET is_next = 0`).run();
    return json({ ok: true, race: null });
  }

  const race = await env.DB.prepare(`
    SELECT
      id,
      access_code_hash
    FROM races
    WHERE id = ?
    LIMIT 1
  `).bind(raceId).first();

  if (!race) {
    return json({
      ok: false,
      error: "Das ausgewählte Rennen wurde nicht gefunden."
    }, 404);
  }

  let codeHash = String(race.access_code_hash || "").trim();

  if (accessCode) {
    if (!validAccessCode(accessCode)) {
      return json({
        ok: false,
        error: "Der Zugangscode muss zwischen 4 und 32 Zeichen lang sein."
      }, 400);
    }

    codeHash = await hashAccessCode(accessCode);
  }

  if (!codeHash) {
    return json({
      ok: false,
      error: "Für dieses Next Race muss ein Zugangscode gesetzt werden."
    }, 400);
  }

  await env.DB.prepare(
    `UPDATE races SET is_next = 0`
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

  const saved = await env.DB.prepare(`
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
  `).bind(raceId).first();

  return json({
    ok: true,
    race: saved || null
  });
}


/* =========================================================
   NEWS DASHBOARD – KATEGORIEN & STEUERUNG
========================================================= */

function slugifyNewsCategory(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

function validHexColor(value, fallback = "#A855FF") {
  const v = String(value || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(v)
    ? v.toUpperCase()
    : fallback;
}

function parseJsonArray(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value || "[]"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}


async function ensureNewsDashboardColumns(env) {
  const required = [
    { name: "display_mode", type: "TEXT NOT NULL DEFAULT 'next_race'" },
    { name: "display_race_id", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "bestlist_race_id", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "laps_race_id", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "event_source", type: "TEXT NOT NULL DEFAULT 'race'" },
    { name: "event_news_id", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "event_custom_title", type: "TEXT NOT NULL DEFAULT ''" },
    { name: "event_custom_text", type: "TEXT NOT NULL DEFAULT ''" }
  ];

  const schema = await getTableSchema(env, "news_dashboard");
  const existing = new Set((schema.results || []).map(col => col.name));
  for (const column of required) {
    if (existing.has(column.name)) continue;
    await env.DB.prepare(
      `ALTER TABLE news_dashboard ADD COLUMN ${quoteIdentifier(column.name)} ${column.type}`
    ).run();
  }
}

async function ensureDefaultNewsCategories(env) {
  const defaults = [
    ["blacklist", "BLACKLIST", "#FF3D4D", "#FFFFFF", 10],
    ["fahrer", "FAHRER", "#3D8BFF", "#FFFFFF", 20],
    ["events", "EVENTS", "#A855FF", "#FFFFFF", 30],
    ["rennen", "RENNEN", "#FF8A3D", "#FFFFFF", 40],
    ["abstimmungen", "ABSTIMMUNGEN", "#35D0BA", "#07100D", 50],
    ["sieger-der-herzen", "SIEGER DER HERZEN", "#FF5CAB", "#FFFFFF", 60],
    ["highlights", "HIGHLIGHTS", "#FFD34D", "#15100A", 70],
    ["allgemein", "ALLGEMEIN", "#9E91B8", "#FFFFFF", 80]
  ];

  const legacySlugs = ["event", "ergebnisse", "update", "blacklist-update", "partner"];
  const now = Math.floor(Date.now() / 1000);

  for (const slug of legacySlugs) {
    await env.DB.prepare(
      `UPDATE news_categories SET active = 0, updated_at = ? WHERE slug = ?`
    ).bind(now, slug).run();
  }

  for (const [slug, name, color, textColor, sortOrder] of defaults) {
    const existing = await env.DB.prepare(
      `SELECT id FROM news_categories WHERE slug = ? LIMIT 1`
    ).bind(slug).first();

    if (existing) {
      // Bestehende Kategorien NICHT überschreiben: individuelle Farben/Namen
      // werden ausschließlich über die Kategorieverwaltung gepflegt.
    } else {
      await env.DB.prepare(`
        INSERT INTO news_categories
          (id,name,slug,color,text_color,active,sort_order,created_at,updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).bind(`default-${slug}`, name, slug, color, textColor, sortOrder, now, now).run();
    }
  }
}

function normalizeNewsDashboardConfig(row) {
  return {
    next_race_id: String(row?.next_race_id ?? ""),
    display_mode: String(row?.display_mode || "next_race"),
    display_race_id: String(row?.display_race_id ?? row?.next_race_id ?? ""),
    bestlist_race_id: String(row?.bestlist_race_id ?? ""),
    laps_race_id: String(row?.laps_race_id ?? ""),
    event_source: String(row?.event_source || "race"),
    event_news_id: String(row?.event_news_id ?? ""),
    event_custom_title: String(row?.event_custom_title ?? ""),
    event_custom_text: String(row?.event_custom_text ?? ""),
    latest_news_ids: parseJsonArray(row?.latest_news_ids)
      .map(String)
      .filter(Boolean)
      .slice(0, 3),
    featured_news_id: String(row?.featured_news_id ?? ""),
    hearts_winner_driver_id: String(row?.hearts_winner_driver_id ?? ""),
    hearts_quote: String(row?.hearts_quote ?? ""),
    poll_active: Number(row?.poll_active) === 1 ? 1 : 0,
    poll_question: String(
      row?.poll_question || "Wer war dein Sieger der Herzen?"
    ),
    poll_options: parseJsonArray(row?.poll_options)
      .map(item => ({
        driver_id: String(item?.driver_id || ""),
        percent: Math.max(
          0,
          Math.min(
            100,
            Number(item?.percent) || 0
          )
        )
      }))
      .filter(item => item.driver_id)
      .slice(0, 20)
  };
}

async function handleAdminNewsDashboardGet(request, env) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "view"
  );

  if (auth instanceof Response) return auth;

  try {
    await ensureNewsDashboardColumns(env);
    const row = await env.DB
      .prepare(`
        SELECT
          id,
          next_race_id,
          display_mode,
          display_race_id,
          bestlist_race_id,
          laps_race_id,
          event_source,
          event_news_id,
          event_custom_title,
          event_custom_text,
          latest_news_ids,
          featured_news_id,
          hearts_winner_driver_id,
          hearts_quote,
          poll_active,
          poll_question,
          poll_options,
          updated_at
        FROM news_dashboard
        WHERE id = 1
        LIMIT 1
      `)
      .first();

    return json({
      ok: true,
      config: normalizeNewsDashboardConfig(row || {})
    });
  } catch (error) {
    console.error(
      "News Dashboard GET:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "News-Dashboard konnte nicht geladen werden. Bitte die D1-Migration prüfen."
      },
      500
    );
  }
}

async function handleAdminNewsDashboardSave(request, env) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "edit"
  );

  if (auth instanceof Response) return auth;

  await ensureNewsDashboardColumns(env);

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

  const latestNewsIds = Array.isArray(body?.latest_news_ids)
    ? body.latest_news_ids
        .map(value => String(value))
        .filter(Boolean)
        .slice(0, 3)
    : [];

  const pollOptions = Array.isArray(body?.poll_options)
    ? body.poll_options
        .map(item => ({
          driver_id: String(item?.driver_id || ""),
          percent: Math.max(
            0,
            Math.min(
              100,
              Number(item?.percent) || 0
            )
          )
        }))
        .filter(item => item.driver_id)
        .slice(0, 20)
    : [];

  if (pollOptions.length) {
    const total = pollOptions.reduce(
      (sum, item) =>
        sum + Number(item.percent || 0),
      0
    );

    if (total > 100) {
      return json(
        {
          ok: false,
          error:
            "Die Prozentwerte der Abstimmung dürfen zusammen nicht über 100 % liegen."
        },
        400
      );
    }

    if (body?.poll_active && total !== 100) {
      return json(
        {
          ok: false,
          error:
            "Bei aktiver Abstimmung müssen die Prozentwerte zusammen genau 100 % ergeben."
        },
        400
      );
    }
  } else if (body?.poll_active) {
    return json(
      {
        ok: false,
        error:
          "Für eine aktive Abstimmung müssen mindestens Kandidaten mit Prozentwerten hinterlegt werden."
      },
      400
    );
  }

  const allowedDisplayModes = new Set([
    "next_race",
    "last_race",
    "next_event",
    "last_event",
    "current_event"
  ]);
  const displayMode = allowedDisplayModes.has(String(body?.display_mode || ""))
    ? String(body.display_mode)
    : "next_race";

  const allowedEventSources = new Set(["race", "news", "custom"]);
  const eventSource = allowedEventSources.has(String(body?.event_source || "")) ? String(body.event_source) : "race";

  const config = {
    next_race_id: String(body?.next_race_id ?? ""),
    display_mode: displayMode,
    display_race_id: String(body?.display_race_id ?? body?.next_race_id ?? ""),
    bestlist_race_id: String(body?.bestlist_race_id ?? ""),
    laps_race_id: String(body?.laps_race_id ?? ""),
    event_source: eventSource,
    event_news_id: String(body?.event_news_id ?? ""),
    event_custom_title: String(body?.event_custom_title ?? "").slice(0, 180),
    event_custom_text: String(body?.event_custom_text ?? "").slice(0, 1000),
    latest_news_ids: latestNewsIds,
    featured_news_id: String(
      body?.featured_news_id ?? ""
    ),
    hearts_winner_driver_id: String(
      body?.hearts_winner_driver_id ?? ""
    ),
    hearts_quote: String(
      body?.hearts_quote ?? ""
    ).slice(0, 1000),
    poll_active: body?.poll_active ? 1 : 0,
    poll_question: String(
      body?.poll_question ||
      "Wer war dein Sieger der Herzen?"
    ).slice(0, 300),
    poll_options: pollOptions
  };

  const now = Math.floor(Date.now() / 1000);

  try {
    await env.DB
      .prepare(`
        INSERT INTO news_dashboard (
          id,
          next_race_id,
          display_mode,
          display_race_id,
          bestlist_race_id,
          laps_race_id,
          event_source,
          event_news_id,
          event_custom_title,
          event_custom_text,
          latest_news_ids,
          featured_news_id,
          hearts_winner_driver_id,
          hearts_quote,
          poll_active,
          poll_question,
          poll_options,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id)
        DO UPDATE SET
          next_race_id = excluded.next_race_id,
          display_mode = excluded.display_mode,
          display_race_id = excluded.display_race_id,
          bestlist_race_id = excluded.bestlist_race_id,
          laps_race_id = excluded.laps_race_id,
          event_source = excluded.event_source,
          event_news_id = excluded.event_news_id,
          event_custom_title = excluded.event_custom_title,
          event_custom_text = excluded.event_custom_text,
          latest_news_ids = excluded.latest_news_ids,
          featured_news_id = excluded.featured_news_id,
          hearts_winner_driver_id = excluded.hearts_winner_driver_id,
          hearts_quote = excluded.hearts_quote,
          poll_active = excluded.poll_active,
          poll_question = excluded.poll_question,
          poll_options = excluded.poll_options,
          updated_at = excluded.updated_at
      `)
      .bind(
        1,
        config.next_race_id,
        config.display_mode,
        config.display_race_id,
        config.bestlist_race_id,
        config.laps_race_id,
        config.event_source,
        config.event_news_id,
        config.event_custom_title,
        config.event_custom_text,
        JSON.stringify(config.latest_news_ids),
        config.featured_news_id,
        config.hearts_winner_driver_id,
        config.hearts_quote,
        config.poll_active,
        config.poll_question,
        JSON.stringify(config.poll_options),
        now
      )
      .run();

    return json({
      ok: true,
      config
    });
  } catch (error) {
    console.error(
      "News Dashboard SAVE:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "News-Dashboard konnte nicht gespeichert werden."
      },
      500
    );
  }
}

async function handleAdminNewsCategoriesGet(request, env) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "view"
  );

  if (auth instanceof Response) return auth;

  try {
    await ensureDefaultNewsCategories(env);
    const result = await env.DB
      .prepare(`
        SELECT
          id,
          name,
          slug,
          color,
          text_color,
          active,
          sort_order,
          created_at,
          updated_at
        FROM news_categories
        ORDER BY
          sort_order ASC,
          name COLLATE NOCASE ASC
      `)
      .all();

    return json({
      ok: true,
      categories: result.results || []
    });
  } catch (error) {
    console.error(
      "News Categories GET:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "News-Kategorien konnten nicht geladen werden. Bitte die D1-Migration prüfen."
      },
      500
    );
  }
}

async function handleAdminNewsCategoryCreate(request, env) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "create"
  );

  if (auth instanceof Response) return auth;

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

  const name = String(
    body?.name || ""
  )
    .trim()
    .slice(0, 60);

  if (!name) {
    return json(
      {
        ok: false,
        error:
          "Bitte einen Kategorienamen eingeben."
      },
      400
    );
  }

  const slug = slugifyNewsCategory(name);

  if (!slug) {
    return json(
      {
        ok: false,
        error:
          "Der Kategoriename ist ungültig."
      },
      400
    );
  }

  const color = validHexColor(
    body?.color,
    "#A855FF"
  );

  const textColor = validHexColor(
    body?.text_color,
    "#FFFFFF"
  );

  const sortOrder =
    Number.isFinite(
      Number(body?.sort_order)
    )
      ? Number(body.sort_order)
      : 0;

  const now = Math.floor(
    Date.now() / 1000
  );

  try {
    const duplicate = await env.DB
      .prepare(`
        SELECT id
        FROM news_categories
        WHERE slug = ?
        LIMIT 1
      `)
      .bind(slug)
      .first();

    if (duplicate) {
      return json(
        {
          ok: false,
          error:
            "Eine Kategorie mit diesem Namen existiert bereits."
        },
        409
      );
    }

    const id = crypto.randomUUID();

    await env.DB
      .prepare(`
        INSERT INTO news_categories (
          id,
          name,
          slug,
          color,
          text_color,
          active,
          sort_order,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        name,
        slug,
        color,
        textColor,
        body?.active === false ? 0 : 1,
        sortOrder,
        now,
        now
      )
      .run();

    const category = await env.DB
      .prepare(`
        SELECT
          id,
          name,
          slug,
          color,
          text_color,
          active,
          sort_order,
          created_at,
          updated_at
        FROM news_categories
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

    return json(
      {
        ok: true,
        category
      },
      201
    );
  } catch (error) {
    console.error(
      "News Category CREATE:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Kategorie konnte nicht angelegt werden."
      },
      500
    );
  }
}

async function handleAdminNewsCategoryUpdate(
  request,
  env,
  id
) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "edit"
  );

  if (auth instanceof Response) return auth;

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

  const name = String(
    body?.name || ""
  )
    .trim()
    .slice(0, 60);

  if (!name) {
    return json(
      {
        ok: false,
        error:
          "Bitte einen Kategorienamen eingeben."
      },
      400
    );
  }

  const slug = slugifyNewsCategory(name);

  if (!slug) {
    return json(
      {
        ok: false,
        error:
          "Der Kategoriename ist ungültig."
      },
      400
    );
  }

  const color = validHexColor(
    body?.color,
    "#A855FF"
  );

  const textColor = validHexColor(
    body?.text_color,
    "#FFFFFF"
  );

  const sortOrder =
    Number.isFinite(
      Number(body?.sort_order)
    )
      ? Number(body.sort_order)
      : 0;

  const now = Math.floor(
    Date.now() / 1000
  );

  try {
    const duplicate = await env.DB
      .prepare(`
        SELECT id
        FROM news_categories
        WHERE slug = ?
          AND id != ?
        LIMIT 1
      `)
      .bind(slug, id)
      .first();

    if (duplicate) {
      return json(
        {
          ok: false,
          error:
            "Eine Kategorie mit diesem Namen existiert bereits."
        },
        409
      );
    }

    const result = await env.DB
      .prepare(`
        UPDATE news_categories
        SET
          name = ?,
          slug = ?,
          color = ?,
          text_color = ?,
          active = ?,
          sort_order = ?,
          updated_at = ?
        WHERE id = ?
      `)
      .bind(
        name,
        slug,
        color,
        textColor,
        body?.active === false ? 0 : 1,
        sortOrder,
        now,
        id
      )
      .run();

    if (
      !result.success ||
      Number(result.meta?.changes || 0) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            "Kategorie wurde nicht gefunden."
        },
        404
      );
    }

    const category = await env.DB
      .prepare(`
        SELECT
          id,
          name,
          slug,
          color,
          text_color,
          active,
          sort_order,
          created_at,
          updated_at
        FROM news_categories
        WHERE id = ?
        LIMIT 1
      `)
      .bind(id)
      .first();

    return json({
      ok: true,
      category
    });
  } catch (error) {
    console.error(
      "News Category UPDATE:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Kategorie konnte nicht gespeichert werden."
      },
      500
    );
  }
}

async function handleAdminNewsCategoryDelete(
  request,
  env,
  id
) {
  const auth = await requirePermission(
    request,
    env,
    "news",
    "delete"
  );

  if (auth instanceof Response) return auth;

  try {
    const result = await env.DB
      .prepare(`
        DELETE FROM news_categories
        WHERE id = ?
      `)
      .bind(id)
      .run();

    if (
      !result.success ||
      Number(result.meta?.changes || 0) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            "Kategorie wurde nicht gefunden."
        },
        404
      );
    }

    return json({
      ok: true
    });
  } catch (error) {
    console.error(
      "News Category DELETE:",
      error
    );

    return json(
      {
        ok: false,
        error:
          "Kategorie konnte nicht gelöscht werden."
      },
      500
    );
  }
}


/* =========================================================
   GESCHÜTZTE RACE DETAILS
   Der gemeinsame Zugangscode wird gegen den in D1
   gespeicherten SHA-256-Hash geprüft.
========================================================= */

async function handlePublicRaceDetails(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      ok: false,
      error: "Ungültige Anfrage."
    }, 400);
  }

  const accessCode = String(
    body?.access_code || ""
  ).trim();

  if (!validAccessCode(accessCode)) {
    return json({
      ok: false,
      error: "Bitte einen gültigen Zugangscode eingeben."
    }, 400);
  }

  const race = await env.DB.prepare(`
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
    return json({
      ok: false,
      error: "Aktuell ist kein Next Race festgelegt."
    }, 404);
  }

  const suppliedHash = await hashAccessCode(accessCode);

  if (
    !race.access_code_hash ||
    suppliedHash !== String(race.access_code_hash)
  ) {
    return json({
      ok: false,
      error: "Der Zugangscode ist nicht korrekt."
    }, 403);
  }

  return json({
    ok: true,
    race: {
      id: race.id,
      name: race.name,
      location: race.location,
      date: race.date,
      time: race.time,
      description: race.description,
      status: race.status,
      image_url: race.image_url,
      track_image_url: race.track_image_url
    }
  }, 200, {
    "Cache-Control": "no-store"
  });
}


/* =========================================================
   ÖFFENTLICHE WEBSITE-DATEN
   Ein zentraler Endpunkt für die komplette öffentliche Website.
   Sensible Admin-Tabellen werden NICHT ausgegeben.
========================================================= */

async function publicRows(env, table, preferredColumns = []) {
  const schema = await getTableSchema(env, table);
  const available = new Set(
    (schema.results || []).map(column => column.name)
  );

  const selected = preferredColumns.filter(column =>
    available.has(column)
  );

  if (!selected.length) {
    return [];
  }

  const columnList = selected
    .map(quoteIdentifier)
    .join(', ');

  const result = await env.DB.prepare(
    `SELECT ${columnList} FROM ${quoteIdentifier(table)}`
  ).all();

  return result.results || [];
}

function normalizePublicStatus(value) {
  return String(value ?? '').trim().toLowerCase();
}

function isPublicActive(value) {
  return [
    'active',
    'aktiv',
    'aktive',
    'published',
    '1',
    'true',
    'ja'
  ].includes(
    normalizePublicStatus(value)
  );
}

async function handlePublicData(env) {
  await ensureRaceVisibilityColumn(env);
  const [
    races,
    drivers,
    news,
    blacklist,
    gallery,
    results,
    newsCategories,
    newsDashboardRows
  ] = await Promise.all([
      publicRows(env, 'races', [
        'id',
        'name',
        'location',
        'date',
        'time',
        'description',
        'status',
        'image_url',
        'track_image_url',
        'is_next',
        'is_hidden',
        'created_at'
      ]),

      publicRows(env, 'drivers', [
        'id',
        'nickname',
        'number',
        'team',
        'car',
        'image_url',
        'status',
        'points',
        'wins',
        'created_at'
      ]),

      publicRows(env, 'news', [
        'id',
        'date',
        'title',
        'text',
        'teaser',
        'short_text',
        'summary',
        'content',
        'long_text',
        'body',
        'image',
        'image_url',
        'category',
        'status',
        'active',
        'created_at'
      ]),

      publicRows(env, 'blacklist', [
        'id',
        'vehicle_name',
        'reason',
        'image_url',
        'created_at'
      ]),

      publicRows(env, 'gallery', [
        'id',
        'title',
        'image',
        'image_url',
        'description',
        'category',
        'status',
        'date',
        'event',
        'car',
        'driver',
        'likes',
        'created_at'
      ]),

      publicRows(env, 'race_results', [
        'id',
        'race_id',
        'driver_id',
        'position',
        'points',
        'vehicle',
        'car',
        'best_lap',
        'bestlap',
        'time',
        'dnf',
        'created_at'
      ]),

      publicRows(env, 'news_categories', [
        'id',
        'name',
        'slug',
        'color',
        'text_color',
        'active',
        'sort_order',
        'created_at',
        'updated_at'
      ]),

      publicRows(env, 'news_dashboard', [
        'id',
        'next_race_id',
        'display_mode',
        'display_race_id',
        'bestlist_race_id',
        'laps_race_id',
        'latest_news_ids',
        'featured_news_id',
        'hearts_winner_driver_id',
        'hearts_quote',
        'poll_active',
        'poll_question',
        'poll_options',
        'updated_at'
      ])
    ]);

  const publicNews = news.filter(item => {
    if (item.active === undefined && item.status === undefined) {
      return true;
    }

    if (item.active !== undefined) {
      return isPublicActive(item.active);
    }

    return isPublicActive(item.status);
  });

  const publicNewsArchive = news.filter(item => {
    const status = String(item.status ?? "").trim().toLowerCase();
    const archivedByStatus = status === "archived";
    const archivedByActiveFlag = item.active !== undefined &&
      Number(item.active) === 0 &&
      !["draft", "inactive"].includes(status);
    return archivedByStatus || archivedByActiveFlag;
  });

  /* Ausgeblendete Rennen samt ihren Ergebnissen nicht öffentlich ausliefern. */
  const hiddenRaceIds = new Set(
    races.filter(race => Number(race.is_hidden) === 1).map(race => String(race.id))
  );
  const publicRaces = races.filter(race => !hiddenRaceIds.has(String(race.id)));
  const publicResults = results.filter(result => !hiddenRaceIds.has(String(result.race_id)));

  const raceCounts = new Map();

  publicResults.forEach(result => {
    if (result.driver_id !== null && result.driver_id !== undefined && result.driver_id !== "") {
      const key = String(result.driver_id);
      raceCounts.set(key, (raceCounts.get(key) || 0) + 1);
    }
  });

  const publicDrivers = drivers.map(driver => ({
    id: driver.id,
    nickname: driver.nickname || '',
    number: driver.number,
    team: driver.team,
    car: driver.car,
    image_url: driver.image_url,
    status: driver.status,
    points: driver.points,
    wins: driver.wins,
    races: raceCounts.get(String(driver.id)) || 0,
    created_at: driver.created_at
  }));

  const nextRace = publicRaces.find(race => Number(race.is_next) === 1) || null;

  const ranking = publicDrivers
    .slice()
    .sort((a, b) => {
      const points =
        (Number(b.points) || 0) -
        (Number(a.points) || 0);

      if (points !== 0) return points;

      const wins =
        (Number(b.wins) || 0) -
        (Number(a.wins) || 0);

      if (wins !== 0) return wins;

      return String(a.nickname || '').localeCompare(
        String(b.nickname || ''),
        'de-DE'
      );
    })
    .map((driver, index) => ({
      place: index + 1,
      ...driver
    }));

  const newsDashboard =
    newsDashboardRows?.[0]
      ? normalizeNewsDashboardConfig(
          newsDashboardRows[0]
        )
      : normalizeNewsDashboardConfig({});

  const publicNewsCategories =
    (newsCategories || []).filter(
      category =>
        Number(category.active) !== 0
    );

  return json(
    {
      ok: true,
      generated_at: new Date().toISOString(),
      races: publicRaces,
      drivers: publicDrivers,
      ranking,
      news: publicNews,
      newsArchive: publicNewsArchive,
      newsCategories: publicNewsCategories,
      newsDashboard,
      blacklist,
      gallery,
      results: publicResults,
      nextRace
    },
    200,
    {
      'Cache-Control': 'no-store, max-age=0, must-revalidate'
    }
  );
}


/* =========================================================
   WEBSITE DESIGN SYSTEM – ADMIN API
   Schritt 2: zentrale Design-, Medien-, Text- und Responsive-
   Einstellungen. Die öffentlichen Seiten werden in diesem
   Schritt noch NICHT umgebaut; sie können die Konfiguration
   später über /api/public/site-config laden.
========================================================= */

const SITE_DESIGN_COLUMNS = new Set([
  "bg_color", "bg2_color", "card_color", "card2_color",
  "line_color", "line_glow_color", "purple_color", "purple2_color",
  "purple3_color", "neon_color", "text_color", "muted_color",
  "brush_font_family", "head_font_family", "body_font_family",
  "brush_font_size", "head_font_size", "body_font_size",
  "brush_font_weight", "head_font_weight", "body_font_weight",
  "brush_font_style", "head_font_style", "body_font_style",
  "brush_font_color", "head_font_color", "body_font_color",
  "small_text_color", "radius_px", "page_max_width", "page_gutter",
  "section_gap_px", "topbar_height_px", "hero_height_px", "glow_strength",
  "shadow_strength", "overlay_strength", "backdrop_blur_px", "hover_effects",
  "animations_enabled", "background_gradient_enabled"
]);

const SITE_RESPONSIVE_FIELDS = new Set([
  "content_width", "max_content_width", "page_gutter", "scale",
  "hero_height_px", "topbar_height_px", "section_gap_px"
]);

const SITE_MEDIA_UPDATE_FIELDS = new Set([
  "label", "image_url", "alt_text", "active", "sort_order"
]);

function siteClampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function siteColor(value, fallback = "#000000") {
  const v = String(value ?? "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(v) ? v.toUpperCase() : fallback;
}

function siteSafeProfile(profile) {
  const p = String(profile || "").trim().toLowerCase();
  return ["fhd", "qhd", "uhd"].includes(p) ? p : null;
}

async function ensureSiteDesignRow(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS site_design (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      bg_color TEXT NOT NULL DEFAULT '#07060D',
      bg2_color TEXT NOT NULL DEFAULT '#0D0B18',
      card_color TEXT NOT NULL DEFAULT '#110E1F',
      card2_color TEXT NOT NULL DEFAULT '#171329',
      line_color TEXT NOT NULL DEFAULT '#2A2342',
      line_glow_color TEXT NOT NULL DEFAULT '#4B2F8A',
      purple_color TEXT NOT NULL DEFAULT '#4E18AE',
      purple2_color TEXT NOT NULL DEFAULT '#B266FF',
      purple3_color TEXT NOT NULL DEFAULT '#DCBCFF',
      neon_color TEXT NOT NULL DEFAULT '#A855FF',
      text_color TEXT NOT NULL DEFAULT '#F2EEFC',
      muted_color TEXT NOT NULL DEFAULT '#A49CBC',
      brush_font_family TEXT NOT NULL DEFAULT '''Permanent Marker'', cursive',
      head_font_family TEXT NOT NULL DEFAULT '''Saira Condensed'', ''Arial Narrow'', sans-serif',
      body_font_family TEXT NOT NULL DEFAULT '''Rajdhani'', ''Segoe UI'', sans-serif',
      brush_font_size TEXT NOT NULL DEFAULT '30px',
      head_font_size TEXT NOT NULL DEFAULT '23px',
      body_font_size TEXT NOT NULL DEFAULT '16px',
      brush_font_weight INTEGER NOT NULL DEFAULT 400,
      head_font_weight INTEGER NOT NULL DEFAULT 800,
      body_font_weight INTEGER NOT NULL DEFAULT 600,
      brush_font_style TEXT NOT NULL DEFAULT 'normal',
      head_font_style TEXT NOT NULL DEFAULT 'italic',
      body_font_style TEXT NOT NULL DEFAULT 'normal',
      brush_font_color TEXT NOT NULL DEFAULT '#F2EEFC',
      head_font_color TEXT NOT NULL DEFAULT '#FFFFFF',
      body_font_color TEXT NOT NULL DEFAULT '#F2EEFC',
      small_text_color TEXT NOT NULL DEFAULT '#A49CBC',
      radius_px INTEGER NOT NULL DEFAULT 10,
      page_max_width TEXT NOT NULL DEFAULT '1500px',
      page_gutter TEXT NOT NULL DEFAULT '18px',
      section_gap_px INTEGER NOT NULL DEFAULT 14,
      topbar_height_px INTEGER NOT NULL DEFAULT 58,
      hero_height_px INTEGER NOT NULL DEFAULT 320,
      glow_strength INTEGER NOT NULL DEFAULT 100,
      shadow_strength INTEGER NOT NULL DEFAULT 100,
      overlay_strength INTEGER NOT NULL DEFAULT 100,
      backdrop_blur_px INTEGER NOT NULL DEFAULT 5,
      hover_effects INTEGER NOT NULL DEFAULT 1,
      animations_enabled INTEGER NOT NULL DEFAULT 1,
      background_gradient_enabled INTEGER NOT NULL DEFAULT 1,
      updated_at INTEGER
    )
  `).run();

  await env.DB.prepare(`INSERT OR IGNORE INTO site_design (id, updated_at) VALUES (1, ?)`)
    .bind(Math.floor(Date.now() / 1000)).run();
}

async function ensureSiteConfigTables(env) {
  await ensureSiteDesignRow(env);

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS site_media (
      id TEXT PRIMARY KEY,
      slot TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      image_url TEXT NOT NULL DEFAULT '',
      r2_key TEXT NOT NULL DEFAULT '',
      alt_text TEXT NOT NULL DEFAULT '',
      active INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER,
      updated_at INTEGER
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS site_texts (
      id TEXT PRIMARY KEY,
      page TEXT NOT NULL,
      text_key TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      value TEXT NOT NULL DEFAULT '',
      text_type TEXT NOT NULL DEFAULT 'text',
      active INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER,
      updated_at INTEGER
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS site_responsive (
      id TEXT PRIMARY KEY,
      profile TEXT NOT NULL UNIQUE,
      min_viewport_width INTEGER NOT NULL DEFAULT 0,
      max_viewport_width INTEGER,
      content_width TEXT NOT NULL DEFAULT '92vw',
      max_content_width TEXT NOT NULL DEFAULT '1500px',
      page_gutter TEXT NOT NULL DEFAULT '18px',
      scale REAL NOT NULL DEFAULT 1,
      hero_height_px INTEGER NOT NULL DEFAULT 320,
      topbar_height_px INTEGER NOT NULL DEFAULT 58,
      section_gap_px INTEGER NOT NULL DEFAULT 14,
      created_at INTEGER,
      updated_at INTEGER
    )
  `).run();

  const now = Math.floor(Date.now() / 1000);
  const mediaSeeds = [
    ["media-logo-small", "logo_small", "Logo klein", "images/logo-small.png", "", "JACKAL Logo", 10],
    ["media-logo", "logo", "Logo groß", "images/logo.png", "", "JACKAL Racing League", 20],
    ["media-main-banner", "main_banner", "Hauptbanner", "jackal-banner.png", "", "JACKAL Racing League", 30],
    ["media-next-race", "home_next_race", "Home – Next Race", "images/next-race.jpg", "", "Next Race", 40],
    ["media-champion-bg", "home_champion_bg", "Home – Champion Hintergrund", "images/champion-bg.jpg", "", "Champion Hintergrund", 50],
    ["media-champion", "home_champion_driver", "Home – Champion Bild", "images/champion.png", "", "Current Champion", 60],
    ["media-champion-car", "home_champion_car", "Home – Champion Fahrzeug", "images/car.png", "", "Champion Fahrzeug", 70],
    ["media-news-race-bg", "news_race_background", "News – Rennbereich Hintergrund", "images/race-bg.jpg", "", "Rennbereich", 80],
    ["media-hearts", "news_hearts", "News – Sieger der Herzen", "images/sieger-herzen.jpg", "", "Sieger der Herzen", 90],
    ["media-team-jackal", "team_jackal", "Team JACKAL", "images/team-jackal.png", "", "Team JACKAL", 100],
    ["media-team-nightshift", "team_nightshift", "Team Nightshift", "images/team-nightshift.png", "", "Team Nightshift", 110],
    ["media-team-phantom", "team_phantom", "Team Phantom", "images/team-phantom.png", "", "Team Phantom", 120],
    ["media-team-velocity", "team_velocity", "Team Velocity", "images/team-velocity.png", "", "Team Velocity", 130]
  ];

  for (const [id, slot, label, imageUrl, r2Key, altText, sortOrder] of mediaSeeds) {
    await env.DB.prepare(`
      INSERT OR IGNORE INTO site_media (
        id, slot, label, image_url, r2_key, alt_text, active, sort_order, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).bind(id, slot, label, imageUrl, r2Key, altText, sortOrder, now, now).run();
  }

  const responsiveSeeds = [
    ["responsive-fhd", "fhd", 0, 2199, "92vw", "1500px", "18px", 1.00, 300, 58, 14],
    ["responsive-qhd", "qhd", 2200, 3199, "88vw", "1850px", "24px", 1.06, 320, 60, 16],
    ["responsive-uhd", "uhd", 3200, null, "84vw", "2500px", "30px", 1.12, 350, 62, 18]
  ];

  for (const row of responsiveSeeds) {
    await env.DB.prepare(`
      INSERT OR IGNORE INTO site_responsive (
        id, profile, min_viewport_width, max_viewport_width,
        content_width, max_content_width, page_gutter, scale,
        hero_height_px, topbar_height_px, section_gap_px,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(...row, now, now).run();
  }

  const textSeeds = [
    ["text-global-name", "global", "global.website_name", "Website Name", "JACKAL RACING LEAGUE", 1],
    ["text-global-slogan", "global", "global.website_slogan", "Slogan", "WE ARE JACKAL. WE ARE RACING.", 2],
    ["text-global-footer-left", "global", "global.footer_left", "Footer links", "JACKAL RACING LEAGUE", 3],
    ["text-global-footer-claim", "global", "global.footer_claim", "Footer Claim", "WE ARE JACKAL. WE ARE RACING.", 4],
    ["text-global-footer-right", "global", "global.footer_right", "Footer rechts", "LOS SANTOS · EST. 2026", 5],
    ["text-home-next-race", "home", "home.next_race_title", "Home Next Race", "NEXT RACE", 10],
    ["text-home-latest-news", "home", "home.latest_news_title", "Home Latest News", "LATEST NEWS", 11],
    ["text-home-champion", "home", "home.champion_title", "Home Champion", "CURRENT CHAMPION", 12],
    ["text-news-title", "news", "news.page_title", "News Seitentitel", "NEWS", 10],
    ["text-news-subtitle", "news", "news.page_subtitle", "News Untertitel", "AKTUELLE NEUIGKEITEN", 11]
  ];
  for (const [id,page,textKey,label,value,sortOrder] of textSeeds) {
    await env.DB.prepare(`
      INSERT OR IGNORE INTO site_texts (id,page,text_key,label,value,text_type,active,sort_order,created_at,updated_at)
      VALUES (?, ?, ?, ?, ?, 'text', 1, ?, ?, ?)
    `).bind(id,page,textKey,label,value,sortOrder,now,now).run();
  }
}

async function handleAdminSiteDesignGet(request, env) {
  const auth = await requirePermission(request, env, "settings", "view");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  const row = await env.DB.prepare(`SELECT * FROM site_design WHERE id = 1 LIMIT 1`).first();
  return json({ ok: true, design: row || null });
}

async function handleAdminSiteDesignSave(request, env) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }

  const input = body?.design && typeof body.design === "object" ? body.design : body;
  const current = await env.DB.prepare(`SELECT * FROM site_design WHERE id = 1 LIMIT 1`).first();
  const next = {};

  for (const key of SITE_DESIGN_COLUMNS) {
    if (!(key in input)) continue;
    let value = input[key];
    if (key.endsWith("_color")) value = siteColor(value, String(current?.[key] || "#000000"));
    else if (["radius_px", "section_gap_px", "topbar_height_px", "hero_height_px", "backdrop_blur_px"].includes(key)) value = siteClampInt(value, 0, 1000, Number(current?.[key] || 0));
    else if (["glow_strength", "shadow_strength", "overlay_strength"].includes(key)) value = siteClampInt(value, 0, 200, Number(current?.[key] || 0));
    else if (["hover_effects", "animations_enabled", "background_gradient_enabled"].includes(key)) value = Number(value) ? 1 : 0;
    else if (["brush_font_weight", "head_font_weight", "body_font_weight"].includes(key)) value = siteClampInt(value, 100, 900, Number(current?.[key] || 400));
    else value = String(value ?? "").trim();
    next[key] = value;
  }

  const keys = Object.keys(next);
  if (!keys.length) return json({ ok: false, error: "Keine Änderungen übergeben." }, 400);
  const setSql = keys.map(key => `${quoteIdentifier(key)} = ?`).join(", ");
  const values = keys.map(key => next[key]);
  await env.DB.prepare(`UPDATE site_design SET ${setSql}, updated_at = ? WHERE id = 1`).bind(...values, Math.floor(Date.now() / 1000)).run();
  const saved = await env.DB.prepare(`SELECT * FROM site_design WHERE id = 1 LIMIT 1`).first();
  return json({ ok: true, design: saved });
}

async function handleAdminSiteMediaGet(request, env) {
  const auth = await requirePermission(request, env, "settings", "view");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  const result = await env.DB.prepare(`SELECT * FROM site_media ORDER BY sort_order ASC, label COLLATE NOCASE ASC`).all();
  return json({ ok: true, media: result.results || [] });
}

async function handleAdminSiteMediaSave(request, env, slot) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);

  const normalizedSlot = String(slot || "").trim();
  if (!normalizedSlot) return json({ ok: false, error: "Ungültiger Medien-Slot." }, 400);

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }

  const current = await env.DB.prepare(`SELECT * FROM site_media WHERE slot = ? LIMIT 1`).bind(normalizedSlot).first();
  if (!current) return json({ ok: false, error: "Medien-Slot wurde nicht gefunden." }, 404);

  const updates = [];
  const values = [];
  let imageUrlChanged = false;
  for (const key of SITE_MEDIA_UPDATE_FIELDS) {
    if (!(key in body)) continue;
    let value = body[key];
    if (key === "active") value = Number(value) ? 1 : 0;
    if (key === "sort_order") value = siteClampInt(value, 0, 100000, Number(current.sort_order || 0));
    else value = String(value ?? "");
    if (key === "image_url" && value !== String(current.image_url || "")) imageUrlChanged = true;
    updates.push(`${quoteIdentifier(key)} = ?`);
    values.push(value);
  }
  if (!updates.length) return json({ ok: false, error: "Keine Änderungen übergeben." }, 400);

  const oldR2Key = imageUrlChanged ? String(current.r2_key || "") : "";
  if (imageUrlChanged) {
    updates.push(`r2_key = ?`);
    values.push("");
  }

  await env.DB.prepare(`UPDATE site_media SET ${updates.join(", ")}, updated_at = ? WHERE slot = ?`).bind(...values, Math.floor(Date.now() / 1000), normalizedSlot).run();
  if (oldR2Key && env.IMAGES) {
    try { await env.IMAGES.delete(oldR2Key); } catch (error) { console.error("Site media old R2 delete failed:", error); }
  }
  const saved = await env.DB.prepare(`SELECT * FROM site_media WHERE slot = ? LIMIT 1`).bind(normalizedSlot).first();
  return json({ ok: true, media: saved });
}

async function handleAdminSiteMediaUpload(request, env) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);

  const url = new URL(request.url);
  const slot = String(url.searchParams.get("slot") || "").trim();
  if (!slot) return json({ ok: false, error: "Kein Medien-Slot angegeben." }, 400);
  if (!env.IMAGES) return json({ ok: false, error: "R2 ist im Worker nicht verbunden." }, 500);

  const contentType = String(request.headers.get("Content-Type") || "").toLowerCase();
  if (!contentType.startsWith("multipart/form-data")) return json({ ok: false, error: "Upload muss als multipart/form-data erfolgen." }, 400);

  const existing = await env.DB.prepare(`SELECT * FROM site_media WHERE slot = ? LIMIT 1`).bind(slot).first();
  if (!existing) return json({ ok: false, error: "Medien-Slot wurde nicht gefunden." }, 404);

  let formData;
  try { formData = await request.formData(); }
  catch { return json({ ok: false, error: "Upload-Daten konnten nicht gelesen werden." }, 400); }
  const file = formData.get("file");
  if (!(file instanceof File) || !file.size) return json({ ok: false, error: "Keine gültige Bilddatei übergeben." }, 400);
  if (file.size > MAX_IMAGE_SIZE) return json({ ok: false, error: "Das Bild darf maximal 10 MB groß sein." }, 413);

  const mimeType = String(file.type || "").toLowerCase();
  const extension = imageExtensionFromType(mimeType);
  if (!extension) return json({ ok: false, error: "Nicht unterstütztes Bildformat. Erlaubt sind JPG, PNG, WEBP und GIF." }, 415);

  const now = new Date();
  const year = String(now.getUTCFullYear());
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const key = `site_media/${slot}/${year}/${month}/${crypto.randomUUID()}.${extension}`;
  await env.IMAGES.put(key, file.stream(), {
    httpMetadata: { contentType: mimeType, cacheControl: "public, max-age=31536000, immutable" },
    customMetadata: { resource: "site_media", slot, originalName: file.name || "image" }
  });

  const imageUrl = publicImageUrl(request, key);
  const oldR2Key = String(existing.r2_key || "");
  try {
    await env.DB.prepare(`UPDATE site_media SET image_url = ?, r2_key = ?, updated_at = ? WHERE slot = ?`).bind(imageUrl, key, Math.floor(Date.now() / 1000), slot).run();
  } catch (error) {
    try { await env.IMAGES.delete(key); } catch (cleanupError) { console.error("Site media upload cleanup failed:", cleanupError); }
    throw error;
  }

  if (oldR2Key && oldR2Key !== key) {
    try { await env.IMAGES.delete(oldR2Key); } catch (error) { console.error("Site media replaced R2 delete failed:", error); }
  }
  return json({ ok: true, slot, key, url: imageUrl, mime_type: mimeType, size: file.size });
}

async function handleAdminSiteMediaDelete(request, env, slot) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);

  const normalizedSlot = String(slot || "").trim();
  const current = await env.DB.prepare(`SELECT * FROM site_media WHERE slot = ? LIMIT 1`).bind(normalizedSlot).first();
  if (!current) return json({ ok: false, error: "Medien-Slot wurde nicht gefunden." }, 404);
  if (current.r2_key && env.IMAGES) {
    try { await env.IMAGES.delete(current.r2_key); } catch (error) { console.error("Site media R2 delete failed:", error); }
  }
  await env.DB.prepare(`UPDATE site_media SET image_url = '', r2_key = '', updated_at = ? WHERE slot = ?`).bind(Math.floor(Date.now() / 1000), normalizedSlot).run();
  return json({ ok: true });
}

async function handleAdminSiteTextsGet(request, env) {
  const auth = await requirePermission(request, env, "settings", "view");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  const result = await env.DB.prepare(`SELECT * FROM site_texts ORDER BY page ASC, sort_order ASC, label COLLATE NOCASE ASC`).all();
  return json({ ok: true, texts: result.results || [] });
}

async function handleAdminSiteTextsSave(request, env) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }
  const texts = Array.isArray(body?.texts) ? body.texts : [];
  if (!texts.length) return json({ ok: false, error: "Keine Texte übergeben." }, 400);
  const now = Math.floor(Date.now() / 1000);
  for (const item of texts) {
    const textKey = String(item?.text_key || "").trim();
    const page = String(item?.page || "").trim();
    const label = String(item?.label || textKey).trim();
    if (!textKey || !page) continue;
    await env.DB.prepare(`
      INSERT INTO site_texts (id, page, text_key, label, value, text_type, active, sort_order, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(text_key) DO UPDATE SET
        page = excluded.page,
        label = excluded.label,
        value = excluded.value,
        text_type = excluded.text_type,
        active = excluded.active,
        sort_order = excluded.sort_order,
        updated_at = excluded.updated_at
    `).bind(
      String(item?.id || crypto.randomUUID()), page, textKey, label,
      String(item?.value ?? ""), String(item?.text_type || "text"),
      Number(item?.active) ? 1 : 0, siteClampInt(item?.sort_order, 0, 100000, 0), now, now
    ).run();
  }
  const result = await env.DB.prepare(`SELECT * FROM site_texts ORDER BY page ASC, sort_order ASC, label COLLATE NOCASE ASC`).all();
  return json({ ok: true, texts: result.results || [] });
}

async function handleAdminSiteResponsiveGet(request, env) {
  const auth = await requirePermission(request, env, "settings", "view");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  const result = await env.DB.prepare(`SELECT * FROM site_responsive ORDER BY min_viewport_width ASC`).all();
  return json({ ok: true, profiles: result.results || [] });
}

async function handleAdminSiteResponsiveSave(request, env) {
  const auth = await requirePermission(request, env, "settings", "edit");
  if (auth instanceof Response) return auth;
  await ensureSiteConfigTables(env);
  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Ungültige Anfrage." }, 400); }
  const profiles = Array.isArray(body?.profiles) ? body.profiles : [];
  if (!profiles.length) return json({ ok: false, error: "Keine Responsive-Profile übergeben." }, 400);
  const now = Math.floor(Date.now() / 1000);
  for (const item of profiles) {
    const profile = siteSafeProfile(item?.profile);
    if (!profile) continue;
    const current = await env.DB.prepare(`SELECT * FROM site_responsive WHERE profile = ? LIMIT 1`).bind(profile).first();
    if (!current) continue;
    const next = {};
    for (const key of SITE_RESPONSIVE_FIELDS) {
      if (!(key in item)) continue;
      let value = item[key];
      if (["hero_height_px", "topbar_height_px", "section_gap_px"].includes(key)) value = siteClampInt(value, 0, 1000, Number(current[key] || 0));
      else if (key === "scale") { const n = Number(value); value = Number.isFinite(n) ? Math.max(0.5, Math.min(2, n)) : Number(current.scale || 1); }
      else value = String(value ?? "").trim();
      next[key] = value;
    }
    const keys = Object.keys(next);
    if (!keys.length) continue;
    const setSql = keys.map(key => `${quoteIdentifier(key)} = ?`).join(", ");
    await env.DB.prepare(`UPDATE site_responsive SET ${setSql}, updated_at = ? WHERE profile = ?`).bind(...keys.map(key => next[key]), now, profile).run();
  }
  const result = await env.DB.prepare(`SELECT * FROM site_responsive ORDER BY min_viewport_width ASC`).all();
  return json({ ok: true, profiles: result.results || [] });
}

async function handlePublicSiteConfig(env) {
  await ensureSiteConfigTables(env);
  const [design, media, texts, responsive] = await Promise.all([
    env.DB.prepare(`SELECT * FROM site_design WHERE id = 1 LIMIT 1`).first(),
    env.DB.prepare(`SELECT slot, label, image_url, alt_text, active, sort_order FROM site_media WHERE active = 1 ORDER BY sort_order ASC`).all(),
    env.DB.prepare(`SELECT page, text_key, label, value, text_type, active, sort_order FROM site_texts WHERE active = 1 ORDER BY page ASC, sort_order ASC`).all(),
    env.DB.prepare(`SELECT profile, min_viewport_width, max_viewport_width, content_width, max_content_width, page_gutter, scale, hero_height_px, topbar_height_px, section_gap_px FROM site_responsive ORDER BY min_viewport_width ASC`).all()
  ]);
  return json({ ok: true, generated_at: new Date().toISOString(), design: design || null, media: media.results || [], texts: texts.results || [], responsive: responsive.results || [] }, 200, { "Cache-Control": "no-store" });
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

      if (
        url.pathname === "/api/admin/news/dashboard" &&
        request.method === "GET"
      ) {
        return await handleAdminNewsDashboardGet(
          request,
          env
        );
      }

      if (
        url.pathname === "/api/admin/news/dashboard" &&
        request.method === "PUT"
      ) {
        return await handleAdminNewsDashboardSave(
          request,
          env
        );
      }

      if (
        url.pathname === "/api/admin/news/categories" &&
        request.method === "GET"
      ) {
        return await handleAdminNewsCategoriesGet(
          request,
          env
        );
      }

      if (
        url.pathname === "/api/admin/news/categories" &&
        request.method === "POST"
      ) {
        return await handleAdminNewsCategoryCreate(
          request,
          env
        );
      }

      const newsCategoryMatch =
        url.pathname.match(
          /^\/api\/admin\/news\/categories\/([^/]+)$/
        );

      if (
        newsCategoryMatch &&
        request.method === "PUT"
      ) {
        return await handleAdminNewsCategoryUpdate(
          request,
          env,
          newsCategoryMatch[1]
        );
      }

      if (
        newsCategoryMatch &&
        request.method === "DELETE"
      ) {
        return await handleAdminNewsCategoryDelete(
          request,
          env,
          newsCategoryMatch[1]
        );
      }

      if (url.pathname === "/api/admin/media/upload" && request.method === "POST") {
        return await handleImageUpload(request, env);
      }

      if (url.pathname === "/api/admin/media" && request.method === "DELETE") {
        return await handleImageDelete(request, env);
      }

      if (url.pathname.startsWith("/media/") && (request.method === "GET" || request.method === "HEAD")) {
        return await handlePublicImage(request, env);
      }


      if (url.pathname === "/api/public/site-config" && request.method === "GET") {
        return await handlePublicSiteConfig(env);
      }

      if (url.pathname === "/api/admin/site/design" && request.method === "GET") {
        return await handleAdminSiteDesignGet(request, env);
      }
      if (url.pathname === "/api/admin/site/design" && request.method === "PUT") {
        return await handleAdminSiteDesignSave(request, env);
      }

      if (url.pathname === "/api/admin/site/media" && request.method === "GET") {
        return await handleAdminSiteMediaGet(request, env);
      }
      if (url.pathname === "/api/admin/site/media/upload" && request.method === "POST") {
        return await handleAdminSiteMediaUpload(request, env);
      }
      if (url.pathname === "/api/admin/site/media" && request.method === "DELETE") {
        const slot = String(url.searchParams.get("slot") || "").trim();
        return await handleAdminSiteMediaDelete(request, env, slot);
      }

      const siteMediaMatch = url.pathname.match(/^\/api\/admin\/site\/media\/([^/]+)$/);
      if (siteMediaMatch && request.method === "PUT") {
        return await handleAdminSiteMediaSave(request, env, decodeURIComponent(siteMediaMatch[1]));
      }

      if (url.pathname === "/api/admin/site/texts" && request.method === "GET") {
        return await handleAdminSiteTextsGet(request, env);
      }
      if (url.pathname === "/api/admin/site/texts" && request.method === "PUT") {
        return await handleAdminSiteTextsSave(request, env);
      }

      if (url.pathname === "/api/admin/site/responsive" && request.method === "GET") {
        return await handleAdminSiteResponsiveGet(request, env);
      }
      if (url.pathname === "/api/admin/site/responsive" && request.method === "PUT") {
        return await handleAdminSiteResponsiveSave(request, env);
      }

      if (url.pathname === "/api/public/race-details" && request.method === "POST") {
        return await handlePublicRaceDetails(request, env);
      }

      if (url.pathname === "/api/admin/races/next" && request.method === "GET") {
        return await handleAdminNextRaceGet(request, env);
      }

      if (url.pathname === "/api/admin/races/next" && request.method === "POST") {
        return await handleAdminNextRaceSave(request, env);
      }

      if (url.pathname === "/api/public/data" && request.method === "GET") {
        return await handlePublicData(env);
      }

      if (url.pathname === "/api/admin/users" && request.method === "GET") {
        return await handleAdminUsersGet(request, env);
      }

      if (url.pathname === "/api/admin/users" && request.method === "POST") {
        return await handleAdminUserCreate(request, env);
      }

      const permissionMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)\/permissions$/);
      if (permissionMatch && request.method === "PUT") {
        return await handleAdminPermissionsUpdate(request, env, permissionMatch[1]);
      }

      const userDeleteMatch = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
      if (userDeleteMatch && request.method === "DELETE") {
        return await handleAdminUserDelete(request, env, userDeleteMatch[1]);
      }

      const schemaMatch = url.pathname.match(/^\/api\/admin\/schema\/([^/]+)$/);
      if (/^\/api\/admin\/(schema|data)\/races(\/|$)/.test(url.pathname)) {
        await ensureRaceVisibilityColumn(env);
      }
      if (schemaMatch && request.method === "GET") {
        return await handleAdminSchema(request, env, schemaMatch[1]);
      }

      const dataMatch = url.pathname.match(/^\/api\/admin\/data\/([^/]+)$/);
      if (dataMatch) {
        const resource = dataMatch[1];
        if (request.method === "GET") return await handleAdminDataGet(request, env, resource);
        if (request.method === "POST") return await handleAdminDataCreate(request, env, resource);
      }

      const dataIdMatch = url.pathname.match(/^\/api\/admin\/data\/([^/]+)\/([^/]+)$/);
      if (dataIdMatch) {
        const resource = dataIdMatch[1];
        const value = decodeURIComponent(dataIdMatch[2]);
        if (request.method === "PUT") return await handleAdminDataUpdate(request, env, resource, value);
        if (request.method === "DELETE") return await handleAdminDataDelete(request, env, resource, value);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Worker error:", error);
      return json(
        { ok: false, error: "Interner Serverfehler." },
        500
      );
    }
  }
};
