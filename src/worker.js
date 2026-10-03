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

    const row = await env.DB.prepare(`
      SELECT can_view, can_create, can_edit, can_delete
      FROM admin_permissions
      WHERE user_id = ? AND resource = ?
      LIMIT 1
    `).bind(auth.user.id, resource).first();

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

async function handleAdminSchema(request, env, resource) {
  const auth = await requirePermission(request, env, resource, "view");
  if (auth instanceof Response) return auth;

  const table = RESOURCES[resource];
  if (!table) return json({ ok: false, error: "Unbekannter Bereich." }, 404);

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

  if (identity && identity.name === "id" && !("id" in data) && String(identity.type || "").toUpperCase().includes("CHAR")) {
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

  await env.DB.prepare(`
    INSERT INTO ${quoteIdentifier(table)} (${quotedKeys})
    VALUES (${placeholders})
  `).bind(...values).run();

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

function normalizeNewsDashboardConfig(row) {
  return {
    next_race_id: String(row?.next_race_id ?? ""),
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
      .slice(0, 5)
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
    const row = await env.DB
      .prepare(`
        SELECT
          id,
          next_race_id,
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
        .slice(0, 5)
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

  const config = {
    next_race_id: String(body?.next_race_id ?? ""),
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
          latest_news_ids,
          featured_news_id,
          hearts_winner_driver_id,
          hearts_quote,
          poll_active,
          poll_question,
          poll_options,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id)
        DO UPDATE SET
          next_race_id = excluded.next_race_id,
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
        'is_next',
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
        'content',
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
        'status',
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

  const publicBlacklist = blacklist.filter(item =>
    isPublicActive(item.status)
  );

  const raceCounts = new Map();

  results.forEach(result => {
    if (result.driver_id !== null && result.driver_id !== undefined && result.driver_id !== "") {
      const key = String(result.driver_id);
      raceCounts.set(key, (raceCounts.get(key) || 0) + 1);
    }
  });

  const publicDrivers = drivers.map(driver => ({
    ...driver,
    races: raceCounts.get(String(driver.id)) || 0
  }));

  const nextRace = races.find(race => Number(race.is_next) === 1) || null;

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
      races,
      drivers: publicDrivers,
      ranking,
      news: publicNews,
      newsCategories: publicNewsCategories,
      newsDashboard,
      blacklist: publicBlacklist,
      gallery,
      results,
      nextRace
    },
    200,
    {
      'Cache-Control': 'public, max-age=60'
    }
  );
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
