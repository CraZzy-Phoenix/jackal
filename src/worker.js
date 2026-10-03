const SESSION_DAYS=7,SESSION_SECONDS=SESSION_DAYS*86400;
const RESOURCES={races:'races',drivers:'drivers',results:'race_results',news:'news',blacklist:'blacklist',gallery:'gallery',settings:'site_settings'};
const RESOURCE_LABELS={dashboard:'Dashboard',races:'Rennen',drivers:'Fahrer',results:'Ergebnisse',news:'News',blacklist:'Fahrzeug-Blacklist',gallery:'Gallery',settings:'Einstellungen'};
const IMAGE_RESOURCES=new Set(['races','drivers','news','blacklist','gallery']);
const IMAGE_TYPES={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif'};
const MAX_IMAGE_SIZE=10*1024*1024;

function json(data,status=200,headers={}){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}})}
function getCookie(req,name){const c=req.headers.get('Cookie')||'',m=c.match(new RegExp('(?:^|;\\s*)'+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'=([^;]*)'));return m?decodeURIComponent(m[1]):null}
function sessionCookie(v,maxAge=SESSION_SECONDS){return[`jackal_admin_session=${encodeURIComponent(v)}`,'Path=/',`Max-Age=${maxAge}`,'HttpOnly','Secure','SameSite=Strict'].join('; ')}
function nowSec(){return Math.floor(Date.now()/1000)}

async function sha256Hex(value){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(String(value??'')));return Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,'0')).join('')}
function bytesToHex(b){return Array.from(b,x=>x.toString(16).padStart(2,'0')).join('')}
function hexToBytes(h){const b=new Uint8Array(h.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(h.slice(i*2,i*2+2),16);return b}
function base64ToBytes(v){const s=atob(v),b=new Uint8Array(s.length);for(let i=0;i<s.length;i++)b[i]=s.charCodeAt(i);return b}
function bytesToBase64(b){let s='';for(const x of b)s+=String.fromCharCode(x);return btoa(s)}

async function derivePasswordHash(password,salt){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),{name:'PBKDF2'},false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},km,256))
}
async function hashPassword(password,saltHex=null){
  const salt=saltHex?hexToBytes(saltHex):crypto.getRandomValues(new Uint8Array(16));
  return{hash:bytesToHex(await derivePasswordHash(password,salt)),salt:bytesToHex(salt)}
}
async function verifyPassword(password,h,s){
  if(!h||!s)return{valid:false,legacy:false};
  if(h.length===64&&s.length===32&&/^[0-9a-fA-F]+$/.test(h)&&/^[0-9a-fA-F]+$/.test(s)){
    return{valid:bytesToHex(await derivePasswordHash(password,hexToBytes(s))).toLowerCase()===h.toLowerCase(),legacy:false}
  }
  try{
    return{valid:bytesToBase64(await derivePasswordHash(password,base64ToBytes(s)))===h,legacy:true}
  }catch{
    return{valid:false,legacy:false}
  }
}

async function createSession(env,username){
  const id=crypto.randomUUID(),n=nowSec();
  await env.DB.prepare('INSERT INTO admin_sessions (id,username,expires_at,created_at) VALUES (?,?,?,?)').bind(id,username,n+SESSION_SECONDS,n).run();
  return id
}
async function getSession(req,env){
  const id=getCookie(req,'jackal_admin_session');
  if(!id)return null;
  return await env.DB.prepare('SELECT id,username,expires_at FROM admin_sessions WHERE id=? AND expires_at>? LIMIT 1').bind(id,nowSec()).first()
}
async function getUser(env,username){
  return await env.DB.prepare('SELECT id,username,active,is_superadmin,created_at,updated_at FROM admin_users WHERE username=? LIMIT 1').bind(username).first()
}
async function requireSession(req,env){
  const session=await getSession(req,env);
  if(!session)return json({ok:false,error:'Nicht angemeldet.'},401);
  const user=await getUser(env,session.username);
  if(!user||!user.active)return json({ok:false,error:'Benutzerkonto ist nicht aktiv.'},403);
  return{session,user}
}
async function requirePermission(req,env,resource,action){
  const a=await requireSession(req,env);
  if(a instanceof Response)return a;
  if(a.user.is_superadmin||(resource==='dashboard'&&action==='view'))return a;
  const p=await env.DB.prepare('SELECT can_view,can_create,can_edit,can_delete FROM admin_permissions WHERE user_id=? AND resource=? LIMIT 1').bind(a.user.id,resource).first();
  if(!p||Number(p[`can_${action}`])!==1)return json({ok:false,error:'Keine Berechtigung für diesen Bereich.'},403);
  return a
}
async function requireSuperadmin(req,env){
  const a=await requireSession(req,env);
  if(a instanceof Response)return a;
  if(!a.user.is_superadmin)return json({ok:false,error:'Nur Superadmins dürfen diese Aktion ausführen.'},403);
  return a
}


/* =========================================================
   LOGIN / LOGOUT / ME
========================================================= */

async function handleLogin(req,env){
  let body;
  try{body=await req.json()}catch{return json({ok:false,error:'Ungültige Anfrage.'},400)}
  const username=String(body?.username||'').trim();
  const password=String(body?.password||'');

  if(!username||!password)return json({ok:false,error:'Bitte Benutzername und Passwort eingeben.'},400);

  const u=await env.DB.prepare(`
    SELECT id,username,password_hash,password_salt,active,is_superadmin
    FROM admin_users
    WHERE username=?
    LIMIT 1
  `).bind(username).first();

  if(!u)return json({ok:false,error:'Benutzername oder Passwort ist falsch.'},401);
  if(!u.active)return json({ok:false,error:'Dieses Benutzerkonto ist deaktiviert.'},403);

  const vr=await verifyPassword(password,u.password_hash,u.password_salt);
  if(!vr.valid)return json({ok:false,error:'Benutzername oder Passwort ist falsch.'},401);

  if(vr.legacy){
    const h=await hashPassword(password);
    await env.DB.prepare(`
      UPDATE admin_users
      SET password_hash=?,password_salt=?,updated_at=?
      WHERE id=?
    `).bind(h.hash,h.salt,nowSec(),u.id).run();
  }

  return json(
    {
      ok:true,
      username:u.username,
      is_superadmin:!!u.is_superadmin
    },
    200,
    {
      'Set-Cookie':sessionCookie(await createSession(env,u.username))
    }
  )
}

async function handleLogout(req,env){
  const id=getCookie(req,'jackal_admin_session');
  if(id)await env.DB.prepare('DELETE FROM admin_sessions WHERE id=?').bind(id).run();

  return json(
    {ok:true},
    200,
    {'Set-Cookie':sessionCookie('',0)}
  )
}

async function handleMe(req,env){
  const a=await requireSession(req,env);
  if(a instanceof Response)return a;

  const permissions={};

  for(const r of Object.keys(RESOURCE_LABELS)){
    if(r==='dashboard'){
      permissions[r]={
        can_view:1,
        can_create:0,
        can_edit:0,
        can_delete:0
      };
      continue
    }

    const p=await env.DB.prepare(`
      SELECT can_view,can_create,can_edit,can_delete
      FROM admin_permissions
      WHERE user_id=? AND resource=?
      LIMIT 1
    `).bind(a.user.id,r).first();

    permissions[r]=a.user.is_superadmin
      ? {
          can_view:1,
          can_create:1,
          can_edit:1,
          can_delete:1
        }
      : {
          can_view:Number(p?.can_view||0),
          can_create:Number(p?.can_create||0),
          can_edit:Number(p?.can_edit||0),
          can_delete:Number(p?.can_delete||0)
        }
  }

  return json({
    ok:true,
    username:a.user.username,
    is_superadmin:!!a.user.is_superadmin,
    expiresAt:a.session.expires_at,
    permissions
  })
}


/* =========================================================
   BENUTZERVERWALTUNG
========================================================= */

async function handleAdminUsersGet(req,env){
  const a=await requireSuperadmin(req,env);
  if(a instanceof Response)return a;

  const rs=(await env.DB.prepare(`
    SELECT id,username,active,is_superadmin,created_at,updated_at
    FROM admin_users
    ORDER BY username COLLATE NOCASE ASC
  `).all()).results||[];

  for(const u of rs){
    u.permissions=(await env.DB.prepare(`
      SELECT id,resource,can_view,can_create,can_edit,can_delete,created_at,updated_at
      FROM admin_permissions
      WHERE user_id=?
      ORDER BY resource ASC
    `).bind(u.id).all()).results||[];
  }

  return json({ok:true,users:rs})
}

async function handleAdminUserCreate(req,env){
  const a=await requireSuperadmin(req,env);
  if(a instanceof Response)return a;

  let b;
  try{b=await req.json()}catch{return json({ok:false,error:'Ungültige Anfrage.'},400)}

  const username=String(b?.username||'').trim();
  const password=String(b?.password||'');
  const active=b?.active===false?0:1;
  const isSuperadmin=b?.is_superadmin===true?1:0;

  if(username.length<2)return json({ok:false,error:'Der Benutzername muss mindestens 2 Zeichen lang sein.'},400);
  if(password.length<8)return json({ok:false,error:'Das Passwort muss mindestens 8 Zeichen lang sein.'},400);

  if(await env.DB.prepare('SELECT id FROM admin_users WHERE username=? LIMIT 1').bind(username).first()){
    return json({ok:false,error:'Dieser Benutzername existiert bereits.'},409)
  }

  const p=await hashPassword(password);
  const id=crypto.randomUUID();
  const n=nowSec();

  await env.DB.prepare(`
    INSERT INTO admin_users (
      id,username,password_hash,password_salt,
      active,is_superadmin,created_at,updated_at
    )
    VALUES (?,?,?,?,?,?,?,?)
  `).bind(
    id,
    username,
    p.hash,
    p.salt,
    active,
    isSuperadmin,
    n,
    n
  ).run();

  return json({
    ok:true,
    user:{
      id,
      username,
      active,
      is_superadmin:isSuperadmin,
      created_at:n,
      updated_at:n,
      permissions:[]
    }
  },201)
}

async function handleAdminUserDelete(req,env,id){
  const a=await requireSuperadmin(req,env);
  if(a instanceof Response)return a;

  if(id===a.user.id){
    return json({
      ok:false,
      error:'Du kannst deinen eigenen Superadmin-Account nicht löschen.'
    },400)
  }

  const u=await env.DB.prepare(`
    SELECT id,username
    FROM admin_users
    WHERE id=?
    LIMIT 1
  `).bind(id).first();

  if(!u)return json({ok:false,error:'Benutzer nicht gefunden.'},404);

  await env.DB.prepare('DELETE FROM admin_permissions WHERE user_id=?').bind(id).run();
  await env.DB.prepare('DELETE FROM admin_sessions WHERE username=?').bind(u.username).run();
  await env.DB.prepare('DELETE FROM admin_users WHERE id=?').bind(id).run();

  return json({ok:true})
}

async function handleAdminPermissionsUpdate(req,env,id){
  const a=await requireSuperadmin(req,env);
  if(a instanceof Response)return a;

  const u=await env.DB.prepare(`
    SELECT id,is_superadmin
    FROM admin_users
    WHERE id=?
    LIMIT 1
  `).bind(id).first();

  if(!u)return json({ok:false,error:'Benutzer nicht gefunden.'},404);

  if(u.is_superadmin){
    return json({
      ok:true,
      message:'Superadmins besitzen automatisch alle Rechte.'
    })
  }

  let b;
  try{b=await req.json()}catch{return json({ok:false,error:'Ungültige Anfrage.'},400)}

  await env.DB.prepare('DELETE FROM admin_permissions WHERE user_id=?').bind(id).run();

  const n=nowSec();

  for(const p of Array.isArray(b?.permissions)?b.permissions:[]){
    const r=String(p?.resource||'').trim();

    if(!RESOURCE_LABELS[r]||r==='dashboard')continue;

    await env.DB.prepare(`
      INSERT INTO admin_permissions (
        id,user_id,resource,
        can_view,can_create,can_edit,can_delete,
        created_at,updated_at
      )
      VALUES (?,?,?,?,?,?,?,?,?)
    `).bind(
      crypto.randomUUID(),
      id,
      r,
      p?.can_view?1:0,
      p?.can_create?1:0,
      p?.can_edit?1:0,
      p?.can_delete?1:0,
      n,
      n
    ).run()
  }

  return json({ok:true})
}


/* =========================================================
   D1 SCHEMA
========================================================= */

async function schema(env,table){
  return env.DB.prepare(`PRAGMA table_info(${quote(table)})`).all()
}

function quote(v){
  if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)){
    throw new Error('Ungültiger Bezeichner.')
  }
  return `"${v.replaceAll('"','""')}"`
}

function identity(s){
  const c=s.results||[];
  const p=c.filter(x=>Number(x.pk)===1);

  if(p.length===1)return p[0];

  return c.find(x=>x.name==='id')||c.find(x=>x.name==='key')||null
}

function normalize(value,col){
  if(value===null||value===undefined)return null;

  const t=String(col?.type||'').toUpperCase();

  if(t.includes('INT')){
    if(typeof value==='boolean')return value?1:0;
    if(value==='true')return 1;
    if(value==='false')return 0;
    if(value==='')return null;

    const n=Number(value);

    return Number.isFinite(n)?n:value
  }

  return String(value)
}

function sanitize(data,cols){
  if(!data||typeof data!=='object'||Array.isArray(data)){
    throw new Error('Ungültige Daten.')
  }

  const allow=new Set(cols.map(c=>c.name));
  const out={};

  for(const[k,v]of Object.entries(data)){
    if(!allow.has(k))continue;
    if(['created_at','updated_at','access_code_hash'].includes(k))continue;
    out[k]=v;
  }

  return out
}

async function handleAdminSchema(req,env,r){
  const a=await requirePermission(req,env,r,'view');
  if(a instanceof Response)return a;

  const t=RESOURCES[r];

  if(!t)return json({ok:false,error:'Unbekannter Bereich.'},404);

  const s=await schema(env,t);

  return json({
    ok:true,
    resource:r,
    label:RESOURCE_LABELS[r],
    table:t,
    identity:identity(s)?.name||null,
    columns:(s.results||[])
      .filter(c=>c.name!=='access_code_hash')
      .map(c=>({
        name:c.name,
        type:c.type,
        notnull:Number(c.notnull),
        default:c.dflt_value,
        pk:Number(c.pk)
      }))
  })
}


/* =========================================================
   GENERISCHES ADMIN CRUD
========================================================= */

async function handleAdminDataGet(req,env,r){
  const a=await requirePermission(req,env,r,'view');
  if(a instanceof Response)return a;

  const t=RESOURCES[r];

  if(!t)return json({ok:false,error:'Unbekannter Bereich.'},404);

  const rs=(await env.DB.prepare(`SELECT * FROM ${quote(t)}`).all()).results||[];

  return json({
    ok:true,
    resource:r,
    rows:rs.map(x=>{
      const y={...x};

      delete y.password_hash;
      delete y.password_salt;
      delete y.access_code_hash;

      return y
    })
  })
}

async function handleAdminDataCreate(req,env,r){
  const a=await requirePermission(req,env,r,'create');
  if(a instanceof Response)return a;

  const t=RESOURCES[r];

  if(!t)return json({ok:false,error:'Unbekannter Bereich.'},404);

  const s=await schema(env,t);
  const cols=s.results||[];

  if(!cols.length)return json({ok:false,error:'Tabelle nicht gefunden.'},404);

  let b;
  try{b=await req.json()}catch{return json({ok:false,error:'Ungültige Anfrage.'},400)}

  const d=sanitize(b,cols);
  const idc=identity(s);

  if(
    idc &&
    idc.name==='id' &&
    !('id' in d) &&
    /CHAR|TEXT|CLOB/i.test(String(idc.type||''))
  ){
    d.id=crypto.randomUUID()
  }

  const n=nowSec();

  if(cols.some(c=>c.name==='created_at')&&d.created_at===undefined){
    d.created_at=n
  }

  if(cols.some(c=>c.name==='updated_at')&&d.updated_at===undefined){
    d.updated_at=n
  }

  for(const c of cols){
    if(
      d[c.name]===undefined &&
      Number(c.notnull)===1 &&
      c.dflt_value===null &&
      Number(c.pk)===0
    ){
      return json({
        ok:false,
        error:`Pflichtfeld fehlt: ${c.name}`
      },400)
    }
  }

  const keys=Object.keys(d);

  if(!keys.length){
    return json({
      ok:false,
      error:'Keine Daten zum Speichern.'
    },400)
  }

  await env.DB.prepare(`
    INSERT INTO ${quote(t)} (${keys.map(quote).join(',')})
    VALUES (${keys.map(()=>'?').join(',')})
  `).bind(
    ...keys.map(k=>normalize(
      d[k],
      cols.find(c=>c.name===k)
    ))
  ).run();

  return json({
    ok:true,
    row:d
  },201)
}

async function handleAdminDataUpdate(req,env,r,v){
  const a=await requirePermission(req,env,r,'edit');
  if(a instanceof Response)return a;

  const t=RESOURCES[r];

  if(!t)return json({ok:false,error:'Unbekannter Bereich.'},404);

  const s=await schema(env,t);
  const cols=s.results||[];
  const idc=identity(s);

  if(!idc){
    return json({
      ok:false,
      error:'Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht bearbeitet werden.'
    },400)
  }

  let b;
  try{b=await req.json()}catch{return json({ok:false,error:'Ungültige Anfrage.'},400)}

  const d=sanitize(b,cols);
  delete d[idc.name];

  if(cols.some(c=>c.name==='updated_at')){
    d.updated_at=nowSec()
  }

  const keys=Object.keys(d);

  if(!keys.length){
    return json({
      ok:false,
      error:'Keine Änderungen übergeben.'
    },400)
  }

  const result=await env.DB.prepare(`
    UPDATE ${quote(t)}
    SET ${keys.map(k=>`${quote(k)}=?`).join(',')}
    WHERE ${quote(idc.name)}=?
  `).bind(
    ...keys.map(k=>normalize(
      d[k],
      cols.find(c=>c.name===k)
    )),
    normalize(v,idc)
  ).run();

  if(
    !result.success||
    Number(result.meta?.changes||0)===0
  ){
    return json({
      ok:false,
      error:'Datensatz wurde nicht gefunden oder nicht geändert.'
    },404)
  }

  return json({ok:true})
}

async function handleAdminDataDelete(req,env,r,v){
  const a=await requirePermission(req,env,r,'delete');
  if(a instanceof Response)return a;

  const t=RESOURCES[r];

  if(!t)return json({ok:false,error:'Unbekannter Bereich.'},404);

  const s=await schema(env,t);
  const idc=identity(s);

  if(!idc){
    return json({
      ok:false,
      error:'Diese Tabelle besitzt keinen eindeutigen Identifikator und kann deshalb nicht gelöscht werden.'
    },400)
  }

  const idValue=normalize(v,idc);
  const old=[];

  if(IMAGE_RESOURCES.has(r)){
    const row=await env.DB.prepare(`
      SELECT *
      FROM ${quote(t)}
      WHERE ${quote(idc.name)}=?
      LIMIT 1
    `).bind(idValue).first();

    if(row){
      for(const f of [
        'image_url',
        'image',
        'track_image_url'
      ]){
        if(
          typeof row[f]==='string' &&
          row[f].trim()
        ){
          old.push(row[f].trim())
        }
      }
    }
  }

  const result=await env.DB.prepare(`
    DELETE FROM ${quote(t)}
    WHERE ${quote(idc.name)}=?
  `).bind(idValue).run();

  if(
    !result.success||
    Number(result.meta?.changes||0)===0
  ){
    return json({
      ok:false,
      error:'Datensatz wurde nicht gefunden.'
    },404)
  }

  for(const u of old){
    try{
      await deleteImageByUrl(env,u)
    }catch(e){
      console.error('R2 cleanup failed:',e)
    }
  }

  return json({ok:true})
}


/* =========================================================
   R2 BILDSYSTEM
========================================================= */

function imageKey(url){
  try{
    const u=new URL(
      String(url||''),
      'https://jackalracing.com'
    );

    if(!u.pathname.startsWith('/media/'))return null;

    const k=decodeURIComponent(
      u.pathname.slice(7)
    );

    if(
      !k||
      k.includes('..')||
      k.includes('\\')
    ){
      return null
    }

    if(!IMAGE_RESOURCES.has(k.split('/')[0])){
      return null
    }

    return k
  }catch{
    return null
  }
}

async function deleteImageByUrl(env,url){
  if(!env.IMAGES)return false;

  const k=imageKey(url);

  if(!k)return false;

  await env.IMAGES.delete(k);

  return true
}

function imageUrl(req,k){
  const origin=new URL(req.url).origin;

  return `${origin}/media/${k
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`
}

async function handleImageUpload(req,env){
  const u=new URL(req.url);
  const r=String(
    u.searchParams.get('resource')||''
  ).trim();

  const a=String(
    u.searchParams.get('action')||'edit'
  ).trim().toLowerCase();

  if(!IMAGE_RESOURCES.has(r)){
    return json({
      ok:false,
      error:'Ungültiger Bildbereich.'
    },400)
  }

  if(!['create','edit'].includes(a)){
    return json({
      ok:false,
      error:'Ungültige Upload-Aktion.'
    },400)
  }

  const auth=await requirePermission(req,env,r,a);

  if(auth instanceof Response)return auth;

  if(!env.IMAGES){
    return json({
      ok:false,
      error:'R2 ist im Worker nicht verbunden.'
    },500)
  }

  const type=String(
    req.headers.get('Content-Type')||''
  ).toLowerCase();

  if(!type.startsWith('multipart/form-data')){
    return json({
      ok:false,
      error:'Upload muss als multipart/form-data erfolgen.'
    },400)
  }

  let fd;

  try{
    fd=await req.formData()
  }catch{
    return json({
      ok:false,
      error:'Upload-Daten konnten nicht gelesen werden.'
    },400)
  }

  const f=fd.get('file');

  if(!(f instanceof File)){
    return json({
      ok:false,
      error:'Keine Bilddatei übergeben.'
    },400)
  }

  if(!f.size){
    return json({
      ok:false,
      error:'Die Bilddatei ist leer.'
    },400)
  }

  if(f.size>MAX_IMAGE_SIZE){
    return json({
      ok:false,
      error:'Das Bild darf maximal 10 MB groß sein.'
    },413)
  }

  const mt=String(
    f.type||''
  ).toLowerCase();

  const ext=IMAGE_TYPES[mt];

  if(!ext){
    return json({
      ok:false,
      error:'Nicht unterstütztes Bildformat. Erlaubt sind JPG, PNG, WEBP und GIF.'
    },415)
  }

  const d=new Date();

  const k=
    `${r}/${d.getUTCFullYear()}/${String(
      d.getUTCMonth()+1
    ).padStart(2,'0')}/${crypto.randomUUID()}.${ext}`;

  await env.IMAGES.put(
    k,
    f.stream(),
    {
      httpMetadata:{
        contentType:mt,
        cacheControl:
          'public, max-age=31536000, immutable'
      },
      customMetadata:{
        resource:r,
        originalName:f.name||'image'
      }
    }
  );

  return json({
    ok:true,
    key:k,
    url:imageUrl(req,k),
    mime_type:mt,
    size:f.size,
    original_name:f.name||'image'
  },201)
}

async function handleImageDelete(req,env){
  const u=new URL(req.url);

  const r=String(
    u.searchParams.get('resource')||''
  ).trim();

  const a=String(
    u.searchParams.get('action')||'edit'
  ).trim().toLowerCase();

  const url=String(
    u.searchParams.get('url')||''
  ).trim();

  if(!IMAGE_RESOURCES.has(r)){
    return json({
      ok:false,
      error:'Ungültiger Bildbereich.'
    },400)
  }

  if(!['delete','edit'].includes(a)){
    return json({
      ok:false,
      error:'Ungültige Lösch-Aktion.'
    },400)
  }

  const auth=await requirePermission(req,env,r,a);

  if(auth instanceof Response)return auth;

  if(!env.IMAGES){
    return json({
      ok:false,
      error:'R2 ist im Worker nicht verbunden.'
    },500)
  }

  const k=imageKey(url);

  if(!k){
    return json({
      ok:false,
      error:'Ungültige Bild-URL.'
    },400)
  }

  await env.IMAGES.delete(k);

  return json({ok:true})
}

async function handlePublicImage(req,env){
  if(!env.IMAGES){
    return new Response(
      'R2 ist nicht verbunden.',
      {status:500}
    )
  }

  if(
    req.method!=='GET' &&
    req.method!=='HEAD'
  ){
    return new Response(
      'Method Not Allowed',
      {
        status:405,
        headers:{Allow:'GET, HEAD'}
      }
    )
  }

  const k=imageKey(
    new URL(req.url).toString()
  );

  if(!k){
    return new Response(
      'Nicht gefunden.',
      {status:404}
    )
  }

  const o=await env.IMAGES.get(k);

  if(!o){
    return new Response(
      'Nicht gefunden.',
      {status:404}
    )
  }

  const h=new Headers();

  o.writeHttpMetadata(h);
  h.set('etag',o.httpEtag);
  h.set(
    'Cache-Control',
    'public, max-age=31536000, immutable'
  );
  h.set(
    'X-Content-Type-Options',
    'nosniff'
  );

  return new Response(
    req.method==='HEAD'
      ? null
      : o.body,
    {
      status:200,
      headers:h
    }
  )
}


/* =========================================================
   NEXT RACE
========================================================= */

async function hashAccessCode(code){
  return sha256Hex(
    String(code||'').trim()
  )
}

function validAccessCode(code){
  const v=String(
    code||''
  ).trim();

  return v.length>=4&&v.length<=32
}

async function handleAdminNextRaceGet(req,env){
  const a=await requirePermission(
    req,
    env,
    'races',
    'view'
  );

  if(a instanceof Response)return a;

  const r=await env.DB.prepare(`
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
          OR TRIM(access_code_hash)=''
        THEN 0
        ELSE 1
      END AS has_access_code
    FROM races
    WHERE is_next=1
    ORDER BY id DESC
    LIMIT 1
  `).first();

  return json({
    ok:true,
    race:r||null
  })
}

async function handleAdminNextRaceSave(req,env){
  const a=await requirePermission(
    req,
    env,
    'races',
    'edit'
  );

  if(a instanceof Response)return a;

  let b;

  try{
    b=await req.json()
  }catch{
    return json({
      ok:false,
      error:'Ungültige Anfrage.'
    },400)
  }

  const id=String(
    b?.race_id??''
  ).trim();

  const code=String(
    b?.access_code??''
  ).trim();

  if(!id){
    await env.DB.prepare(
      'UPDATE races SET is_next=0'
    ).run();

    return json({
      ok:true,
      race:null
    })
  }

  const race=await env.DB.prepare(`
    SELECT
      id,
      access_code_hash
    FROM races
    WHERE id=?
    LIMIT 1
  `).bind(id).first();

  if(!race){
    return json({
      ok:false,
      error:'Das ausgewählte Rennen wurde nicht gefunden.'
    },404)
  }

  let hash=String(
    race.access_code_hash||''
  ).trim();

  if(code){
    if(!validAccessCode(code)){
      return json({
        ok:false,
        error:'Der Zugangscode muss zwischen 4 und 32 Zeichen lang sein.'
      },400)
    }

    hash=await hashAccessCode(code)
  }

  if(!hash){
    return json({
      ok:false,
      error:'Für dieses Next Race muss ein Zugangscode gesetzt werden.'
    },400)
  }

  await env.DB.prepare(
    'UPDATE races SET is_next=0'
  ).run();

  await env.DB.prepare(`
    UPDATE races
    SET
      is_next=1,
      access_code_hash=?
    WHERE id=?
  `).bind(
    hash,
    id
  ).run();

  const saved=await env.DB.prepare(`
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
    WHERE id=?
    LIMIT 1
  `).bind(id).first();

  return json({
    ok:true,
    race:saved||null
  })
}


/* =========================================================
   GESCHÜTZTE RACE DETAILS
========================================================= */

async function handlePublicRaceDetails(req,env){
  let b;

  try{
    b=await req.json()
  }catch{
    return json({
      ok:false,
      error:'Ungültige Anfrage.'
    },400)
  }

  const code=String(
    b?.access_code||''
  ).trim();

  if(!validAccessCode(code)){
    return json({
      ok:false,
      error:'Bitte einen gültigen Zugangscode eingeben.'
    },400)
  }

  const r=await env.DB.prepare(`
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
    WHERE is_next=1
    LIMIT 1
  `).first();

  if(!r){
    return json({
      ok:false,
      error:'Aktuell ist kein Next Race festgelegt.'
    },404)
  }

  const supplied=await hashAccessCode(code);

  if(
    !r.access_code_hash||
    supplied!==String(
      r.access_code_hash
    )
  ){
    return json({
      ok:false,
      error:'Der Zugangscode ist nicht korrekt.'
    },403)
  }

  return json({
    ok:true,
    race:{
      id:r.id,
      name:r.name,
      location:r.location,
      date:r.date,
      time:r.time,
      description:r.description,
      status:r.status,
      image_url:r.image_url,
      track_image_url:r.track_image_url
    }
  },200,{
    'Cache-Control':'no-store'
  })
}


/* =========================================================
   PUBLIC API
========================================================= */

async function publicRows(env,table,cols){
  const s=await schema(env,table);

  const available=new Set(
    (s.results||[]).map(
      c=>c.name
    )
  );

  const chosen=cols.filter(
    c=>available.has(c)
  );

  if(!chosen.length)return[];

  const r=await env.DB.prepare(`
    SELECT
      ${chosen.map(quote).join(',')}
    FROM ${quote(table)}
  `).all();

  return r.results||[]
}

function publicActive(v){
  return[
    'active',
    'aktiv',
    'aktive',
    'published',
    '1',
    'true',
    'ja'
  ].includes(
    String(v??'').trim().toLowerCase()
  )
}

async function handlePublicData(env){
  const[
    races,
    drivers,
    news,
    blacklist,
    gallery,
    results
  ]=await Promise.all([

    publicRows(
      env,
      'races',
      [
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
      ]
    ),

    publicRows(
      env,
      'drivers',
      [
        'id',
        'name',
        'nickname',
        'number',
        'team',
        'car',
        'image_url',
        'status',
        'points',
        'wins',
        'created_at'
      ]
    ),

    publicRows(
      env,
      'news',
      [
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
      ]
    ),

    publicRows(
      env,
      'blacklist',
      [
        'id',
        'vehicle_name',
        'reason',
        'image_url',
        'status',
        'created_at'
      ]
    ),

    publicRows(
      env,
      'gallery',
      [
        'id',
        'title',
        'image',
        'image_url',
        'description',
        'category',
        'date',
        'event',
        'car',
        'likes',
        'status',
        'created_at'
      ]
    ),

    publicRows(
      env,
      'race_results',
      [
        'id',
        'race_id',
        'driver_id',
        'position',
        'vehicle',
        'car',
        'time',
        'best_lap',
        'bestlap',
        'points',
        'created_at'
      ]
    )

  ]);

  const publicNews=
    news.filter(
      x=>
        x.active===undefined&&
        x.status===undefined
          ? true
          : x.active!==undefined
            ? publicActive(x.active)
            : publicActive(x.status)
    );

  const publicBlacklist=
    blacklist.filter(
      x=>
        x.status===undefined||
        publicActive(x.status)
    );

  const raceCount=new Map();

  for(const x of results){
    if(
      x.driver_id===undefined||
      x.driver_id===null
    ){
      continue
    }

    const k=String(
      x.driver_id
    );

    if(!raceCount.has(k)){
      raceCount.set(
        k,
        new Set()
      )
    }

    if(
      x.race_id!==undefined&&
      x.race_id!==null&&
      String(x.race_id).trim()
    ){
      raceCount
        .get(k)
        .add(
          String(x.race_id)
        )
    }
  }

  const publicDrivers=
    drivers.map(
      x=>({
        ...x,
        races:
          raceCount
            .get(String(x.id))
            ?.size||0
      })
    );

  const ranking=
    publicDrivers
      .slice()
      .sort(
        (a,b)=>{
          const p=
            (Number(b.points)||0)-
            (Number(a.points)||0);

          if(p)return p;

          const w=
            (Number(b.wins)||0)-
            (Number(a.wins)||0);

          if(w)return w;

          return String(
            a.name||''
          ).localeCompare(
            String(
              b.name||''
            ),
            'de-DE'
          )
        }
      )
      .map(
        (x,i)=>({
          place:i+1,
          ...x
        })
      );

  const nextRace=
    races.find(
      x=>Number(
        x.is_next
      )===1
    )||null;

  return json(
    {
      ok:true,
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
      'Cache-Control':
        'public, max-age=60'
    }
  )
}


/* =========================================================
   ROUTER
========================================================= */

export default{
  async fetch(request,env){
    const u=new URL(
      request.url
    );

    try{

      /* AUTH */

      if(
        u.pathname===
          '/api/login'&&
        request.method===
          'POST'
      ){
        return handleLogin(
          request,
          env
        )
      }

      if(
        u.pathname===
          '/api/logout'&&
        request.method===
          'POST'
      ){
        return handleLogout(
          request,
          env
        )
      }

      if(
        u.pathname===
          '/api/me'&&
        request.method===
          'GET'
      ){
        return handleMe(
          request,
          env
        )
      }


      /* PUBLIC RACE DETAILS */

      if(
        u.pathname===
          '/api/public/race-details'&&
        request.method===
          'POST'
      ){
        return handlePublicRaceDetails(
          request,
          env
        )
      }


      /* NEXT RACE ADMIN */

      if(
        u.pathname===
          '/api/admin/races/next'&&
        request.method===
          'GET'
      ){
        return handleAdminNextRaceGet(
          request,
          env
        )
      }

      if(
        u.pathname===
          '/api/admin/races/next'&&
        request.method===
          'POST'
      ){
        return handleAdminNextRaceSave(
          request,
          env
        )
      }


      /* R2 */

      if(
        u.pathname===
          '/api/admin/media/upload'&&
        request.method===
          'POST'
      ){
        return handleImageUpload(
          request,
          env
        )
      }

      if(
        u.pathname===
          '/api/admin/media'&&
        request.method===
          'DELETE'
      ){
        return handleImageDelete(
          request,
          env
        )
      }

      if(
        u.pathname.startsWith(
          '/media/'
        )&&
        (
          request.method==='GET'||
          request.method==='HEAD'
        )
      ){
        return handlePublicImage(
          request,
          env
        )
      }


      /* PUBLIC DATA */

      if(
        u.pathname===
          '/api/public/data'&&
        request.method===
          'GET'
      ){
        return handlePublicData(
          env
        )
      }


      /* USERS */

      if(
        u.pathname===
          '/api/admin/users'&&
        request.method===
          'GET'
      ){
        return handleAdminUsersGet(
          request,
          env
        )
      }

      if(
        u.pathname===
          '/api/admin/users'&&
        request.method===
          'POST'
      ){
        return handleAdminUserCreate(
          request,
          env
        )
      }


      /* USER PERMISSIONS */

      let m=u.pathname.match(
        /^\/api\/admin\/users\/([^/]+)\/permissions$/
      );

      if(
        m&&
        request.method===
          'PUT'
      ){
        return handleAdminPermissionsUpdate(
          request,
          env,
          m[1]
        )
      }


      /* USER DELETE */

      m=u.pathname.match(
        /^\/api\/admin\/users\/([^/]+)$/
      );

      if(
        m&&
        request.method===
          'DELETE'
      ){
        return handleAdminUserDelete(
          request,
          env,
          m[1]
        )
      }


      /* SCHEMA */

      m=u.pathname.match(
        /^\/api\/admin\/schema\/([^/]+)$/
      );

      if(
        m&&
        request.method===
          'GET'
      ){
        return handleAdminSchema(
          request,
          env,
          m[1]
        )
      }


      /* ADMIN DATA */

      m=u.pathname.match(
        /^\/api\/admin\/data\/([^/]+)$/
      );

      if(m){
        if(
          request.method===
            'GET'
        ){
          return handleAdminDataGet(
            request,
            env,
            m[1]
          )
        }

        if(
          request.method===
            'POST'
        ){
          return handleAdminDataCreate(
            request,
            env,
            m[1]
          )
        }
      }


      /* ADMIN DATA WITH ID */

      m=u.pathname.match(
        /^\/api\/admin\/data\/([^/]+)\/([^/]+)$/
      );

      if(m){
        const value=
          decodeURIComponent(
            m[2]
          );

        if(
          request.method===
            'PUT'
        ){
          return handleAdminDataUpdate(
            request,
            env,
            m[1],
            value
          )
        }

        if(
          request.method===
            'DELETE'
        ){
          return handleAdminDataDelete(
            request,
            env,
            m[1],
            value
          )
        }
      }


      /* STATIC WEBSITE */

      return env.ASSETS.fetch(
        request
      )

    }catch(e){
      console.error(
        'Worker error:',
        e
      );

      return json(
        {
          ok:false,
          error:'Interner Serverfehler.'
        },
        500
      )
    }
  }
};
