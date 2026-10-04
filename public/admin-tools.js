(function(){
  'use strict';

  const STYLE = `
    .hidden{display:none!important}
    .jackal-admin-auth-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-left:auto;flex:0 0 auto}
    .jackal-admin-auth-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:36px;padding:0 13px;border:1px solid rgba(178,102,255,.68);border-radius:3px;color:#fff;background:linear-gradient(180deg,#5c22c4,#4e18ae 60%,#43149a);box-shadow:0 0 12px rgba(168,85,255,.30),inset 0 1px 0 rgba(255,255,255,.08);font:800 13px 'Saira Condensed',sans-serif;letter-spacing:.05em;text-transform:uppercase;cursor:pointer;white-space:nowrap;text-decoration:none}
    .jackal-admin-auth-btn:hover{filter:brightness(1.12);box-shadow:0 0 18px rgba(178,102,255,.46)}
    .jackal-admin-auth-btn.secondary{background:rgba(20,15,34,.78);border-color:rgba(178,102,255,.55)}
    .jackal-admin-auth-btn.logout{background:rgba(20,15,34,.58);border-color:rgba(95,220,140,.24);color:#d8f5e2}
    .jackal-admin-auth-btn svg{width:15px;height:15px;flex:0 0 auto}
    .jackal-admin-edit{display:inline-flex;align-items:center;justify-content:center;gap:7px;margin-left:auto;padding:7px 11px;border:1px solid rgba(178,102,255,.65);border-radius:3px;color:#fff;background:linear-gradient(180deg,#5c22c4,#4e18ae 60%,#43149a);box-shadow:0 0 12px rgba(168,85,255,.24);font:800 13px 'Saira Condensed',sans-serif;letter-spacing:.05em;text-transform:uppercase;cursor:pointer;white-space:nowrap}
    .jackal-admin-edit:hover{filter:brightness(1.12);box-shadow:0 0 18px rgba(178,102,255,.42)}
    .next-race .jackal-admin-edit{position:absolute;top:16px;right:24px;z-index:6;margin-left:0}
    .jackal-admin-row-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:10px}
    .jackal-admin-inline{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(178,102,255,.55);border-radius:3px;color:#fff;background:rgba(78,24,174,.72);font:800 12px 'Saira Condensed',sans-serif;text-transform:uppercase;cursor:pointer}
    .jackal-admin-inline.danger{border-color:rgba(255,80,110,.45);background:rgba(120,20,50,.42);color:#ffd5df}
    .jackal-admin-inline.danger:hover{border-color:#ff5d7d;box-shadow:0 0 12px rgba(255,80,110,.20);color:#fff}
    .jackal-admin-row-actions .jackal-admin-inline{margin-left:0}
    .jackal-admin-home-modal{position:fixed;inset:0;z-index:9000;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(4,3,10,.18);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
    .jackal-home-admin-window{width:min(720px,94vw);max-height:min(760px,92vh);overflow:auto;border:1px solid rgba(178,102,255,.42);border-radius:10px;background:rgba(17,14,31,.96);box-shadow:0 30px 100px rgba(0,0,0,.45),0 0 38px rgba(168,85,255,.16)}
    .jackal-home-admin-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:20px;border-bottom:1px solid rgba(42,35,66,.9)}
    .jackal-home-admin-kicker{font:800 11px 'Saira Condensed',sans-serif;letter-spacing:.16em;color:#b266ff;text-transform:uppercase}
    .jackal-home-admin-head h2{margin:3px 0 0;font:800 30px 'Saira Condensed',sans-serif;font-style:italic;text-transform:uppercase;color:#fff}
    .jackal-home-admin-head p{margin:4px 0 0;color:#a49cbc;font:600 12px 'Rajdhani',sans-serif}
    .jackal-home-admin-close{width:34px;height:34px;border:1px solid rgba(75,47,138,.7);border-radius:3px;color:#ddd5eb;background:rgba(15,12,24,.78);font:700 18px 'Saira Condensed',sans-serif;cursor:pointer}
    .jackal-home-admin-body{padding:18px 20px}.jackal-home-admin-actions{display:flex;justify-content:flex-end;gap:9px;padding:16px 20px;border-top:1px solid rgba(42,35,66,.9)}
    .jackal-home-admin-cancel,.jackal-home-admin-save,.jackal-home-news-feature{border:1px solid rgba(178,102,255,.55);border-radius:3px;padding:9px 12px;color:#fff;background:#0f0c18;font:800 13px 'Saira Condensed',sans-serif;text-transform:uppercase;cursor:pointer}.jackal-home-admin-save{background:linear-gradient(180deg,#5c22c4,#4e18ae 60%,#43149a);box-shadow:0 0 15px rgba(168,85,255,.28)}
    .jackal-home-admin-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.jackal-home-admin-field{display:grid;gap:6px}.jackal-home-admin-field.full{grid-column:1/-1}.jackal-home-admin-field label{font:800 11px 'Rajdhani',sans-serif;color:#d9d3ec;letter-spacing:.08em;text-transform:uppercase}.jackal-home-admin-field input,.jackal-home-admin-field select{width:100%;padding:11px 12px;border:1px solid #2a2342;border-radius:4px;color:#fff;background:#0e0b17;outline:none}.jackal-home-admin-field input:focus,.jackal-home-admin-field select:focus{border-color:#b266ff}.jackal-home-admin-inline{display:flex;gap:7px}.jackal-home-admin-inline button{border:1px solid #4b2f8a;border-radius:3px;color:#fff;background:#251545;padding:0 12px;font:800 12px 'Saira Condensed',sans-serif;text-transform:uppercase;cursor:pointer}.jackal-home-admin-help,.jackal-home-news-note{margin-top:10px;color:#817892;font:600 11px 'Rajdhani',sans-serif;line-height:1.5}.jackal-home-admin-message{min-height:18px;margin-top:10px;color:#ff8798;font:700 12px 'Rajdhani',sans-serif}.jackal-home-news-list{display:grid;gap:8px;max-height:52vh;overflow:auto;margin-top:12px;padding-right:3px}.jackal-home-news-row{display:grid;grid-template-columns:auto 1fr auto auto;align-items:center;gap:10px;padding:10px 12px;border:1px solid #2a2342;border-radius:6px;background:#0e0b17;cursor:pointer}.jackal-home-news-row:hover{border-color:#4b2f8a}.jackal-home-news-row input{width:16px;height:16px;accent-color:#a855ff}.jackal-home-news-main strong{display:block;color:#fff;font:800 14px 'Saira Condensed',sans-serif}.jackal-home-news-main small{display:block;margin-top:2px;color:#756d80;font:600 10px 'Rajdhani',sans-serif}.jackal-home-news-status{font:700 9px 'Rajdhani',sans-serif;color:#b266ff;text-transform:uppercase;letter-spacing:.06em}.jackal-home-news-feature{padding:6px 9px;font-size:10px}.jackal-home-news-feature[aria-pressed="true"]{background:linear-gradient(180deg,#5c22c4,#4e18ae 60%,#43149a);box-shadow:0 0 12px rgba(168,85,255,.25)}
    @media(max-width:700px){.jackal-home-admin-grid{grid-template-columns:1fr}.jackal-home-admin-field.full{grid-column:auto}.jackal-home-news-row{grid-template-columns:auto 1fr}.jackal-home-news-status,.jackal-home-news-feature{grid-column:2}}
    .jackal-admin-news-actions{margin-left:auto;display:flex;align-items:center;justify-content:flex-end;gap:6px;flex-wrap:wrap}
    .jackal-admin-news-actions .jackal-admin-edit{margin-left:0;padding:6px 9px;font-size:11px}
    .jackal-login-overlay{background:rgba(4,3,10,.12)!important;backdrop-filter:blur(9px)!important;-webkit-backdrop-filter:blur(9px)!important}
    .jackal-login-modal{background:rgba(17,14,31,.92)!important;box-shadow:0 24px 90px rgba(0,0,0,.38),0 0 30px rgba(168,85,255,.16)!important}
    @media(max-width:960px){.jackal-admin-auth-actions{gap:5px}.jackal-admin-auth-btn{height:34px;padding:0 10px;font-size:12px}}
    @media(max-width:700px){.jackal-admin-auth-actions{gap:4px}.jackal-admin-auth-btn{padding:0 8px;font-size:11px}.jackal-admin-auth-btn svg{width:14px;height:14px}}
  `;

  const style=document.createElement('style');
  style.id='jackalAdminToolsStyle';
  style.textContent=STYLE;
  document.head.appendChild(style);

  let currentAuth=null;
  let observerTimer=null;
  let adminObserver=null;

  function esc(v){return String(v ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}

  function icon(type){
    if(type==='login') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"></rect><path d="M7 11V8a5 5 0 0 1 10 0v3"></path></svg>';
    if(type==='manage') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z"></path><path d="M19.4 15a1.8 1.8 0 0 0 .36 1.98l.05.05-1.9 1.9-.05-.05a1.8 1.8 0 0 0-1.98-.36 1.8 1.8 0 0 0-1.08 1.65V20h-2.7v-.07a1.8 1.8 0 0 0-1.08-1.65 1.8 1.8 0 0 0-1.98.36l-.05.05-1.9-1.9.05-.05A1.8 1.8 0 0 0 7.6 15a1.8 1.8 0 0 0-1.65-1.08H5.9v-2.7h.07A1.8 1.8 0 0 0 7.62 10.1 1.8 1.8 0 0 0 7.26 8.1l-.05-.05 1.9-1.9.05.05a1.8 1.8 0 0 0 1.98.36 1.8 1.8 0 0 0 1.08-1.65V4.8h2.7v.07a1.8 1.8 0 0 0 1.08 1.65 1.8 1.8 0 0 0 1.98-.36l.05-.05 1.9 1.9-.05.05A1.8 1.8 0 0 0 19.4 10c.2.66.8 1.08 1.5 1.08h.1v2.7h-.1c-.7 0-1.3.42-1.5 1.22Z"></path></svg>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 17l5-5-5-5"></path><path d="M15 12H3"></path><path d="M21 19V5"></path></svg>';
  }

  function ensureAuthControls(){
    const header=document.querySelector('.topbar');
    if(!header) return null;
    let old=header.querySelector('.login-link');
    let wrap=header.querySelector('.jackal-admin-auth-actions');
    if(!wrap){
      wrap=document.createElement('div');
      wrap.className='jackal-admin-auth-actions';
      if(old){
        old.replaceWith(wrap);
      }else{
        header.appendChild(wrap);
      }
      wrap.innerHTML=`<button type="button" class="jackal-admin-auth-btn" data-auth-action="login">${icon('login')}<span>Login</span></button><button type="button" class="jackal-admin-auth-btn secondary hidden" data-auth-action="manage">${icon('manage')}<span>Verwaltung</span></button><button type="button" class="jackal-admin-auth-btn logout hidden" data-auth-action="logout">${icon('logout')}<span>Logout</span></button>`;
      wrap.querySelector('[data-auth-action="login"]')?.addEventListener('click',()=>openLogin());
      wrap.querySelector('[data-auth-action="manage"]')?.addEventListener('click',()=>openManagement());
      wrap.querySelector('[data-auth-action="logout"]')?.addEventListener('click',()=>logout());
    }
    return wrap;
  }

  function clearInjectedAdminUi(){
    document.querySelectorAll('.jackal-admin-edit,.jackal-admin-inline').forEach(el=>el.remove());
    document.querySelectorAll('.jackal-admin-row-actions').forEach(row=>{
      if(!row.children.length) row.remove();
    });
  }

  function setAuthUi(auth){
    const wrap=ensureAuthControls();
    if(!wrap) return;
    const login=wrap.querySelector('[data-auth-action="login"]');
    const manage=wrap.querySelector('[data-auth-action="manage"]');
    const logoutBtn=wrap.querySelector('[data-auth-action="logout"]');
    const yes=!!auth;
    login?.classList.toggle('hidden',yes);
    manage?.classList.toggle('hidden',!yes);
    logoutBtn?.classList.toggle('hidden',!yes);
    if(!yes) clearInjectedAdminUi();
  }

  function openLogin(){
    const overlay=document.getElementById('jackalLoginOverlay');
    const msg=document.getElementById('jackalLoginMessage');
    if(!overlay) return;
    if(msg) msg.textContent='';
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden','false');
    setTimeout(()=>document.getElementById('jackalLoginUsername')?.focus(),40);
  }
  function closeLogin(){
    const overlay=document.getElementById('jackalLoginOverlay');
    if(!overlay) return;
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden','true');
  }

  async function getAuth(force=false){
    if(!force && currentAuth) return currentAuth;
    try{
      const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
      if(!r.ok){currentAuth=null;return null;}
      const d=await r.json().catch(()=>null);
      currentAuth=d?.ok?d:null;
      return currentAuth;
    }catch(_){currentAuth=null;return null;}
  }

  function can(auth,resource,action){
    return !!auth && (auth.is_superadmin || Number(auth.permissions?.[resource]?.[`can_${action}`]||0)===1);
  }

  function addButton(container,label,params,opts={}){
    if(!container || container.querySelector(`.jackal-admin-edit[data-action-key="${CSS.escape(opts.key||params)}"]`)) return;
    const button=document.createElement('button');
    button.type='button';button.className='jackal-admin-edit';button.dataset.actionKey=opts.key||params;button.textContent=label;
    button.addEventListener('click',e=>{
      e.preventDefault(); e.stopPropagation();
      if(params==='home-next-race') return openHomeNextRaceManager();
      if(params==='home-news-manager') return openHomeNewsManager();
      openEditor(params);
    });
    container.appendChild(button);
  }

  async function deleteResource(resource,id,label){
    if(!currentAuth){ setAuthUi(null); return; }
    if(!can(currentAuth,resource,'delete')) return;
    if(!window.confirm(`"${label || resource}" wirklich löschen?`)) return;
    try{
      const r=await fetch(`/api/admin/data/${encodeURIComponent(resource)}/${encodeURIComponent(String(id))}`,{
        method:'DELETE',credentials:'same-origin',cache:'no-store'
      });
      const d=await r.json().catch(()=>({}));
      if(!r.ok||!d.ok) throw new Error(d.error||'Löschen fehlgeschlagen.');
      location.reload();
    }catch(e){
      if(String(e?.message||'').includes('Nicht angemeldet')){
        currentAuth=null;setAuthUi(null);openLogin();return;
      }
      window.alert(e.message||'Löschen fehlgeschlagen.');
    }
  }

  async function openEditor(params){
    const auth=currentAuth || await getAuth();
    if(!auth){ setAuthUi(null); openLogin(); return; }
    const overlay=document.getElementById('jackalAdminEditOverlay');
    const frame=document.getElementById('jackalAdminEditFrame');
    if(!overlay||!frame) return;
    frame.src='/admin?'+params;
    overlay.classList.remove('management-mode');
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden','false');
    document.body.classList.add('jackal-admin-edit-open');
  }

  function openManagement(){
    Promise.resolve(currentAuth || getAuth()).then(auth=>{
      if(!auth){setAuthUi(null);openLogin();return;}
      const overlay=document.getElementById('jackalAdminEditOverlay');
      const frame=document.getElementById('jackalAdminEditFrame');
      if(!overlay||!frame) return;
      frame.src='/admin';
      overlay.classList.add('management-mode');
      overlay.classList.add('open');
      overlay.setAttribute('aria-hidden','false');
      document.body.classList.add('jackal-admin-edit-open');
    });
  }

  function closeEditor(){
    const overlay=document.getElementById('jackalAdminEditOverlay');
    const frame=document.getElementById('jackalAdminEditFrame');
    if(!overlay)return;
    overlay.classList.remove('open','management-mode');overlay.setAttribute('aria-hidden','true');
    if(frame)frame.src='about:blank';
    document.body.classList.remove('jackal-admin-edit-open');
  }

  function ensureOverlay(){
    if(document.getElementById('jackalAdminEditOverlay')) return;
    const wrap=document.createElement('div');
    wrap.innerHTML=`<div class="jackal-admin-edit-overlay" id="jackalAdminEditOverlay" aria-hidden="true"><div class="jackal-admin-edit-window" role="dialog" aria-modal="true" aria-label="JACKAL Verwaltung"><button class="jackal-admin-edit-close" type="button" id="jackalAdminEditClose" aria-label="Fenster schließen">×</button><iframe id="jackalAdminEditFrame" title="JACKAL Verwaltung" src="about:blank"></iframe></div></div>`;
    document.body.appendChild(wrap.firstElementChild);
    const s=document.createElement('style');
    s.textContent=`
      .jackal-admin-edit-overlay{position:fixed;inset:0;z-index:7000;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(4,3,10,.10);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      .jackal-admin-edit-overlay.open{display:flex}
      .jackal-admin-edit-window{position:relative;width:min(920px,96vw);height:min(760px,92vh);border:1px solid rgba(178,102,255,.42);border-radius:10px;overflow:hidden;background:rgba(13,10,22,.78);box-shadow:0 30px 100px rgba(0,0,0,.40),0 0 38px rgba(168,85,255,.15);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
      .jackal-admin-edit-overlay.management-mode{padding:0;align-items:stretch;justify-content:stretch;background:rgba(4,3,10,.16)}
      .jackal-admin-edit-overlay.management-mode .jackal-admin-edit-window{width:100vw;height:100vh;border:0;border-radius:0;background:rgba(13,10,22,.94);box-shadow:none;backdrop-filter:none;-webkit-backdrop-filter:none}
      .jackal-admin-edit-window iframe{width:100%;height:100%;display:block;border:0;background:transparent}
      .jackal-admin-edit-close{position:absolute;top:9px;right:9px;z-index:5;width:34px;height:34px;border:1px solid rgba(75,47,138,.7);border-radius:3px;color:#ddd5eb;background:rgba(15,12,24,.78);font:700 19px 'Saira Condensed',sans-serif;cursor:pointer}
      .jackal-admin-edit-close:hover{color:#fff;border-color:#b266ff;box-shadow:0 0 12px rgba(168,85,255,.28)}
    `;
    document.head.appendChild(s);
    document.getElementById('jackalAdminEditClose')?.addEventListener('click',closeEditor);
    document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.getElementById('jackalAdminEditOverlay')?.classList.contains('open'))closeEditor();});
  }

  function addHeadButton(card,label,params,key){
    const head=card?.querySelector('.head,.big-head,.card-head,.card-header');
    if(head){
      addButton(head,label,params,{key});
      return;
    }

    // Home: the Next Race card has no standard card header.
    // Put its admin action into the content area instead.
    if(card?.classList?.contains('next-race')){
      const host=card.querySelector('.next-race-content');
      if(host) addButton(host,label,params,{key});
    }
  }

  function createHomeModal(title, subtitle, bodyHtml, onSave, saveLabel='Speichern'){
    let overlay=document.getElementById('jackalHomeAdminModal');
    if(overlay) overlay.remove();
    overlay=document.createElement('div');
    overlay.id='jackalHomeAdminModal';
    overlay.className='jackal-admin-home-modal';
    overlay.innerHTML=`<div class="jackal-home-admin-window" role="dialog" aria-modal="true" aria-label="${esc(title)}"><div class="jackal-home-admin-head"><div><div class="jackal-home-admin-kicker">JACKAL ADMIN</div><h2>${esc(title)}</h2><p>${esc(subtitle||'')}</p></div><button type="button" class="jackal-home-admin-close" aria-label="Fenster schließen">×</button></div><div class="jackal-home-admin-body">${bodyHtml}</div><div class="jackal-home-admin-actions"><button type="button" class="jackal-home-admin-cancel">Abbrechen</button><button type="button" class="jackal-home-admin-save">${esc(saveLabel)}</button></div></div>`;
    document.body.appendChild(overlay);
    const close=()=>overlay.remove();
    overlay.querySelector('.jackal-home-admin-close')?.addEventListener('click',close);
    overlay.querySelector('.jackal-home-admin-cancel')?.addEventListener('click',close);
    overlay.querySelector('.jackal-home-admin-save')?.addEventListener('click',async()=>{
      const btn=overlay.querySelector('.jackal-home-admin-save');
      try{ btn.disabled=true; await onSave?.(overlay); close(); location.reload(); }
      catch(e){ btn.disabled=false; const msg=overlay.querySelector('.jackal-home-admin-message'); if(msg) msg.textContent=e?.message||'Speichern fehlgeschlagen.'; }
    });
    return overlay;
  }

  function randomAccessCode(){
    const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes=crypto.getRandomValues(new Uint8Array(8));
    let out='';
    for(const b of bytes) out += alphabet[b % alphabet.length];
    return out;
  }

  async function openHomeNextRaceManager(){
    const data=await fetch('/api/public/data',{cache:'no-store'}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw new Error(d.error||'Website-Daten konnten nicht geladen werden.');return d;});
    const dash=await fetch('/api/admin/news/dashboard',{credentials:'same-origin',cache:'no-store'}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw new Error(d.error||'Home-Konfiguration konnte nicht geladen werden.');return d;});
    const races=Array.isArray(data.races)?data.races.slice().sort((a,b)=>String(a.date||'').localeCompare(String(b.date||''))):[];
    const selected=String(dash.config?.next_race_id||'');
    const current=String(selected || data.nextRace?.id || races.find(r=>Number(r.is_next)===1)?.id || '');
    const opts=races.map(r=>`<option value="${esc(String(r.id))}" ${String(r.id)===current?'selected':''}>${esc(r.name||'Rennen')} · ${esc(String(r.date||''))}${r.time?` · ${esc(String(r.time).slice(0,5))}`:''}</option>`).join('');
    const html=`<div class="jackal-home-admin-grid"><div class="jackal-home-admin-field full"><label>Rennen für Home</label><select id="homeNextRaceSelect"><option value="">Kein Rennen ausgewählt</option>${opts}</select></div><div class="jackal-home-admin-field"><label>Anzeigemodus</label><select id="homeNextRaceMode"><option value="next_race" ${String(dash.config?.display_mode||'next_race')==='next_race'?'selected':''}>Next Race</option><option value="next_event" ${String(dash.config?.display_mode||'next_race')==='next_event'?'selected':''}>Next Event</option><option value="last_race" ${String(dash.config?.display_mode||'next_race')==='last_race'?'selected':''}>Letztes Rennen</option></select></div><div class="jackal-home-admin-field"><label>Zugangscode</label><div class="jackal-home-admin-inline"><input id="homeNextRaceCode" maxlength="32" placeholder="Neuen Code eingeben..."><button type="button" id="homeNextRaceGenerate">Generieren</button></div></div></div><div class="jackal-home-admin-help">Das hier festgelegte Rennen wird auf der Home-Seite angezeigt. Mit „Generieren“ kannst du direkt einen neuen Zugangscode setzen.</div><div class="jackal-home-admin-message"></div>`;
    const overlay=createHomeModal('Next Race verwalten','Home · Event-Bereich',html,async ov=>{
      const raceId=ov.querySelector('#homeNextRaceSelect')?.value||'';
      const mode=ov.querySelector('#homeNextRaceMode')?.value||'next_race';
      const code=ov.querySelector('#homeNextRaceCode')?.value.trim()||randomAccessCode();
      if(raceId){
        const nextRes=await fetch('/api/admin/races/next',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({race_id:raceId,access_code:code})});
        const nextData=await nextRes.json().catch(()=>({}));
        if(!nextRes.ok||!nextData.ok) throw new Error(nextData.error||'Next Race konnte nicht gespeichert werden.');
      }else{
        await fetch('/api/admin/races/next',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({race_id:'',access_code:''})}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw new Error(d.error||'Next Race konnte nicht entfernt werden.');});
      }
      const payload={display_mode:mode,next_race_id:raceId,latest_news_ids:dash.config?.latest_news_ids||[],featured_news_id:dash.config?.featured_news_id||'',hearts_winner_driver_id:dash.config?.hearts_winner_driver_id||'',hearts_quote:dash.config?.hearts_quote||'',poll_active:Number(dash.config?.poll_active)===1,poll_question:dash.config?.poll_question||'Wer war dein Sieger der Herzen?',poll_options:dash.config?.poll_options||[]};
      const cfgRes=await fetch('/api/admin/news/dashboard',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const cfgData=await cfgRes.json().catch(()=>({}));
      if(!cfgRes.ok||!cfgData.ok) throw new Error(cfgData.error||'Home-Konfiguration konnte nicht gespeichert werden.');
    },'Speichern');
    overlay.querySelector('#homeNextRaceGenerate')?.addEventListener('click',()=>{const i=overlay.querySelector('#homeNextRaceCode');if(i)i.value=randomAccessCode();});
    return overlay;
  }

  async function openHomeNewsManager(){
    const [publicRes,dashRes]=await Promise.all([
      fetch('/api/public/data',{cache:'no-store'}),
      fetch('/api/admin/news/dashboard',{credentials:'same-origin',cache:'no-store'})
    ]);
    const data=await publicRes.json().catch(()=>({}));
    const dash=await dashRes.json().catch(()=>({}));
    if(!publicRes.ok||!data.ok) throw new Error(data.error||'News konnten nicht geladen werden.');
    if(!dashRes.ok||!dash.ok) throw new Error(dash.error||'Home-News-Konfiguration konnte nicht geladen werden.');
    const selected=new Set((dash.config?.latest_news_ids||[]).map(String));
    const featured=String(dash.config?.featured_news_id||'');
    const news=(data.news||[]).slice().sort((a,b)=>String(b.date||b.created_at||'').localeCompare(String(a.date||a.created_at||'')));
    const rows=news.length?news.map(n=>`<label class="jackal-home-news-row"><input type="checkbox" data-home-news-id="${esc(String(n.id))}" ${selected.has(String(n.id))?'checked':''}><span class="jackal-home-news-main"><strong>${esc(n.title||'Unbenannte News')}</strong><small>${esc(String(n.date||n.created_at||''))}</small></span><span class="jackal-home-news-status">${esc(String(n.category||'ALLGEMEIN'))}</span><button type="button" class="jackal-home-news-feature" data-feature-id="${esc(String(n.id))}" aria-pressed="${featured===String(n.id)?'true':'false'}">${featured===String(n.id)?'Featured':'Als Featured setzen'}</button></label>`).join(''):'<div class="jackal-home-admin-help">Noch keine News vorhanden.</div>';
    const html=`<div class="jackal-home-news-note">Wähle bis zu 3 Meldungen aus, die auf Home unter „Latest News“ erscheinen sollen. Nicht ausgewählte News werden dort nicht eingeblendet. Optional kannst du eine davon als Featured markieren.</div><div class="jackal-home-news-list">${rows}</div><div class="jackal-home-admin-message"></div>`;
    const overlay=createHomeModal('News verwalten','Home · Latest News',html,async ov=>{
      const ids=[...ov.querySelectorAll('[data-home-news-id]:checked')].map(x=>x.dataset.homeNewsId).filter(Boolean).slice(0,3);
      let feat=ov.querySelector('[data-feature-id][aria-pressed="true"]')?.dataset.featureId||'';
      if(feat && !ids.includes(String(feat))) feat='';
      const payload={...dash.config,latest_news_ids:ids,featured_news_id:feat};
      const r=await fetch('/api/admin/news/dashboard',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const d=await r.json().catch(()=>({}));
      if(!r.ok||!d.ok) throw new Error(d.error||'Latest News konnten nicht gespeichert werden.');
    });
    overlay.querySelectorAll('[data-feature-id]').forEach(btn=>btn.addEventListener('click',()=>{overlay.querySelectorAll('[data-feature-id]').forEach(b=>b.setAttribute('aria-pressed','false'));btn.setAttribute('aria-pressed','true');}));
    return overlay;
  }

  function setupIndex(auth){
    if(!auth) return;
    const next=document.querySelector('.next-race');
    if(next && can(auth,'races','edit')) addHeadButton(next,'Next Race verwalten','home-next-race','home-next-race');
    const news=document.querySelector('section.card.news');
    if(news && can(auth,'news','edit')) addHeadButton(news,'News verwalten','home-news-manager','home-news-manager');
    const hearts=document.querySelector('.hearts');
    if(hearts && can(auth,'news','edit')) addHeadButton(hearts,'Sieger & Abstimmung','embed=special&special=hearts-poll','home-hearts');
    const laps=document.querySelector('.laps');
    if(laps && can(auth,'results','create')) addHeadButton(laps,'Rundenzeiten verwalten','embed=crud&resource=results&action=new','home-laps');
    const champion=document.querySelector('.champion');
    if(champion){
      champion.querySelectorAll('[data-action-key="home-champion"]').forEach(el=>el.remove());
    }
  }

  function setupNews(auth){
    if(!auth) return;

    const best=document.querySelector('.bestlist');
    if(best && can(auth,'results','edit')){
      addHeadButton(best,'Bestenliste verwalten','embed=special&special=news-bestlist','news-bestlist');
    }

    const race=document.querySelector('.race-card');
    if(race && can(auth,'news','edit')){
      addHeadButton(race,'Bereich verwalten','embed=special&special=news-event','news-event');
    }

    const newsCard=document.querySelector('.changes');
    if(newsCard){
      const head=newsCard.querySelector('.big-head');
      if(head && !head.querySelector('.jackal-admin-news-actions')){
        const group=document.createElement('div');
        group.className='jackal-admin-news-actions';

        if(can(auth,'news','create')){
          const b=document.createElement('button');
          b.type='button'; b.className='jackal-admin-edit';
          b.dataset.actionKey='news-manage'; b.textContent='News verwalten';
          b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=special&special=news-manage');});
          group.appendChild(b);
        }

        if(can(auth,'news','edit')){
          const b=document.createElement('button');
          b.type='button'; b.className='jackal-admin-edit';
          b.dataset.actionKey='news-archive-manage'; b.textContent='News Archiv';
          b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=special&special=news-archive');});
          group.appendChild(b);
        }

        if(group.children.length) head.appendChild(group);
      }
    }

    const hearts=document.querySelector('.hearts');
    if(hearts && can(auth,'news','edit')){
      const head=hearts.querySelector('.hearts-left .big-head,.big-head,.card-head');
      if(head) addButton(head,'Sieger der Herzen verwalten','embed=special&special=hearts-poll',{key:'news-hearts'});
    }

    const poll=document.querySelector('.poll');
    if(poll && can(auth,'news','edit')){
      const pollHead=poll.querySelector('.poll-head');
      if(pollHead && !pollHead.querySelector('[data-action-key="news-poll"]')){
        const b=document.createElement('button');
        b.type='button'; b.className='jackal-admin-edit';
        b.dataset.actionKey='news-poll'; b.textContent='Abstimmung verwalten';
        b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=special&special=poll');});
        pollHead.style.display='flex'; pollHead.style.alignItems='center'; pollHead.style.justifyContent='space-between';
        pollHead.appendChild(b);
      }
    }

    const laps=document.querySelector('.laps');
    if(laps && can(auth,'results','edit')){
      const host=laps.querySelector('.card-foot') || laps.querySelector('.table-wrap');
      if(host) addButton(host,'Rundenzeiten verwalten','embed=special&special=news-laps',{key:'news-laps'});
    }

    document.querySelectorAll('.news-read-link[data-news-id]').forEach(link=>{
      const id=link.dataset.newsId; if(!id || link.dataset.jackalAdminWired==='1') return;
      link.dataset.jackalAdminWired='1';
      const parent=link.parentElement; if(!parent) return;
      let row=parent.querySelector('.jackal-admin-row-actions');
      if(!row){ row=document.createElement('div'); row.className='jackal-admin-row-actions'; parent.appendChild(row); }

      if(can(auth,'news','edit')){
        const b=document.createElement('button'); b.type='button'; b.className='jackal-admin-inline';
        b.dataset.actionKey=`news-edit-${id}`; b.textContent='News bearbeiten';
        b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor(`embed=crud&resource=news&action=edit&id=${encodeURIComponent(id)}`);});
        row.appendChild(b);
      }
      if(can(auth,'news','delete')){
        const b=document.createElement('button'); b.type='button'; b.className='jackal-admin-inline danger';
        b.dataset.actionKey=`news-delete-${id}`; b.textContent='Löschen';
        b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();deleteResource('news',id,link.textContent.trim());});
        row.appendChild(b);
      }
    });
  }

  function setupDrivers(auth){
    if(!auth) return;
    const card=document.querySelector('main .card');
    if(card && can(auth,'drivers','create')) addHeadButton(card,'+ Fahrer','embed=crud&resource=drivers&action=new','drivers-new');
    document.querySelectorAll('.driver[data-driver-id]').forEach(el=>{
      const id=el.dataset.driverId;
      if(!id) return;
      const actions=el.querySelector('.jackal-admin-row-actions')||document.createElement('div');
      actions.className='jackal-admin-row-actions';
      if(can(auth,'drivers','edit') && !actions.querySelector(`[data-action-key="driver-edit-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey=`driver-edit-${id}`;b.textContent='Bearbeiten';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor(`embed=crud&resource=drivers&action=edit&id=${encodeURIComponent(id)}`)});actions.appendChild(b);
      }
      if(can(auth,'drivers','delete') && !actions.querySelector(`[data-action-key="driver-delete-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline danger';b.dataset.actionKey=`driver-delete-${id}`;b.textContent='Löschen';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();deleteResource('drivers',id,el.querySelector('h2')?.textContent?.trim()||'Fahrer')});actions.appendChild(b);
      }
      if(actions.children.length && !actions.parentElement) el.appendChild(actions);
      else if(actions.children.length && !el.contains(actions)) el.appendChild(actions);
    });
  }

  function setupRanking(auth){
    if(!auth || !can(auth,'drivers','edit')) return;
    const card=document.querySelector('main .card');
    if(card) addHeadButton(card,'Punkte & Fahrer bearbeiten','embed=crud&resource=drivers&action=new','ranking-edit');
  }

  function setupRaces(auth){
    if(!auth) return;
    const toolbar=document.querySelector('main .toolbar');
    if(toolbar && can(auth,'races','create') && !toolbar.querySelector('[data-action-key="races-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='races-new';b.textContent='+ Neues Rennen';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=crud&resource=races&action=new')});row.appendChild(b);toolbar.appendChild(row);
    }
    document.querySelectorAll('.race[data-race-id]').forEach(el=>{
      const id=el.dataset.raceId;if(!id) return;
      const body=el.querySelector('.race-body')||el;
      const row=body.querySelector('.jackal-admin-row-actions')||document.createElement('div');row.className='jackal-admin-row-actions';
      if(can(auth,'races','edit') && !row.querySelector(`[data-action-key="race-edit-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey=`race-edit-${id}`;b.textContent='Rennen bearbeiten';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor(`embed=crud&resource=races&action=edit&id=${encodeURIComponent(id)}`)});row.appendChild(b);
      }
      if(can(auth,'races','delete') && !row.querySelector(`[data-action-key="race-delete-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline danger';b.dataset.actionKey=`race-delete-${id}`;b.textContent='Löschen';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();deleteResource('races',id,el.querySelector('.race-title,.race-name,h2')?.textContent?.trim()||'Rennen')});row.appendChild(b);
      }
      if(row.children.length && !body.contains(row)) body.appendChild(row);
    });
  }

  function setupBlacklist(auth){
    if(!auth) return;
    const toolbar=document.querySelector('main .toolbar');
    if(toolbar && can(auth,'blacklist','create') && !toolbar.querySelector('[data-action-key="blacklist-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='blacklist-new';b.textContent='+ Fahrzeug';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=crud&resource=blacklist&action=new')});row.appendChild(b);toolbar.appendChild(row);
    }
    document.querySelectorAll('.item[data-blacklist-id]').forEach(el=>{
      const id=el.dataset.blacklistId;if(!id) return;
      const host=el.querySelector('.body')||el;
      const row=host.querySelector('.jackal-admin-row-actions')||document.createElement('div');row.className='jackal-admin-row-actions';
      if(can(auth,'blacklist','edit') && !row.querySelector(`[data-action-key="blacklist-edit-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey=`blacklist-edit-${id}`;b.textContent='Bearbeiten';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor(`embed=crud&resource=blacklist&action=edit&id=${encodeURIComponent(id)}`)});row.appendChild(b);
      }
      if(can(auth,'blacklist','delete') && !row.querySelector(`[data-action-key="blacklist-delete-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline danger';b.dataset.actionKey=`blacklist-delete-${id}`;b.textContent='Löschen';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();deleteResource('blacklist',id,el.querySelector('.name')?.textContent?.trim()||'Fahrzeug')});row.appendChild(b);
      }
      if(row.children.length && !host.contains(row)) host.appendChild(row);
    });
  }

  function setupGallery(auth){
    if(!auth) return;
    const toolbar=document.querySelector('main .toolbar');
    if(toolbar && can(auth,'gallery','create') && !toolbar.querySelector('[data-action-key="gallery-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='gallery-new';b.textContent='+ Foto';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor('embed=crud&resource=gallery&action=new')});row.appendChild(b);toolbar.appendChild(row);
    }
    document.querySelectorAll('.tile[data-gallery-id]').forEach(el=>{
      const id=el.dataset.galleryId;if(!id) return;
      const host=el.querySelector('.caption')||el;
      const row=host.querySelector('.jackal-admin-row-actions')||document.createElement('div');row.className='jackal-admin-row-actions';
      if(can(auth,'gallery','edit') && !row.querySelector(`[data-action-key="gallery-edit-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey=`gallery-edit-${id}`;b.textContent='Bearbeiten';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();openEditor(`embed=crud&resource=gallery&action=edit&id=${encodeURIComponent(id)}`)});row.appendChild(b);
      }
      if(can(auth,'gallery','delete') && !row.querySelector(`[data-action-key="gallery-delete-${CSS.escape(String(id))}"]`)){
        const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline danger';b.dataset.actionKey=`gallery-delete-${id}`;b.textContent='Löschen';b.addEventListener('click',e=>{e.preventDefault();e.stopPropagation();deleteResource('gallery',id,el.querySelector('.title')?.textContent?.trim()||'Foto')});row.appendChild(b);
      }
      if(row.children.length && !host.contains(row)) host.appendChild(row);
    });
  }

  function init(auth){
    ensureOverlay();
    setAuthUi(auth);
    if(!auth) return;
    const path=location.pathname.replace(/\/$/,'')||'/';
    if(path==='/'||path==='/index.html')setupIndex(auth);
    else if(path==='/news')setupNews(auth);
    else if(path==='/drivers')setupDrivers(auth);
    else if(path==='/rangliste')setupRanking(auth);
    else if(path==='/races')setupRaces(auth);
    else if(path==='/blacklist')setupBlacklist(auth);
    else if(path==='/gallery')setupGallery(auth);
  }

  async function logout(){
    try{await fetch('/api/logout',{method:'POST',credentials:'same-origin'});}catch(_){}
    currentAuth=null;
    closeEditor();
    location.reload();
  }

  function wireLoginModal(){
    const overlay=document.getElementById('jackalLoginOverlay');
    const close=document.getElementById('jackalLoginClose');
    const form=document.getElementById('jackalLoginForm');
    const message=document.getElementById('jackalLoginMessage');
    if(!overlay||!form||form.dataset.authWired==='1')return;
    form.dataset.authWired='1';
    close?.addEventListener('click',closeLogin);
    overlay.addEventListener('click',e=>{if(e.target===overlay)closeLogin();});
    document.addEventListener('keydown',e=>{if(e.key==='Escape'&&overlay.classList.contains('open'))closeLogin();});
    form.addEventListener('submit',async e=>{
      e.preventDefault();
      const username=document.getElementById('jackalLoginUsername')?.value.trim()||'';
      const password=document.getElementById('jackalLoginPassword')?.value||'';
      if(message)message.textContent='Anmeldung wird geprüft...';
      try{
        const r=await fetch('/api/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
        const d=await r.json().catch(()=>({}));
        if(!r.ok||!d.ok){if(message)message.textContent=d.error||'Benutzername oder Passwort ist falsch.';return;}
        if(document.getElementById('jackalLoginPassword'))document.getElementById('jackalLoginPassword').value='';
        closeLogin();
        const auth=await getAuth(true);
        currentAuth=auth;
        setAuthUi(auth);
        init(auth);
      }catch(_){if(message)message.textContent='Der Login-Server ist momentan nicht erreichbar.';}
    });
  }

  window.addEventListener('message',event=>{
    if(event.origin!==location.origin)return;
    if(event.data?.type==='jackal-admin-saved'){closeEditor();setTimeout(()=>location.reload(),120);}
    if(event.data?.type==='jackal-admin-close')closeEditor();
    if(event.data?.type==='jackal-admin-auth-required'){currentAuth=null;closeEditor();setAuthUi(null);setTimeout(openLogin,50);}
  });

  document.addEventListener('DOMContentLoaded',async()=>{
    ensureAuthControls();
    wireLoginModal();
    ensureOverlay();
    const auth=await getAuth(true);
    currentAuth=auth;
    init(auth);
    if(auth){
      adminObserver=new MutationObserver((mutations)=>{
        const relevant=mutations.some(m=>{
          const nodes=[...m.addedNodes,...m.removedNodes].filter(n=>n.nodeType===1);
          if(!nodes.length) return false;
          return nodes.some(node=>{
            const el=node;
            if(el.matches?.('.jackal-admin-auth-actions,.jackal-admin-edit-overlay,.jackal-admin-row-actions,.jackal-admin-edit,.jackal-admin-inline,.jackal-admin-home-modal')) return false;
            if(el.closest?.('.jackal-admin-auth-actions,.jackal-admin-edit-overlay,.jackal-admin-row-actions')) return false;
            return true;
          });
        });
        if(!relevant || !currentAuth || observerTimer) return;
        observerTimer=setTimeout(()=>{observerTimer=null;if(currentAuth)init(currentAuth);},60);
      });
      adminObserver.observe(document.body,{childList:true,subtree:true});
    }
  });
})();
