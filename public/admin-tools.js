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
    .jackal-admin-row-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:10px}
    .jackal-admin-inline{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(178,102,255,.55);border-radius:3px;color:#fff;background:rgba(78,24,174,.72);font:800 12px 'Saira Condensed',sans-serif;text-transform:uppercase;cursor:pointer}
    .jackal-admin-row-actions .jackal-admin-inline{margin-left:0}
    .jackal-login-overlay{background:rgba(4,3,10,.12)!important;backdrop-filter:blur(9px)!important;-webkit-backdrop-filter:blur(9px)!important}
    .jackal-login-modal{background:rgba(17,14,31,.92)!important;box-shadow:0 24px 90px rgba(0,0,0,.38),0 0 30px rgba(168,85,255,.16)!important}
    @media(max-width:960px){.jackal-admin-auth-actions{gap:5px}.jackal-admin-auth-btn{height:34px;padding:0 10px;font-size:12px}}
    @media(max-width:700px){.jackal-admin-auth-actions{gap:4px}.jackal-admin-auth-btn{padding:0 8px;font-size:11px}.jackal-admin-auth-btn svg{width:14px;height:14px}}
  `;

  const style=document.createElement('style');
  style.id='jackalAdminToolsStyle';
  style.textContent=STYLE;
  document.head.appendChild(style);

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

  async function getAuth(){
    try{
      const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
      if(!r.ok) return null;
      const d=await r.json().catch(()=>null);
      return d?.ok?d:null;
    }catch(_){return null;}
  }

  function can(auth,resource,action){
    return !!auth && (auth.is_superadmin || Number(auth.permissions?.[resource]?.[`can_${action}`]||0)===1);
  }

  function addButton(container,label,params,opts={}){
    if(!container || container.querySelector(`.jackal-admin-edit[data-action-key="${CSS.escape(opts.key||params)}"]`)) return;
    const button=document.createElement('button');
    button.type='button';button.className='jackal-admin-edit';button.dataset.actionKey=opts.key||params;button.textContent=label;
    button.addEventListener('click',()=>openEditor(params));
    container.appendChild(button);
  }

  async function openEditor(params){
    // Never open the admin iframe unless the parent page currently has a valid session.
    const auth=await getAuth();
    if(!auth){ setAuthUi(null); return; }
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
    getAuth().then(auth=>{
      if(!auth){setAuthUi(null);return;}
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
    const head=card?.querySelector('.head,.card-head,.card-header');
    if(head)addButton(head,label,params,{key});
  }

  function setupIndex(auth){
    if(!auth) return;
    const next=document.querySelector('.next-race');
    if(next && can(auth,'races','edit') && can(auth,'news','edit')) addHeadButton(next,'Nächstes Event anpassen','embed=special&special=next-event','home-next');
    const news=document.querySelector('section.card.news');
    if(news && can(auth,'news','create')) addHeadButton(news,'Neue News','embed=crud&resource=news&action=new','home-news');
    const hearts=document.querySelector('.hearts');
    if(hearts && can(auth,'news','edit')) addHeadButton(hearts,'Sieger & Abstimmung','embed=special&special=hearts-poll','home-hearts');
    const laps=document.querySelector('.laps');
    if(laps && can(auth,'results','create')) addHeadButton(laps,'Rundenzeiten verwalten','embed=crud&resource=results&action=new','home-laps');
    const champion=document.querySelector('.champion');
    if(champion && can(auth,'drivers','create')) addHeadButton(champion,'Fahrer hinzufügen','embed=crud&resource=drivers&action=new','home-champion');
  }

  function setupNews(auth){
    if(!auth) return;
    const best=document.querySelector('.bestlist');
    if(best && can(auth,'results','create')) addHeadButton(best,'Ergebnisse verwalten','embed=crud&resource=results&action=new','news-best');
    const race=document.querySelector('.race-card');
    if(race && can(auth,'races','edit') && can(auth,'news','edit')) addHeadButton(race,'Event anpassen','embed=special&special=next-event','news-race');
    const hearts=document.querySelector('.hearts');
    if(hearts && can(auth,'news','edit')){
      const head=hearts.querySelector('.card-head');
      if(head) addButton(head,'Sieger & Abstimmung','embed=special&special=hearts-poll',{key:'news-hearts'});
    }
    const laps=document.querySelector('.laps');
    if(laps && can(auth,'results','create')) addHeadButton(laps,'Rundenzeiten verwalten','embed=crud&resource=results&action=new','news-laps');
    document.querySelectorAll('.news-read-link[data-news-id]').forEach((link,idx)=>{
      const id=link.dataset.newsId;
      if(!id||!can(auth,'news','edit')||link.parentElement.querySelector(`.jackal-admin-inline[data-news-edit="${CSS.escape(id)}"]`)) return;
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.newsEdit=id;b.textContent='News bearbeiten';b.addEventListener('click',()=>openEditor(`embed=crud&resource=news&action=edit&id=${encodeURIComponent(id)}`));
      row.appendChild(b);link.parentElement.appendChild(row);
    });
  }

  function setupDrivers(auth){
    if(!auth) return;
    const card=document.querySelector('main .card');
    if(card && can(auth,'drivers','create')) addHeadButton(card,'+ Fahrer','embed=crud&resource=drivers&action=new','drivers-new');
    document.querySelectorAll('.driver[data-driver-id]').forEach(el=>{
      const id=el.dataset.driverId;
      if(id && can(auth,'drivers','edit')){
        const actions=el.querySelector('.jackal-admin-row-actions')||document.createElement('div');
        actions.className='jackal-admin-row-actions';
        if(!actions.querySelector('button')){const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.textContent='Bearbeiten';b.addEventListener('click',()=>openEditor(`embed=crud&resource=drivers&action=edit&id=${encodeURIComponent(id)}`));actions.appendChild(b);el.appendChild(actions);}
      }
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
    if(toolbar && can(auth,'races','create') && !toolbar.querySelector('.jackal-admin-edit[data-action-key="races-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='races-new';b.textContent='+ Neues Rennen';b.addEventListener('click',()=>openEditor('embed=crud&resource=races&action=new'));toolbar.appendChild(row);row.appendChild(b);
    }
    document.querySelectorAll('.race[data-race-id]').forEach(el=>{
      const id=el.dataset.raceId;
      if(!id||!can(auth,'races','edit')) return;
      const body=el.querySelector('.race-body')||el;
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.textContent='Rennen bearbeiten';b.addEventListener('click',()=>openEditor(`embed=crud&resource=races&action=edit&id=${encodeURIComponent(id)}`));row.appendChild(b);
      body.appendChild(row);
    });
  }

  function setupBlacklist(auth){
    if(!auth) return;
    const toolbar=document.querySelector('main .toolbar');
    if(toolbar && can(auth,'blacklist','create') && !toolbar.querySelector('.jackal-admin-edit[data-action-key="blacklist-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='blacklist-new';b.textContent='+ Fahrzeug';b.addEventListener('click',()=>openEditor('embed=crud&resource=blacklist&action=new'));toolbar.appendChild(row);row.appendChild(b);
    }
    document.querySelectorAll('.item[data-blacklist-id]').forEach(el=>{
      const id=el.dataset.blacklistId;
      if(!id||!can(auth,'blacklist','edit')) return;
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.textContent='Bearbeiten';b.addEventListener('click',()=>openEditor(`embed=crud&resource=blacklist&action=edit&id=${encodeURIComponent(id)}`));row.appendChild(b);el.querySelector('.body')?.appendChild(row);
    });
  }

  function setupGallery(auth){
    if(!auth) return;
    const toolbar=document.querySelector('main .toolbar');
    if(toolbar && can(auth,'gallery','create') && !toolbar.querySelector('.jackal-admin-edit[data-action-key="gallery-new"]')){
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.dataset.actionKey='gallery-new';b.textContent='+ Foto';b.addEventListener('click',()=>openEditor('embed=crud&resource=gallery&action=new'));toolbar.appendChild(row);row.appendChild(b);
    }
    document.querySelectorAll('.tile[data-gallery-id]').forEach(el=>{
      const id=el.dataset.galleryId;
      if(!id||!can(auth,'gallery','edit')) return;
      const row=document.createElement('div');row.className='jackal-admin-row-actions';
      const b=document.createElement('button');b.type='button';b.className='jackal-admin-inline';b.textContent='Bearbeiten';b.addEventListener('click',()=>openEditor(`embed=crud&resource=gallery&action=edit&id=${encodeURIComponent(id)}`));row.appendChild(b);el.querySelector('.caption')?.appendChild(row);
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
        const auth=await getAuth();
        setAuthUi(auth);
        init(auth);
      }catch(_){if(message)message.textContent='Der Login-Server ist momentan nicht erreichbar.';}
    });
  }

  window.addEventListener('message',event=>{
    if(event.origin!==location.origin)return;
    if(event.data?.type==='jackal-admin-saved'){closeEditor();setTimeout(()=>location.reload(),120);}
    if(event.data?.type==='jackal-admin-close')closeEditor();
    if(event.data?.type==='jackal-admin-auth-required'){closeEditor();setAuthUi(null);setTimeout(openLogin,50);}
  });

  document.addEventListener('DOMContentLoaded',async()=>{
    ensureAuthControls();
    wireLoginModal();
    ensureOverlay();
    const auth=await getAuth();
    init(auth);
    if(auth){const observer=new MutationObserver(()=>init(auth));observer.observe(document.body,{childList:true,subtree:true});setTimeout(()=>observer.disconnect(),5000);}
  });
})();
