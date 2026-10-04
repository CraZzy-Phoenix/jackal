(function(){
  'use strict';

  const EDIT_STYLE = `
    .jackal-admin-edit{display:inline-flex;align-items:center;justify-content:center;gap:7px;margin-left:auto;padding:7px 11px;border:1px solid rgba(178,102,255,.65);border-radius:3px;color:#fff;background:linear-gradient(180deg,#5c22c4,#4e18ae 60%,#43149a);box-shadow:0 0 12px rgba(168,85,255,.24);font:800 13px 'Saira Condensed',sans-serif;letter-spacing:.05em;text-transform:uppercase;cursor:pointer;white-space:nowrap}
    .jackal-admin-edit:hover{filter:brightness(1.12);box-shadow:0 0 18px rgba(178,102,255,.42)}
    .jackal-admin-row-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:10px}
    .jackal-admin-inline{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border:1px solid rgba(178,102,255,.55);border-radius:3px;color:#fff;background:rgba(78,24,174,.72);font:800 12px 'Saira Condensed',sans-serif;text-transform:uppercase;cursor:pointer}
    .jackal-admin-row-actions .jackal-admin-inline{margin-left:0}
    @media(max-width:700px){.jackal-admin-edit{padding:6px 9px;font-size:12px}.jackal-admin-row-actions{gap:5px}}
  `;

  const style = document.createElement('style');
  style.id = 'jackalAdminToolsStyle';
  style.textContent = EDIT_STYLE;
  document.head.appendChild(style);

  function esc(v){
    return String(v ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  }

  function addButton(container, label, params, opts={}){
    if(!container || container.querySelector(`.jackal-admin-edit[data-action-key="${CSS.escape(opts.key||params)}"]`)) return;
    const button = document.createElement('button');
    button.type='button';
    button.className='jackal-admin-edit';
    button.dataset.actionKey = opts.key || params;
    button.textContent = label;
    button.addEventListener('click', ()=>openEditor(params));
    container.appendChild(button);
  }

  function openEditor(params){
    const url = '/admin?' + params;
    const overlay = document.getElementById('jackalAdminEditOverlay');
    const frame = document.getElementById('jackalAdminEditFrame');
    if(!overlay || !frame) return;
    frame.src = url;
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden','false');
    document.body.classList.add('jackal-admin-edit-open');
  }

  function closeEditor(){
    const overlay=document.getElementById('jackalAdminEditOverlay');
    const frame=document.getElementById('jackalAdminEditFrame');
    if(!overlay) return;
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden','true');
    if(frame) frame.src='about:blank';
    document.body.classList.remove('jackal-admin-edit-open');
  }

  function ensureOverlay(){
    if(document.getElementById('jackalAdminEditOverlay')) return;
    const wrap=document.createElement('div');
    wrap.innerHTML=`<div class="jackal-admin-edit-overlay" id="jackalAdminEditOverlay" aria-hidden="true"><div class="jackal-admin-edit-window" role="dialog" aria-modal="true" aria-label="JACKAL bearbeiten"><button class="jackal-admin-edit-close" type="button" id="jackalAdminEditClose" aria-label="Fenster schließen">×</button><iframe id="jackalAdminEditFrame" title="JACKAL Bearbeitung" src="about:blank"></iframe></div></div>`;
    document.body.appendChild(wrap.firstElementChild);
    const style=document.createElement('style');
    style.textContent=`
      .jackal-admin-edit-overlay{position:fixed;inset:0;z-index:7000;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(4,3,10,.68);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px)}
      .jackal-admin-edit-overlay.open{display:flex}
      .jackal-admin-edit-window{position:relative;width:min(920px,96vw);height:min(760px,92vh);border:1px solid #4b2f8a;border-radius:10px;overflow:hidden;background:#0d0a16;box-shadow:0 30px 100px rgba(0,0,0,.72),0 0 38px rgba(168,85,255,.18)}
      .jackal-admin-edit-window iframe{width:100%;height:100%;display:block;border:0;background:#0d0a16}
      .jackal-admin-edit-close{position:absolute;top:9px;right:9px;z-index:5;width:34px;height:34px;border:1px solid #4b2f8a;border-radius:3px;color:#ddd5eb;background:#0f0c18;font:700 19px 'Saira Condensed',sans-serif;cursor:pointer}
      .jackal-admin-edit-close:hover{color:#fff;border-color:#b266ff;box-shadow:0 0 12px rgba(168,85,255,.28)}
    `;
    document.head.appendChild(style);
    document.getElementById('jackalAdminEditClose')?.addEventListener('click',closeEditor);
    document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.getElementById('jackalAdminEditOverlay')?.classList.contains('open'))closeEditor();});
  }

  function addHeadButton(card, label, params, key){
    const head=card?.querySelector('.head,.card-head,.card-header');
    if(head) addButton(head,label,params,{key});
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
    const path=location.pathname.replace(/\/$/,'')||'/';
    if(path==='/'||path==='/index.html') setupIndex(auth);
    else if(path==='/news') setupNews(auth);
    else if(path==='/drivers') setupDrivers(auth);
    else if(path==='/rangliste') setupRanking(auth);
    else if(path==='/races') setupRaces(auth);
    else if(path==='/blacklist') setupBlacklist(auth);
    else if(path==='/gallery') setupGallery(auth);
  }

  window.addEventListener('message',event=>{
    if(event.origin!==location.origin) return;
    if(event.data?.type==='jackal-admin-saved'){
      closeEditor();
      setTimeout(()=>location.reload(),120);
    }
    if(event.data?.type==='jackal-admin-close') closeEditor();
  });

  document.addEventListener('DOMContentLoaded', async()=>{
    const auth=await getAuth();
    init(auth);
    // Public pages render their dynamic cards after this script in some cases.
    // A small observer adds row-level controls once those cards appear.
    if(auth){
      const observer=new MutationObserver(()=>init(auth));
      observer.observe(document.body,{childList:true,subtree:true});
      setTimeout(()=>observer.disconnect(),5000);
    }
  });
})();
