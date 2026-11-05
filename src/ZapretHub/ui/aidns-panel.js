'use strict';
// Scoped to AI DNS. Existing navigation and other sections keep their contracts.
(() => {
  let panel=null, draft=null, dirty=false, polling=false, customId=null, cardSignature='',fixture=false;
  const key=s=>`${s.address}|${s.template}|${s.doh?'True':'False'}|${s.fallback?'True':'False'}`;
  const time=s=>s?new Date(s).toLocaleString('ru-RU'):'Не проверялся';
  const tag=(s,cls='')=>`<span class="ai-status ${cls}">${esc(s)}</span>`;
  const entries=()=>panel?.entries||[];
  const results=()=>panel?.probes?.results||[];
  const current=r=>r.network===panel?.probes?.network&&r.network===panel?.network?.generation;
  const rows=e=>results().filter(r=>e.servers.some(s=>key(s)===r.key));
  const title=k=>{ const e=entries().find(e=>e.servers.some(s=>key(s)===k)); return e?.name||'Не выбран'; };
  function mark(){dirty=true;$('#aiDirty').textContent='Есть несохранённые изменения';}
  function controls(){
    if(!draft)return;
    $$('#aiModes button').forEach(b=>b.classList.toggle('on',b.dataset.mode===draft.selectionMode));
    $('#aiManual').classList.toggle('hidden',draft.selectionMode!=='manual');
    const options=entries().flatMap(e=>e.servers.map(s=>`<option value="${esc(e.id+'@'+s.address)}">${esc(e.name+' · '+s.address)}</option>`)).join('');
    $('#aiManual').innerHTML=[['ChatGPT','manualChatgpt','fallbackChatgpt'],['Gemini','manualGemini','fallbackGemini']].map(([name,main,backup])=>`<div><label class="field"><span>${name}: основной DNS</span><select data-ai-setting="${main}">${options}</select></label><label class="field"><span>Явный резерв</span><select data-ai-setting="${backup}"><option value="">Без резерва — не переключаться</option>${options}</select></label></div>`).join('');
    $$('[data-ai-setting]').forEach(s=>{ let v=draft[s.dataset.aiSetting]||''; if(v&&!v.includes('@')){const e=entries().find(e=>e.id===v);v=e?e.id+'@'+e.servers[0].address:'';} s.value=v; });
    $('#aiModeHint').textContent=draft.selectionMode==='auto'?'Независимый выбор для ChatGPT и Gemini. Выбирается первый доступный DNS с успешной HTTPS-проверкой.':'Только выбранный IP. Другой сервер допускается исключительно при явно назначенном резерве.';
    $('#aiDirty').textContent=dirty?'Есть несохранённые изменения':'';
  }
  function draw(){
    if(!panel)return;
    const busy=panel.starting||aiSwitching;
    $('#aiHero').classList.toggle('on',panel.running);
    if(!aiSwitching)$('#aiSwitch').checked=panel.running||panel.starting;
    $('#aiSwitch').disabled=busy;
    $('#aiTitle').textContent=busy?'Проверка маршрутов…':panel.running?(panel.active?.error?'AI DNS включён частично':'AI DNS включён'):panel.cfg.enabled?'AI DNS: служба остановлена':'AI DNS выключен';
    $('#aiSub').textContent=panel.error||panel.active?.error||'Проверка страниц не подтверждает работу чатов. Доступ в браузере НЕ ПРОВЕРЕН.';
    $('#aiServices').innerHTML=tag(panel.cfg.selectionMode==='manual'?'Ручной режим':'Автоматический режим')+' '+tag('Relay: '+(panel.active?.observedQueries||0)+' запросов');
    $('#aiRouteCards').innerHTML=['chatgpt.com','gemini.google.com'].map(host=>{
      const r=panel.active?.routes?.find(r=>r.service===host);
      const proof=results().find(p=>p.key===r?.key&&p.service===host&&current(p));
      const ready=panel.running&&!!r?.address&&!r.error&&proof?.https;
      return `<div class="card ai-route ${ready?'ready':''}"><div class="ai-row"><h3>${host==='chatgpt.com'?'ChatGPT':'Gemini'}</h3>${tag(ready?'DNS + HTTPS проверены':r?.error?'Маршрут недоступен':'Нет активной проверки',r?.error?'fail':ready?'pass':'')}</div><strong>${esc(panel.running&&r?.address?title(r.key):'Не выбран')}</strong><p class="muted xs">${esc(panel.running?r?.address||'':r?.error||'AI DNS выключен')}</p><p class="muted xs mt-sm">${esc(r?.reason||'Ожидает проверки')}<br>Последний успех: ${esc(time(proof?.lastSuccess||r?.lastSuccess))}<br>DoH: ${esc(proof?.httpVersion||'Не проверено')} · HTTPS: ${proof?.https?'проверен':'не подтверждён'}<br>Резерв: ${esc(r?.next||(r?.candidates?.length>1?'Нет готового резерва':'не назначен'))}</p></div>`;
    }).join('');
    const probing=panel.probes?.checking;
    $('#aiProbeAll').disabled=probing||busy;
    $('#aiCancel').disabled=!probing&&!busy;
    $('#aiProgress').textContent=probing?`Проверка ${panel.probes.done} / ${panel.probes.total}`:panel.probes?.total?`Завершено ${panel.probes.done} / ${panel.probes.total}`:'';
    const signature=JSON.stringify([panel.entries,panel.probes,panel.active?.routes?.map(r=>r.address)]);
    if(signature!==cardSignature){cardSignature=signature;$('#aiProviders').innerHTML=entries().map((e,i)=>{
      const rr=rows(e), fresh=rr.filter(current), passed=fresh.filter(r=>r.https);
      const best=passed[0]||fresh.find(r=>r.dns)||fresh[0];
      const err=fresh.find(r=>r.error);
      const dnsLabel=best?.dns?`${best.dnsMs} мс · ${best.fallback?'UDP после ошибки DoH':best.httpVersion?.startsWith('HTTP/')?'DoH TLS пройден':'DNS ответ; TLS не подтверждён'}`:best?.stage||'Не проверено';
      const status=['chatgpt.com','gemini.google.com'].map(h=>{const p=fresh.filter(r=>r.service===h);return `${h==='chatgpt.com'?'ChatGPT':'Gemini'}: ${p.some(r=>r.https)?'DNS + HTTPS':p.some(r=>r.error)?'ошибка':'не проверен'}`;}).join(' · ');
      return `<article class="card ai-provider" data-provider="${esc(e.id)}"><div class="ai-row"><h3><span class="ai-number">${String(i+1).padStart(2,'0')}</span>${esc(e.name)}</h3>${tag(passed.length?'HTTPS проверен':err?'Ошибка':'Не проверено',passed.length?'pass':err?'fail':'')}</div><div class="ai-endpoint">${esc(e.servers.map(s=>s.address).join(' · '))}<br>${esc(e.servers[0].template||'Обычный DNS')}</div><dl class="ai-metrics"><div><dt>СЕРВИСЫ</dt><dd>${esc(status)}</dd></div><div><dt>ТРАНСПОРТ</dt><dd>${esc(best?.httpVersion||'HTTP/2 предпочитается; не проверено')}</dd></div><div><dt>DNS / TLS</dt><dd>${esc(dnsLabel)}</dd></div><div><dt>HTTPS К ПОЛУЧЕННОМУ IP</dt><dd>${passed.length?'Проверен IPv4; чат не проверен':'Не подтверждён'}</dd></div><div><dt>SMART DNS</dt><dd>${esc(best?.smart||'Не установлено')}</dd></div><div><dt>UDP FALLBACK</dt><dd>${rr.some(r=>r.fallback)?'Использовался':e.servers.some(s=>s.fallback)?'Разрешён настройкой':'Запрещён'}</dd></div></dl>${err?`<p class="ai-provider-error">${esc(err.service+' · '+err.stage+' · '+err.target+' · '+err.error)}</p>`:''}<footer><span>${esc(time(best?.checkedAt))}${rr.length&&!fresh.length?' · сеть изменилась':''}</span><div class="ai-row">${e.custom?`<button class="btn sm" data-act="ai-custom-edit" data-id="${esc(e.id)}">Изменить</button>`:''}<button class="btn sm" data-act="ai-probe-one" data-id="${esc(e.id)}" ${probing||busy?'disabled':''}>Проверить</button></div></footer></article>`;
    }).join('');}
    const net=panel.network;
    $('#aiNetwork').innerHTML=`<div class="notice">${icon('info')}<span>${esc(panel.engine?.running?'Основной обход активен: '+panel.engine.strategy+'. Влияние фильтра на TLS не установлено.':'Основной обход выключен.')} ${net?.interfaces?.some(n=>n.tunnel)?'Есть активный интерфейс с признаками VPN.':'Активный VPN по имени интерфейса не обнаружен; это не доказательство его отсутствия.'}</span></div>`+(net?.routes||[]).map(r=>`<div class="ai-diag-item">${esc(r.destination)} → ${esc(r.adapter||'#'+r.index)} · ${esc(r.source)} → шлюз ${esc(r.gateway)}${r.tunnel?' · ТУННЕЛЬ':''}</div>`).join('')+`<p class="muted xs">${esc(net?.note||'Маршрут не получен')}</p>`;
    $('#aiDiagnosticRows').innerHTML=results().map(r=>`<div class="ai-diag-item">${esc(r.address)} · ${esc(r.service)} · ${esc(r.stage)}${!current(r)?' · УСТАРЕЛО ПОСЛЕ СМЕНЫ СЕТИ':''}<br>A: ${esc(r.ipv4.join(', ')||'нет')}<br>AAAA: ${esc(r.ipv6.join(', ')||r.ipv6Status||'нет / не проверено')}<br>Транспорт: ${esc(r.dnsTransport||'не проверен')} · TCP-источник DNS: ${esc(r.dnsSource||'не измерен / соединение из пула')} · HTTPS: ${esc(r.httpsSource||'не измерен')}<br>HTTP: ${esc(r.httpStatus||'—')} · ${esc(r.accessState||'')}<br>${esc(r.target)} ${esc(r.error)}</div>`).join('')||'<p class="muted xs">Нажмите «Проверить все DNS», чтобы получить этапы и A/AAAA.</p>';
    $('#aiEvents').innerHTML='<h3>Переключения</h3>'+(panel.active?.events||[]).map(e=>`<div class="ai-diag-item">${esc(time(e.utc))} · ${esc(e.service)} → ${esc(e.address)}<br>${esc(e.reason)}</div>`).join('');
  }
  async function pull(reset=false){
    if(polling||fixture)return;polling=true;
    try{const r=await call('aidns_panel');if(!r.ok)return;panel=r;if(!draft||reset){draft=structuredClone(r.cfg);dirty=false;controls();}draw();}finally{polling=false;}
  }
  renderAiDns=()=>{if(!panel){if(S){$('#aiSwitch').checked=!!S.aidns.enabled;$('#aiSwitch').disabled=aiSwitching;}}else draw();};
  loadAiDns=()=>pull(!dirty);
  aiSave=async()=>{if(!draft)return {ok:true};const r=await call('aidns_panel_save',draft);if(r.ok){dirty=false;await pull(true);}return r;};
  actions['ai-mode']=btn=>{if(!draft)return;draft.selectionMode=btn.dataset.mode;mark();controls();};
  actions['ai-save']=async btn=>{const r=await withLoading(btn,aiSave);if(r.ok){toast('Назначения сохранены','ok');await refresh();}};
  actions['ai-probe-all']=async()=>{await call('aidns_probe','');await pull();};
  actions['ai-probe-one']=async btn=>{await call('aidns_probe',btn.dataset.id);await pull();};
  actions['ai-cancel']=async()=>{await call('aidns_cancel');await pull();};
  function custom(e=null){customId=e?.id||null;$('#aiCustom').classList.remove('hidden');$('#aiCustomName').value=e?.name||'';$('#aiCustomIp').value=e?.servers[0].address||'';$('#aiCustomUrl').value=e?.servers[0].template||'';$('#aiCustomUdp').checked=!!e?.servers[0].fallback;$('#aiCustomName').focus();}
  actions['ai-custom-new']=()=>custom();
  actions['ai-custom-edit']=btn=>custom(entries().find(e=>e.id===btn.dataset.id));
  actions['ai-custom-close']=()=>$('#aiCustom').classList.add('hidden');
  actions['ai-custom-store']=async()=>{
    if(!draft)return;const name=$('#aiCustomName').value.trim(),ip=$('#aiCustomIp').value.trim(),url=$('#aiCustomUrl').value.trim();
    if(!name||!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)||ip.split('.').some(v=>+v>255)||!url.startsWith('https://'))return toast('Введите название, IPv4 и полный HTTPS URL','err');
    const id=customId||'custom-'+crypto.randomUUID();const entry={id,name,custom:true,servers:[{address:ip,template:url,doh:true,fallback:$('#aiCustomUdp').checked}]};
    const before=structuredClone(draft);draft.customServers=draft.customServers.filter(e=>e.id!==id).concat(entry);
    for(const k of ['manualChatgpt','manualGemini','fallbackChatgpt','fallbackGemini'])if(draft[k]?.split('@')[0]===id)draft[k]=id+'@'+ip;
    mark();
    const r=await aiSave();if(r.ok){$('#aiCustom').classList.add('hidden');toast('Запись DNS сохранена','ok');}else draft=before;
  };
  actions['ai-report']=async()=>{const r=await call('aidns_report');if(!r.ok)return;const b=new Blob([JSON.stringify(r.report,null,2)],{type:'application/json'});const u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='ZapretHub-SmartDNS-'+Date.now()+'.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000);toast('Обезличенный отчёт подготовлен','info');};
  document.addEventListener('change',e=>{if(e.target.dataset.aiSetting&&draft){draft[e.target.dataset.aiSetting]=e.target.value;mark();}});
  setInterval(()=>{if(page==='aidns'&&S)pull();},1800);
  // Used only by the isolated screenshot harness, never activates DNS.
  if(window.__debug)window.aiPanelTest={set(value){fixture=true;panel=value;draft=structuredClone(value.cfg);dirty=false;cardSignature='';controls();draw();},get(){return {panel,draft,dirty};}};
})();
