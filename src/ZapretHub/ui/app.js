'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const GROUP_COLORS = { Discord: '#8b9cff', YouTube: '#ff5a6e', Google: '#4fd1ff', Cloudflare: '#ffb547' };
const groupColor = g => GROUP_COLORS[g] || '#a78bfa';

const LIST_HINTS = {
  general: ['Сайты, которые нужно пропускать через обход в дополнение к встроенному списку. Поддомены подхватываются автоматически.', 'example.com'],
  exclude: ['Сайты, которые обход не должен трогать никогда — например, банки или госуслуги, если с ними начались проблемы.', 'bank.example'],
  ipset_exclude: ['IP-адреса и подсети, которые нужно исключить из обхода (для режима IPSet).', '192.168.0.0/16'],
};
const IPSET_DESC = {
  none: 'Обход работает только по спискам доменов. Рекомендуемый режим — без лишних побочных эффектов.',
  loaded: 'Дополнительно обрабатывается трафик к IP-адресам из списка (Cloudflare, игровые серверы и т. п.).',
  any: 'Обрабатываются все IP-адреса. Включайте только для проверки — может ломать часть сайтов.',
};

let S = null;               // состояние из Python
let page = 'home';
let testMode = 'quick';
let listKey = 'general';
let updCheckError = null;  // последняя ошибка проверки обновлений (например, источник недоступен)
let qc = null;             // результат «Проверить доступность»
let qcRunning = false;
let switching = false;
let onboarding = null;      // null | 'download' | 'test' | 'done'
let tgSwitching = false;    // идёт включение/установка Telegram-прокси

// ---------- связь с Python ----------
async function call(method, ...args) {
  try {
    const r = await window.pywebview.api[method](...args);
    if (r && r.ok === false) toast(r.error || 'Что-то пошло не так', 'err');
    return r || { ok: false };
  } catch (e) {
    toast(String(e), 'err');
    return { ok: false };
  }
}

window.hub = {
  onEvent(kind, data) {
    if (kind === 'toast') toast(data.msg, data.kind);
    else if (kind === 'state') refresh();
    else if (kind === 'update') {
      if (S) { S.update = data; renderUpdates(); renderChrome(); renderTelegram(); }
      if (data.component !== 'tg') onboardUpdate(data);
      if (['done', 'error'].includes(data.stage)) { tgSwitching = false; refresh(); }
    }
    else if (kind === 'test') { if (S) { S.test = data; applyTestScores(data); renderTest(); renderStrategies(); renderChrome(); renderHome(); } onboardTest(data); }
  },
};

// ---------- утилиты отображения ----------
function pretty(name) {
  if (!name) return '—';
  if (name.toLowerCase() === 'general') return 'General';
  const m = name.match(/^general\s*\((.+)\)$/i);
  return m ? m[1].replace(/ALT(\d+)/g, 'ALT $1') : name;
}
const pct = sc => (sc && sc.total ? Math.round((sc.ok * 100) / sc.total) : null);
const tone = p => (p == null ? 'none' : p >= 90 ? 'good' : p >= 50 ? 'mid' : 'bad');
const toneColor = p => ({ good: '#34f5c5', mid: '#fbbf24', bad: '#fb5a7a', none: '#5b6183' }[tone(p)]);

function ring(p) {
  const r = 19, c = 2 * Math.PI * r, off = p == null ? c : c * (1 - p / 100);
  return `<div class="ring"><svg viewBox="0 0 46 46"><circle class="bg" cx="23" cy="23" r="${r}"/>
    <circle class="fg" cx="23" cy="23" r="${r}" stroke="${toneColor(p)}" stroke-dasharray="${c}" stroke-dashoffset="${off}"/></svg>
    <em style="color:${p == null ? 'var(--dim)' : toneColor(p)}">${p == null ? '—' : p}</em></div>`;
}

function toast(msg, kind = 'info') {
  // Одинаковое сообщение, уже висящее на экране, повторно не показываем.
  for (const t of $('#toasts').children) if (t.className === `toast ${kind}` && t.textContent === msg) return;
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `${icon(kind === 'err' ? 'alert' : kind === 'ok' ? 'check' : 'info')}<span>${esc(msg)}</span>`;
  $('#toasts').append(el);
  setTimeout(() => el.classList.add('out'), kind === 'err' ? 6500 : 4200);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 4700);
}

function confirmBox(text) {
  return new Promise(resolve => {
    $('#confirmText').textContent = text;
    $('#confirm').classList.remove('hidden');
    $('#confirm').onclick = e => {
      const b = e.target.closest('[data-confirm-answer]');
      if (!b && e.target !== $('#confirm')) return;
      $('#confirm').classList.add('hidden');
      resolve(b?.dataset.confirmAnswer === '1');
    };
  });
}

async function withLoading(btn, fn) {
  btn?.classList.add('loading');
  if (btn) btn.disabled = true;
  try { return await fn(); } finally { btn?.classList.remove('loading'); if (btn) btn.disabled = false; }
}

// ---------- обновление состояния ----------
async function refresh() {
  const r = await call('get_state');
  if (!r.ok) return;
  S = r;
  renderChrome();
  renderHome();
  renderStrategies();
  renderTest();
  renderUpdates();
  renderSettings();
  renderTelegram();
  renderAiDns();
  if (!S.installed && !onboarding) $('#onboard').classList.remove('hidden');
}

function renderChrome() {
  const st = S.status, busy = S.busy || switching;
  document.body.classList.toggle('on', st.running);
  const pill = $('#tbPill');
  pill.className = 'tb-pill pywebview-drag-region' + (busy ? ' busy' : st.running ? ' on' : '');
  $('#tbText').textContent = S.busy === 'test' ? 'Подбор стратегии…' : S.busy === 'update' ? 'Обновление…'
    : switching ? 'Переключение…' : st.running ? `Активен · ${st.external ? 'внешний winws' : pretty(st.strategy)}` : 'Обход выключен';
  $('#sideVer').textContent = S.engine_version || '—';
  const newer = (S.latest && S.engine_version && verNewer(S.latest.version, S.engine_version))
    || (S.tg.latest && S.tg.version && verNewer(S.tg.latest.version, S.tg.version));
  $('#updBadge').classList.toggle('hidden', !newer);
  $('#tgDot').classList.toggle('hidden', !S.tg.running);
  $('#aiDot').classList.toggle('hidden', !S.aidns.enabled);
  $('#appVer').textContent = S.app_version;
}

function verNewer(a, b) {
  const pa = String(a).match(/\d+/g)?.map(Number) || [], pb = String(b).match(/\d+/g)?.map(Number) || [];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return false;
}

function renderHome() {
  const st = S.status, busy = switching || S.busy === 'test' || S.busy === 'update';
  const orb = $('#orb');
  orb.className = 'orb' + (busy ? ' busy' : st.running ? ' on' : '');
  let title = st.running ? 'Обход активен' : 'Обход выключен';
  let sub = st.running
    ? (st.external ? 'Работает winws.exe, запущенный не из Zapret Hub' : `${pretty(st.strategy)} · ${st.mode === 'service' ? 'служба Windows' : 'через приложение'}`)
    : 'Нажмите на кнопку, чтобы включить';
  if (switching) { title = st.running ? 'Выключаю…' : 'Включаю…'; sub = 'Это займёт пару секунд'; }
  if (S.busy === 'test') { title = 'Идёт подбор…'; sub = S.test?.current ? `Проверяю ${pretty(S.test.current)}` : 'Подготовка'; }
  if (S.busy === 'update') { title = 'Обновляю zapret…'; sub = 'Обход перезапустится автоматически'; }
  $('#stateTitle').textContent = title;
  $('#stateSub').textContent = sub;
  $('#modeChip').textContent = S.options.run_mode === 'service' ? 'Служба Windows' : 'Через приложение';

  const cur = S.strategies.find(s => s.name === S.strategy);
  $('#pickerValue').textContent = pretty(S.strategy);
  const p = pct(cur?.score);
  const pill = $('#pickerScore');
  pill.classList.toggle('hidden', p == null);
  pill.className = `score-pill ${tone(p)}` + (p == null ? ' hidden' : '');
  pill.textContent = p == null ? '' : `${p}%`;
  renderPickerMenu();
  renderServices();

  const gf = S.game_filter.mode;
  const tiles = [
    ['telegram', 'send', '#37bbfe', 'Telegram', S.tg.running ? 'Работает' : 'Выкл'],
    ['aidns', 'bot', '#e879f9', 'AI DNS', S.aidns.enabled ? 'Включён' : 'Выкл'],
    ['filters', 'gamepad', '#f472b6', 'Game Filter', { disabled: 'Выкл', all: 'TCP + UDP', tcp: 'TCP', udp: 'UDP' }[gf]],
    ['filters', 'globe', '#22d3ee', 'IPSet', { none: 'Выкл', loaded: 'По списку', any: 'Все IP' }[S.ipset]],
  ];
  $('#quickTiles').innerHTML = tiles.map(([pg, ic, c, l, v]) =>
    `<button class="qt" data-go="${pg}"><span class="ttl-ic" style="--c:${c}">${icon(ic)}</span><span><small>${l}</small><b>${esc(v)}</b></span></button>`).join('');

  const newer = S.latest && verNewer(S.latest.version, S.engine_version);
  $('#updMini').innerHTML = `<span class="ttl-ic" style="--c:${newer ? '#a78bfa' : '#34f5c5'}">${icon(newer ? 'download' : 'check')}</span>
    <div class="txt"><b>zapret ${esc(S.engine_version || '—')}</b><span>${newer ? `Доступна версия ${esc(S.latest.version)}` : S.latest ? 'Установлена последняя версия' : (S.options.auto_update ? 'Автообновление включено' : 'Автообновление выключено')}</span></div>
    ${newer ? '<button class="btn sm primary" data-act="upd-install">Обновить</button>' : '<button class="btn sm" data-go="updates">Подробнее</button>'}`;
}

function renderPickerMenu() {
  $('#pickerMenu').innerHTML = S.strategies.map(s => {
    const p = pct(s.score);
    return `<button class="pm-item ${s.name === S.strategy ? 'sel' : ''}" data-pick="${esc(s.name)}">
      <span class="nm">${esc(pretty(s.name))}</span>${p == null ? '<span class="sub">не тестировалась</span>' : `<span class="score-pill ${tone(p)}">${p}%</span>`}</button>`;
  }).join('');
}

function renderServices() {
  const groups = S.groups;
  $('#svcList').innerHTML = groups.map(g => {
    const r = qc?.groups?.[g];
    const p = pct(r);
    let st = '<span class="svc-st st-none">Не проверено</span>';
    if (qcRunning) st = '<span class="svc-st st-wait">Проверяю…</span>';
    else if (r) st = `<span class="svc-st st-${{ good: 'ok', mid: 'mid', bad: 'bad' }[tone(p)]}">${p >= 90 ? 'Доступен' : p >= 50 ? 'Частично' : 'Недоступен'}</span>`;
    return `<div class="svc"><span class="svc-ic" style="--c:${groupColor(g)}">${esc(g[0])}</span>
      <div class="svc-mid"><b>${esc(g)}</b><div class="mini"><span style="width:${p ?? 0}%;background:${toneColor(p)}"></span></div></div>${st}</div>`;
  }).join('');
}

// ---------- стратегии и автоподбор ----------
function applyTestScores(t) {
  for (const r of t.results || []) {
    const s = S.strategies.find(x => x.name === r.name);
    if (s) s.score = { ok: r.ok, total: r.total, ms: r.ms };
  }
}

function renderStrategies() {
  const sel = S.test_groups || [];
  $('#groupChips').innerHTML = S.groups.map(g =>
    `<button class="chip ${sel.includes(g) ? 'on' : ''}" style="--c:${groupColor(g)}" data-group="${esc(g)}"><i></i>${esc(g)}</button>`).join('');
  const t = S.test || {};
  const best = t.best;
  $('#stratCount').textContent = `${S.strategies.length} шт.`;
  $('#stratGrid').innerHTML = S.strategies.map((s, i) => {
    const p = pct(s.score);
    const active = S.status.running && S.status.strategy === s.name;
    const testing = t.running && t.current === s.name;
    const meta = s.score ? (s.score.total ? `${s.score.ok}/${s.score.total} проверок${s.score.ms ? ` · ${s.score.ms} мс` : ''}` : 'не запустилась') : 'не тестировалась';
    return `<div class="strat ${active ? 'active' : ''} ${testing ? 'testing' : ''}" style="animation-delay:${Math.min(i * 18, 300)}ms">
      ${best === s.name && !t.running ? `<span class="badge best">${icon('star')}Лучшая</span>` : ''}
      <div class="strat-top"><div><b>${esc(pretty(s.name))}</b><span>${esc(s.name)}.bat</span></div>${ring(p)}</div>
      <div class="strat-foot"><span class="muted">${testing ? 'проверяется…' : meta}</span>
      ${active ? `<span class="badge on">${icon('check')}Активна</span>` : `<button class="btn sm" data-apply="${esc(s.name)}" ${S.busy ? 'disabled' : ''}>Включить</button>`}</div></div>`;
  }).join('');
  // анимация появления только при первом показе
  $$('.strat', $('#stratGrid')).forEach(el => { if (renderStrategies.done) el.style.animation = 'none'; });
  renderStrategies.done = true;
}

function renderTest() {
  const t = S.test || {};
  const running = S.busy === 'test';
  const btn = $('#testBtn');
  btn.innerHTML = running ? `${icon('stop')}Остановить` : `${icon('sparkles')}Запустить подбор`;
  btn.classList.toggle('danger', running);
  btn.classList.toggle('primary', !running);
  btn.dataset.act = running ? 'test-cancel' : 'test-start';
  const live = $('#testLive');
  live.classList.toggle('hidden', !t.phase);
  if (!t.phase) return;
  const done = (t.results || []).length;
  const total = t.total || 1;
  let now = 'Подготовка…';
  if (t.phase === 'baseline') now = 'Проверяю, что открывается без обхода…';
  else if (t.phase === 'testing') now = `Тестирую ${pretty(t.current)}`;
  else if (t.phase === 'done') now = t.best ? `Готово — лучшая стратегия: ${pretty(t.best)}` : 'Готово — подходящей стратегии не нашлось';
  else if (t.phase === 'cancelled') now = 'Подбор остановлен';
  else if (t.phase === 'error') now = `Ошибка: ${t.error || ''}`;
  $('#testNow').textContent = now;
  $('#testCount').textContent = `${done} / ${total}`;
  $('#testBar').style.width = `${t.running ? Math.max(4, (done / total) * 100) : 100}%`;
  const base = t.baseline;
  const bestRes = (t.results || []).find(r => r.name === t.best);
  $('#testBase').innerHTML = (base ? `<span>Без обхода: <b>${base.ok}/${base.total}</b></span>` : '')
    + (bestRes ? `<span>С лучшей стратегией: <b>${bestRes.ok}/${bestRes.total}</b>${bestRes.ms ? ` · ${bestRes.ms} мс` : ''}</span>` : '');
}

// ---------- фильтры ----------
async function loadFilters() {
  const r = await call('get_filters');
  if (!r.ok) return;
  setSeg('#gfMode', r.game_filter.mode);
  $('#gfTcp').value = r.game_filter.tcp;
  $('#gfUdp').value = r.game_filter.udp;
  setSeg('#ipsetMode', r.ipset);
  $('#ipsetDesc').textContent = IPSET_DESC[r.ipset];
  $('#ipsetInfo').textContent = r.ipset_count ? `В списке ${r.ipset_count.toLocaleString('ru')} подсетей` : 'Список IP ещё не загружен';
  for (const [sel, kind] of [['#fakeDiscord', 'discord'], ['#fakeGame', 'game']]) {
    const cur = r.fakes[kind];
    $(sel).innerHTML = (cur ? '' : '<option value="">(свой файл)</option>')
      + (r.fakes.files || []).map(f => `<option value="${esc(f)}" ${f === cur ? 'selected' : ''}>${esc(f)}</option>`).join('');
  }
}

const setSeg = (sel, val) => $$(`${sel} button`).forEach(b => b.classList.toggle('on', b.dataset.val === val));

const portsOk = v => /^\s*[1-9]\d{0,4}(-[1-9]\d{0,4})?(\s*,\s*[1-9]\d{0,4}(-[1-9]\d{0,4})?)*\s*$/.test(v);

// ---------- списки ----------
async function loadList() {
  $$('#listTabs button').forEach(b => b.classList.toggle('on', b.dataset.list === listKey));
  const [hint, ph] = LIST_HINTS[listKey];
  $('#listHint').textContent = hint;
  $('#listAdd').placeholder = ph;
  const r = await call('get_list', listKey);
  if (r.ok) { $('#listText').value = r.text; countList(); }
}
const countList = () => {
  const n = $('#listText').value.split('\n').filter(l => l.trim()).length;
  $('#listCount').textContent = n ? `Записей: ${n}` : 'Список пуст';
};

// ---------- диагностика и журнал ----------
function renderDiag(items) {
  const icons = { ok: 'check', warn: 'alert', fail: 'x' };
  const bad = items.filter(i => i.status !== 'ok').length;
  $('#diagList').innerHTML = `<div class="diag-sum">${bad ? `<span class="svc-st st-mid">Найдено проблем: ${bad}</span>` : '<span class="svc-st st-ok">Всё в порядке</span>'}</div>`
    + items.map((it, i) => `<div class="diag ${it.status}" style="animation-delay:${i * 30}ms">
      <span class="dic">${icon(icons[it.status])}</span>
      <div class="dtxt"><b>${esc(it.title)}</b><span>${esc(it.detail)}</span></div>
      ${it.fix ? `<button class="btn sm ${it.status === 'fail' ? 'primary' : ''}" data-fix="${esc(it.fix)}" ${it.fix === 'remove_conflicts' ? 'data-confirm="Конфликтующие службы обхода будут остановлены и удалены. Продолжить?"' : ''}>${esc(it.fix_label)}</button>` : ''}
    </div>`).join('');
}

async function loadLog() {
  const r = await call('get_log');
  if (!r.ok) return;
  const el = $('#logView');
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
  el.innerHTML = r.lines.length ? r.lines.map(l => {
    const t = new Date(l.t * 1000).toLocaleTimeString('ru');
    return `<div class="${l.lvl}"><span class="t">${t}</span>${esc(l.msg)}</div>`;
  }).join('') : '<div class="muted">Пока пусто</div>';
  if (atBottom) el.scrollTop = el.scrollHeight;
}

// ---------- обновления и настройки ----------
function renderUpdates() {
  renderTgUpdate();
  const u = S.update?.component === 'tg' ? {} : (S.update || {}), L = S.latest;
  $('#vLocal').textContent = S.engine_version || '—';
  $('#vRemote').textContent = L ? L.version : '—';
  const newer = L && verNewer(L.version, S.engine_version);
  const st = $('#updStatus');
  const wrap = $('#updBarWrap');
  wrap.classList.toggle('hidden', !['download', 'install'].includes(u.stage));
  if (u.stage === 'download') {
    st.className = 'upd-status new';
    st.innerHTML = `${icon('download')}Скачиваю ${esc(u.version)}… ${u.total ? Math.round(u.done / u.total * 100) + '%' : ''}`;
    $('#updBar').style.width = `${u.total ? (u.done / u.total) * 100 : 30}%`;
  } else if (u.stage === 'install') {
    st.className = 'upd-status new';
    st.innerHTML = `${icon('refresh')}Устанавливаю и переношу настройки…`;
    $('#updBar').style.width = '100%';
  } else if (u.stage === 'error') {
    st.className = 'upd-status err';
    st.innerHTML = `${icon('alert')}${esc(u.error)}`;
  } else if (updCheckError && !L) {
    st.className = 'upd-status err';
    st.innerHTML = `${icon('alert')}${esc(updCheckError)}`;
  } else if (newer) {
    st.className = 'upd-status new';
    st.innerHTML = `${icon('sparkles')}Доступна новая версия ${esc(L.version)}`;
  } else if (L) {
    st.className = 'upd-status ok';
    st.innerHTML = `${icon('check')}У вас последняя версия`;
  } else {
    st.className = 'upd-status';
    st.innerHTML = `${icon('info')}Нажмите «Проверить», чтобы узнать о новой версии`;
  }
  const inst = $('#updInstall');
  inst.disabled = !!S.busy;
  inst.innerHTML = `${icon('download')}${newer ? 'Обновить' : 'Переустановить'}`;
  inst.classList.toggle('primary', !!newer);
  $('#relNotes').textContent = L?.notes?.trim() || (L ? 'Описание изменений не найдено' : '—');
}

function renderTgUpdate() {
  // В 2.0 ядро Telegram-прокси встроено в приложение: отдельной установки и проверки версий нет.
  $('#updTg').innerHTML = `<span class="ttl-ic" style="--c:#37bbfe">${icon('send')}</span>
    <div class="comp-txt"><b>Ядро Telegram-прокси</b><span>Встроено в приложение — обновляется вместе с Zapret Hub</span></div>`;
}

function renderTelegram() {
  const tg = S.tg;
  const installing = S.busy === 'update' && S.update?.component === 'tg';
  const busy = installing || tgSwitching;
  $('#tgHero').classList.toggle('on', tg.running);
  const sw = $('#tgSwitch');
  sw.checked = busy ? sw.checked : tg.running;
  sw.disabled = busy;
  sw.parentElement.classList.toggle('busy', busy);
  let title = tg.running ? 'Прокси работает' : 'Прокси выключен';
  let sub = tg.running ? `127.0.0.1:${tg.port} · встроенное ядро`
    : tg.installed ? 'Включите, затем добавьте прокси в Telegram кнопкой ниже' : 'При первом включении tg-ws-proxy скачается с GitHub';
  if (installing) { title = 'Устанавливаю tg-ws-proxy…'; sub = S.update.stage === 'download' && S.update.total ? `Скачано ${Math.round(S.update.done / S.update.total * 100)}%` : 'Проверяю совместимость'; }
  else if (tgSwitching) { title = 'Запускаю прокси…'; sub = 'Это займёт несколько секунд'; }
  else if (tg.enabled && !tg.running) { title = 'Прокси перезапускается'; sub = 'Сторож поднимет его автоматически'; }
  $('#tgTitle').textContent = title;
  $('#tgSub').textContent = sub;
  $('#tgLink').textContent = tg.link;
  $('#tgOpenBtn').disabled = !tg.running;
}

function loadTg() {
  const tg = S.tg;
  $('#tgPort').value = tg.port;
  $('#tgSecret').value = tg.secret;
  $('#tgDc').value = (tg.dc_ip || []).join('\n');
  $('#tgCf').checked = !!tg.cfproxy;
}

// ---------- AI DNS ----------
let aiSwitching = false;
const AI_EDITORS = [['primary', 'Предпочтительный DNS', 'Например, 31.31.207.68'], ['alternate', 'Дополнительный DNS', 'Необязательно, например 8.8.8.8']];

function renderAiDns() {
  const ai = S.aidns, servers = [ai.primary, ai.alternate].filter(s => s.address).map(s => s.address).join(' + ');
  $('#aiHero').classList.toggle('on', ai.enabled);
  const sw = $('#aiSwitch');
  if (!aiSwitching) sw.checked = ai.enabled;
  sw.disabled = aiSwitching;
  sw.parentElement.classList.toggle('busy', aiSwitching);
  $('#aiTitle').textContent = aiSwitching ? (sw.checked ? 'Применяю DNS…' : 'Возвращаю прежние DNS…') : ai.enabled ? 'ИИ-сервисы открыты' : 'AI DNS выключен';
  $('#aiSub').textContent = ai.enabled ? `DNS ${servers}${ai.primary.doh ? ' · DNS по HTTPS' : ''}` : 'Включите, чтобы открыть ИИ-сервисы через свои DNS-серверы';
  $('#aiServices').innerHTML = ai.services.map(s => `<span>${esc(s)}</span>`).join('');
  const note = $('#aiNotice');
  note.classList.toggle('hidden', !ai.standalone);
  if (ai.standalone) note.querySelector('span').textContent = ai.imported
    ? 'Настройки перенесены из AI DNS для Windows. Чтобы программы не спорили за DNS, выключите автозапуск отдельного AI DNS.'
    : 'Найден отдельный AI DNS для Windows. Чтобы программы не спорили за DNS, выключите его автозапуск.';
}

function aiEditor([key, title, ph]) {
  return `<div class="card ai-ed" data-ai="${key}">
    <h3>${title}</h3>
    <label class="field"><span>IP-адрес</span><input data-f="address" placeholder="${ph}" spellcheck="false" autocomplete="off"></label>
    <div class="opt"><div><b>DNS по протоколу HTTPS</b><span>Шифрует запросы — провайдер их не видит и не подменяет</span></div><label class="switch"><input type="checkbox" data-f="doh"><span></span></label></div>
    <label class="field" data-dep><span>Шаблон DNS по протоколу HTTPS</span><input data-f="template" placeholder="https://example.com/dns-query" spellcheck="false" autocomplete="off"></label>
    <div class="opt" data-dep><div><b>Возврат к открытому тексту</b><span>Если DoH не ответил — спросить тот же сервер обычным DNS</span></div><label class="switch"><input type="checkbox" data-f="fallback"><span></span></label></div>
    <div class="ai-check" data-check>${icon('info')}<span>Нажмите «Проверить серверы»</span></div>
  </div>`;
}

function fillAi(key, s) {
  const box = $(`[data-ai="${key}"]`);
  $('[data-f="address"]', box).value = s.address;
  $('[data-f="template"]', box).value = s.template;
  $('[data-f="doh"]', box).checked = s.doh;
  $('[data-f="fallback"]', box).checked = s.fallback;
  aiDeps(box);
}

const aiDeps = box => $$('[data-dep]', box).forEach(el => el.classList.toggle('off', !$('[data-f="doh"]', box).checked));

function readAi(key) {
  const box = $(`[data-ai="${key}"]`);
  return { address: $('[data-f="address"]', box).value.trim(), template: $('[data-f="template"]', box).value.trim(),
    doh: $('[data-f="doh"]', box).checked, fallback: $('[data-f="fallback"]', box).checked };
}

function setAiCheck(key, r) {
  const el = $(`[data-ai="${key}"] [data-check]`);
  el.className = `ai-check${r ? ' l' + r.level : ''}`;
  el.innerHTML = r ? `${icon(['check', 'alert', 'x'][r.level])}<span>${esc(r.text)}</span>` : `${icon('refresh', 'spin')}<span>Проверяю…</span>`;
}

const aiSelected = () => $$('#aiAdapters input:checked').map(i => i.value);

async function loadAiDns() {
  $('#aiEditors').innerHTML = AI_EDITORS.map(aiEditor).join('');
  fillAi('primary', S.aidns.primary);
  fillAi('alternate', S.aidns.alternate);
  const r = await call('aidns_adapters');
  if (!r.ok) return;
  $('#aiAdapters').innerHTML = r.items.length ? r.items.map(a => `<label class="ai-ad">
      <span class="check"><input type="checkbox" value="${esc(a.id)}" ${a.selected ? 'checked' : ''}><span></span></span>
      <span class="ad-txt"><b>${esc(a.name)}</b><small>${esc(a.description)}</small></span>
      <code title="DNS на адаптере сейчас">${esc(a.current || 'автоматически')}</code>
      <span class="kind ${a.physical ? 'phys' : ''}">${a.physical ? 'физический' : 'виртуальный'}</span></label>`).join('')
    : '<div class="empty">Активных сетевых адаптеров не найдено</div>';
}

async function aiSave() {
  return call('aidns_save', readAi('primary'), readAi('alternate'), aiSelected());
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove();
  }
}

function renderSettings() {
  $$('[data-opt]').forEach(el => {
    const v = S.options[el.dataset.opt];
    if (el.type === 'checkbox') el.checked = !!v;
    else if (document.activeElement !== el) el.value = String(v);
  });
  $$('#runMode .mode').forEach(b => b.classList.toggle('on', b.dataset.val === S.options.run_mode));
}

// ---------- онбординг ----------
function obStep(step) {
  const order = ['download', 'test', 'done'];
  $$('#obSteps li').forEach(li => {
    const i = order.indexOf(li.dataset.step), cur = order.indexOf(step);
    li.className = i < cur ? 'done' : i === cur ? 'now' : '';
  });
}

function onboardUpdate(u) {
  if (onboarding !== 'download') return;
  if (u.stage === 'download') {
    $('#obBar').style.width = `${u.total ? (u.done / u.total) * 100 : 20}%`;
    $('#obStatus').textContent = `Скачиваю zapret ${u.version || ''}…`;
  } else if (u.stage === 'install') {
    $('#obStatus').textContent = 'Распаковываю…';
  } else if (u.stage === 'done') {
    onboarding = 'test';
    obStep('test');
    $('#obBar').style.width = '0%';
    $('#obStatus').textContent = 'Подбираю стратегию…';
    call('start_test', ['Discord', 'YouTube'], true, true);
  } else if (u.stage === 'error') {
    onboarding = null;
    $('#obStatus').textContent = `Не получилось: ${u.error}`;
    $('#obBtn').classList.remove('hidden');
    $('#obBtn').innerHTML = `${icon('refresh')}Повторить`;
  }
}

function onboardTest(t) {
  if (onboarding !== 'test') return;
  const done = (t.results || []).length;
  $('#obBar').style.width = `${Math.max(5, (done / (t.total || 1)) * 100)}%`;
  if (t.phase === 'testing') $('#obStatus').textContent = `Проверяю ${pretty(t.current)} · ${done + 1} из ${t.total}`;
  if (!t.running && t.phase !== 'baseline') {
    onboarding = 'done';
    obStep('done');
    $('#obBar').style.width = '100%';
    $('#obStatus').textContent = t.best ? `Готово! Включена стратегия ${pretty(t.best)}` : 'Подобрать не удалось — попробуйте «Диагностику»';
    setTimeout(() => { $('#onboard').classList.add('hidden'); refresh(); }, 1600);
  }
}

// ---------- навигация ----------
function go(name) {
  page = name;
  $$('.nav').forEach(n => n.classList.toggle('active', n.dataset.page === name));
  $$('.page').forEach(p => p.classList.toggle('active', p.id === `page-${name}`));
  $('#main').scrollTop = 0;
  if (name === 'filters') loadFilters();
  if (name === 'telegram' && S) loadTg();
  if (name === 'aidns' && S) loadAiDns();
  if (name === 'lists') loadList();
  if (name === 'diag') { loadLog(); defRefresh(); }
  if (name === 'updates' && !S?.latest) call('check_update').then(r => r.ok && refresh());
  if (name === 'updates' && S?.tg.installed && !S.tg.latest) call('check_update', 'tg').then(r => r.ok && refresh());
  if (name === 'strategies') { renderStrategies.done = false; renderStrategies(); }
}

// ---------- действия ----------
const syncMax = r => { if (r?.ok) document.body.classList.toggle('max', !!r.maximized); };

const actions = {
  'win-min': () => call('win_minimize'),
  'win-max': () => call('win_toggle_max').then(syncMax),
  'win-close': () => call('win_close'),

  async toggle() {
    if (switching || S?.busy) return;
    switching = true;
    const on = !S.status.running;
    renderHome(); renderChrome();
    const r = await call('toggle', on);
    switching = false;
    if (r.ok) toast(on ? 'Обход включён' : 'Обход выключен', on ? 'ok' : 'info');
    await refresh();
    if (r.ok) actions['quick-check']($('#qcBtn'));  // сразу показываем, открылось ли
  },
  picker() { $('#picker').classList.toggle('open'); },
  'go-autoselect': () => go('strategies'),

  async 'quick-check'(btn) {
    if (qcRunning) return;
    qcRunning = true;
    renderServices();
    const r = await withLoading(btn, () => call('quick_check'));
    qcRunning = false;
    if (r.ok) qc = r;
    renderServices();
  },

  async 'test-start'() {
    const groups = $$('#groupChips .chip.on').map(c => c.dataset.group);
    if (!groups.length) return toast('Выберите хотя бы один сервис для проверки', 'err');
    const r = await call('start_test', groups, testMode === 'quick', $('#autoApply').checked);
    if (r.ok) { S.busy = 'test'; S.test = { running: true, phase: 'baseline', results: [], total: S.strategies.length }; renderTest(); renderChrome(); }
  },
  'test-cancel': () => call('cancel_test'),

  async 'gf-save'(btn) {
    const tcp = $('#gfTcp').value, udp = $('#gfUdp').value;
    $('#gfTcp').classList.toggle('bad', !portsOk(tcp));
    $('#gfUdp').classList.toggle('bad', !portsOk(udp));
    if (!portsOk(tcp) || !portsOk(udp)) return toast('Проверьте формат портов: 1024-65535 или 1024-1934,1936-65535', 'err');
    const mode = $('#gfMode .on')?.dataset.val || 'disabled';
    const r = await withLoading(btn, () => call('set_game_filter', mode, tcp, udp));
    if (r.ok) { toast('Порты Game Filter сохранены', 'ok'); refresh(); }
  },
  async 'ipset-update'(btn) {
    const r = await withLoading(btn, () => call('update_ipset'));
    if (r.ok) { toast(`Список IP обновлён: ${r.count.toLocaleString('ru')} подсетей`, 'ok'); loadFilters(); }
  },

  'list-add'() {
    const v = $('#listAdd').value.trim();
    if (!v) return;
    const ta = $('#listText');
    ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + v;
    $('#listAdd').value = '';
    countList();
  },
  async 'list-save'(btn) {
    const r = await withLoading(btn, () => call('save_list', listKey, $('#listText').value));
    if (r.ok) { $('#listText').value = r.text; countList(); toast('Список сохранён и применён', 'ok'); }
  },

  async 'diag-run'(btn) {
    $('#diagList').innerHTML = `<div class="empty">${icon('refresh', 'spin')}Проверяю систему…</div>`;
    const r = await withLoading(btn, () => call('run_diagnostics'));
    if (r.ok) renderDiag(r.items);
    loadLog();
  },
  'open-log': () => call('open_log'),

  async 'def-open'() {
    $('#defDlg').classList.remove('hidden');
    $('#defState').textContent = 'Проверяю…';
    $('#defAdd').disabled = true;
    $('#defCancel').focus();
    await defRefresh();
    $('#defCancel').focus();
  },
  'def-cancel'() { $('#defDlg').classList.add('hidden'); },
  async 'def-add'(btn) {
    const r = await withLoading(btn, () => call('defender_add', true));
    if (r.ok) toast('Исключение добавлено', 'ok');
    await defRefresh();
  },
  async 'def-remove'(btn) {
    const paths = defSt?.existing || [];
    if (!paths.length) return;
    if (!(await confirmBox(`Из исключений Защитника будет удалено только: ${paths.join(', ')}. Остальные исключения не изменятся. Продолжить?`))) return;
    const r = await withLoading(btn, () => call('defender_remove', true));
    if (r.ok) toast('Исключение удалено — Защитник снова проверяет папку', 'ok');
    await defRefresh();
  },

  async 'upd-check'(btn) {
    const r = await withLoading(btn, () => call('check_update'));
    updCheckError = r.ok ? null : (r.error || 'Не удалось проверить обновления');
    if (!r.ok) { await refresh(); return; }
    if (r.ok) { toast(r.newer ? `Доступна версия ${r.version}` : 'У вас последняя версия', r.newer ? 'info' : 'ok'); refresh(); }
  },
  async 'upd-install'() {
    // «Обновить» ставит найденную новую версию, «Переустановить» — заново скачивает с GitHub ту же установленную.
    const newer = S.latest && verNewer(S.latest.version, S.engine_version);
    const r = await call('install_update', 'zapret', newer ? '' : 'reinstall');
    if (r.ok) { S.busy = 'update'; S.update = { stage: 'download', done: 0, total: 0 }; renderUpdates(); renderChrome(); renderHome(); }
  },

  async 'tg-copy'() {
    await copyText(S.tg.link);
    toast('Ссылка скопирована — отправьте её себе в «Избранное» и нажмите', 'ok');
  },
  async 'tg-open'() {
    const r = await call('tg_open');
    if (r.ok) toast('Подтвердите добавление прокси в Telegram', 'info');
  },
  async 'tg-save'(btn) {
    const r = await withLoading(btn, () => call('tg_save', $('#tgPort').value, $('#tgDc').value, $('#tgCf').checked));
    if (r.ok) { toast(S.tg.running ? 'Сохранено, прокси перезапущен' : 'Настройки прокси сохранены', 'ok'); await refresh(); loadTg(); }
  },
  async 'tg-secret'(btn) {
    if (!(await confirmBox('Будет создан новый секрет. Прокси, добавленный в Telegram раньше, перестанет работать — его нужно будет добавить заново кнопкой «Открыть в Telegram». Продолжить?'))) return;
    const r = await withLoading(btn, () => call('tg_new_secret'));
    if (r.ok) { toast('Новый секрет создан — заново добавьте прокси в Telegram', 'ok'); await refresh(); loadTg(); }
  },
  async 'upd-check-tg'(btn) {
    const r = await withLoading(btn, () => call('check_update', 'tg'));
    if (r.ok) { toast(r.newer ? `Доступна tg-ws-proxy ${r.version}` : 'tg-ws-proxy последней версии', r.newer ? 'info' : 'ok'); refresh(); }
  },
  async 'upd-install-tg'() {
    const r = await call('install_update', 'tg');
    if (r.ok) { S.busy = 'update'; S.update = { stage: 'download', done: 0, total: 0, component: 'tg' }; renderUpdates(); renderTelegram(); }
  },

  async 'ai-recommended'() {
    const r = await call('aidns_recommended');
    if (!r.ok) return;
    fillAi('primary', r.primary);
    fillAi('alternate', r.alternate);
    toast('Подставлены рекомендуемые настройки (WebShift + GeoHide). Нажмите «Сохранить и применить»', 'info');
  },
  async 'ai-check'(btn) {
    setAiCheck('primary', null);
    setAiCheck('alternate', null);
    const r = await withLoading(btn, () => call('aidns_check', readAi('primary'), readAi('alternate')));
    if (r.ok) { setAiCheck('primary', r.primary); setAiCheck('alternate', r.alternate); }
    else { $$('[data-check]').forEach(el => { el.className = 'ai-check'; el.innerHTML = `${icon('info')}<span>Проверка не выполнена</span>`; }); }
  },
  async 'ai-save'(btn) {
    const r = await withLoading(btn, aiSave);
    if (r.ok) { toast(r.applied ? 'Сохранено и применено' : 'Сохранено. Включите переключатель, чтобы применить', 'ok'); await refresh(); loadAiDns(); }
  },

  async 'ob-start'() {
    onboarding = 'download';
    obStep('download');
    $('#obBarWrap').classList.remove('hidden');
    $('#obBtn').classList.add('hidden');
    $('#obStatus').textContent = 'Узнаю последнюю версию…';
    const r = await call('install_update');
    if (!r.ok) { onboarding = null; $('#obBtn').classList.remove('hidden'); $('#obStatus').textContent = r.error || ''; }
  },
};

document.addEventListener('click', async e => {
  const t = e.target;
  if (!t.closest('#picker')) $('#picker').classList.remove('open');

  const nav = t.closest('[data-page]');
  if (nav) return go(nav.dataset.page);
  const goto = t.closest('[data-go]');
  if (goto) return go(goto.dataset.go);

  const act = t.closest('[data-act]');
  if (act && actions[act.dataset.act]) return actions[act.dataset.act](act);

  const pick = t.closest('[data-pick]');
  if (pick) {
    $('#picker').classList.remove('open');
    const r = await call('set_strategy', pick.dataset.pick);
    if (r.ok) { toast(`Стратегия: ${pretty(pick.dataset.pick)}`, 'ok'); refresh(); }
    return;
  }
  const apply = t.closest('[data-apply]');
  if (apply) {
    const name = apply.dataset.apply;
    const r = await withLoading(apply, async () => {
      const a = await call('set_strategy', name);
      return a.ok && !S.status.running ? call('toggle', true) : a;
    });
    if (r.ok) { toast(`Включена стратегия ${pretty(name)}`, 'ok'); refresh(); }
    return;
  }
  const chip = t.closest('[data-group]');
  if (chip) { chip.classList.toggle('on'); S.test_groups = $$('#groupChips .chip.on').map(c => c.dataset.group); return; }

  const seg = t.closest('.seg button');
  if (seg) {
    const box = seg.parentElement;
    if (box.id === 'testMode') {
      testMode = seg.dataset.val;
      setSeg('#testMode', testMode);
      $('#testModeHint').textContent = testMode === 'quick'
        ? 'Остановится на первой стратегии, которая открыла всё · ~30 сек'
        : 'Проверит все стратегии и выберет самую быструю · 2–3 мин';
      return;
    }
    if (box.id === 'gfMode') {
      setSeg('#gfMode', seg.dataset.val);
      const r = await call('set_game_filter', seg.dataset.val, $('#gfTcp').value, $('#gfUdp').value);
      if (r.ok) toast(seg.dataset.val === 'disabled' ? 'Game Filter выключен' : 'Game Filter включён', 'ok');
      return loadFilters().then(refresh);
    }
    if (box.id === 'ipsetMode') {
      const r = await call('set_ipset', seg.dataset.val);
      if (r.ok) toast('Режим IPSet изменён', 'ok');
      return loadFilters().then(refresh);
    }
  }
  const tab = t.closest('[data-list]');
  if (tab) { listKey = tab.dataset.list; return loadList(); }

  const mode = t.closest('#runMode .mode');
  if (mode) {
    const r = await call('set_run_mode', mode.dataset.val);
    if (r.ok) toast(mode.dataset.val === 'service' ? 'Обход будет работать как служба Windows' : 'Обход будет работать через приложение', 'ok');
    return refresh();
  }

  const fix = t.closest('[data-fix]');
  if (fix) {
    if (fix.dataset.confirm && !(await confirmBox(fix.dataset.confirm))) return;
    const r = await withLoading(fix, () => call('fix', fix.dataset.fix));
    if (r.ok && r.message) toast(r.message, 'ok');
    if (r.ok && page === 'diag' && $('.diag')) actions['diag-run']($('#diagBtn'));
    return;
  }
  const link = t.closest('[data-link]');
  if (link) call('open_link', link.dataset.link);
});

document.addEventListener('change', async e => {
  const t = e.target;
  if (t.id === 'tgSwitch') {
    const on = t.checked;
    tgSwitching = true;
    renderTelegram();
    const r = await call('tg_toggle', on);
    if (r.ok && r.installing) { toast('Скачиваю tg-ws-proxy — прокси включится сам', 'info'); return; }  // дальше — событие update
    tgSwitching = false;
    if (r.ok) toast(on ? 'Telegram-прокси включён — нажмите «Открыть в Telegram»' : 'Telegram-прокси выключен', on ? 'ok' : 'info');
    else t.checked = !on;
    return refresh();
  }
  if (t.id === 'aiSwitch') {
    const on = t.checked;
    aiSwitching = true;
    renderAiDns();
    let r = { ok: true };
    if (on && $('[data-ai="primary"]')) r = await aiSave();  // как в AI DNS: включаем то, что сейчас в форме
    if (r.ok) r = await call('aidns_toggle', on);
    aiSwitching = false;
    if (r.ok) toast(on ? 'AI DNS включён — ИИ-сервисы открываются через свои DNS' : 'AI DNS выключен, прежние DNS возвращены', on ? 'ok' : 'info');
    await refresh();
    if (page === 'aidns') loadAiDns();
    return;
  }
  if (t.dataset.f === 'doh') return aiDeps(t.closest('[data-ai]'));
  if (t.dataset.opt) {
    const v = t.type === 'checkbox' ? t.checked : Number(t.value);
    const r = await call('set_option', t.dataset.opt, v);
    if (r.ok) toast('Настройка сохранена', 'ok');
    refresh();
  } else if (t.dataset.fake && t.value) {
    const r = await call('set_fake', t.dataset.fake, t.value);
    if (r.ok) toast(`Fake-пакет: ${t.value}`, 'ok');
    loadFilters();
  }
});

$('#listText').addEventListener('input', countList);
$('#listAdd').addEventListener('keydown', e => { if (e.key === 'Enter') actions['list-add'](); });
$('#titlebar').addEventListener('dblclick', e => { if (!e.target.closest('.win')) call('win_toggle_max').then(syncMax); });
document.addEventListener('mousedown', e => {
  const rz = e.target.closest('[data-rz]');
  if (rz && e.button === 0) { e.preventDefault(); call('win_resize', rz.dataset.rz); }
});
let maxTimer;
window.addEventListener('resize', () => {  // в т.ч. Win+↑ и прилипание к краю экрана
  clearTimeout(maxTimer);
  maxTimer = setTimeout(() => call('win_state').then(syncMax), 250);
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { $('#picker').classList.remove('open'); $('#defDlg').classList.add('hidden'); } });
$('#defDlg').addEventListener('mousedown', e => { if (e.target.id === 'defDlg') actions['def-cancel'](); });

// ---------- исключение Защитника: только по явному согласию, с состоянием и удалением ----------
let defSt = null;
async function defRefresh() {
  const r = await call('defender_status');
  defSt = r.ok ? r : null;
  const tool = $('#defToolState');
  if (!defSt) tool.textContent = 'Состояние неизвестно';
  else if (!defSt.available) tool.textContent = defSt.error;
  else tool.textContent = defSt.existing.length ? `Сейчас добавлено: ${defSt.existing.join(', ')}` : 'Не добавлено — Zapret Hub само ничего не добавляет';
  defRender();
}

function defRender() {
  $('#defPath').textContent = defSt?.addPath || 'C:\\ProgramData\\ZapretHub\\engine\\bin';
  const st = $('#defState'), add = $('#defAdd'), rem = $('#defRemove');
  if (!defSt || !defSt.available) {
    st.textContent = defSt ? defSt.error : 'Состояние неизвестно';
    add.disabled = true;
    rem.classList.add('hidden');
    return;
  }
  st.textContent = defSt.existing.length
    ? `Сейчас в исключениях: ${defSt.existing.join(', ')}. Программа их не меняла и сама не изменит.`
    : 'Исключений для Zapret Hub сейчас нет.';
  add.disabled = defSt.root || defSt.bin;
  rem.classList.toggle('hidden', !defSt.existing.length);
}
// ---------- старт ----------
hydrateIcons();
window.addEventListener('pywebviewready', async () => {
  await refresh();
  if (S?.status.running && !S.busy) actions['quick-check']($('#qcBtn'));
  setInterval(() => { if (!document.hidden) refresh(); }, 3000);
  setInterval(() => { if (!document.hidden && page === 'diag') loadLog(); }, 3000);
});
