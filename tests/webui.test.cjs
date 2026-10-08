'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// A strict, dependency-free DOM shim: deliberately reject invalid HTML tag names.
// The complete production app is executed, including event registration/timers.
class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.listeners = {}; this.className = ''; this.value = ''; this.hidden = false; this._text = ''; this.dataset = {}; }
  get textContent() { return this._text + this.children.map(x => x.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  append(...nodes) { for (const node of nodes) { if (node.tagName === '#FRAGMENT') this.append(...node.children); else { node.parent = this; this.children.push(node); } } }
  replaceChildren(...nodes) { this.children = []; this._text = ''; this.append(...nodes); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  click() { this.clicked = true; }
  setAttribute() {}
  focus() {}
  remove() { this.parent.children = this.parent.children.filter(x => x !== this); }
  get classList() { return { toggle() {} }; }
  querySelectorAll(selector) {
    const result = [];
    for (const child of this.children) {
      if (selector.startsWith('.') ? child.className.split(' ').includes(selector.slice(1)) : child.tagName.toLowerCase() === selector) result.push(child);
      result.push(...child.querySelectorAll(selector));
    }
    return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function fixture(overrides = {}) {
  return { version: 'test', status: { api_reachable: true, balancer_api_reachable: true, adopted: true },
    system: { installed: true, command_ok: true, checked_at: '2026-09-26T00:00:00Z', xray_running: true },
    keys: { Keys: [{ tag: 'main--VL-fi', name: '🇫🇮 Финляндия', checked: true, verified: true, Selected: true, Applied: true }] },
    sites: ['https://example.com/'], economy_checks: false, live_probes_allowed: false, warnings: [], ...overrides };
}
async function app() {
  const elements = new Map();
  const html = fs.readFileSync(path.join(__dirname, '../cmd/hotwatcher/ui/index.html'), 'utf8');
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*\bid="([^"]+)"[^>]*>/g)) elements.set(match[2], new Element(match[1]));
  const calls = [], intervals = [], downloads = [];
  const context = {
    document: { hidden: false, getElementById: id => { assert(elements.has(id), `unknown ID ${id}`); return elements.get(id); }, querySelectorAll: () => [],
      createElement: tag => { if (!/^[a-z][a-z0-9-]*$/i.test(tag)) throw new Error('Document.createElement: Invalid element name'); return new Element(tag); },
      createDocumentFragment: () => new Element('#fragment') },
    location: { hash: '#keys' }, window: { scrollTo() {}, addEventListener() {} },
    setInterval: (fn, delay) => { intervals.push({ fn, delay }); }, setTimeout() {}, console,
    Blob, URL: { createObjectURL: blob => { downloads.push(blob); return 'blob:test'; }, revokeObjectURL() {} },
    fetch: async (url, options) => {
      calls.push({ url, options });
      const data = url === '/api/session' ? { authenticated: false } : url === '/api/overview' ? fixture() : url === '/api/system' ? fixture().system : url === '/api/action' ? { id: 1 } : { id: 1, state: 'succeeded', message: 'OK' };
      return { ok: true, json: async () => data };
    }
  };
  const source = fs.readFileSync(process.env.HW_UI_SOURCE || path.join(__dirname, '../cmd/hotwatcher/ui/app.js'), 'utf8');
  const instrumented = source.replace(/\}\)\(\);\s*$/, 'globalThis.testing = { renderOverview, renderKeys, renderResults, renderDNS, renderSystem, renderJobResult, renderActivity, downloadReport, refresh, refreshSystem, refreshActivity, setSession: () => { csrf = "test"; }, busy: () => { activeJob = 1; sitesDirty = true; }, setWebJob: job => { webJob = job; if (currentActivity) renderActivity(currentActivity); } };\n})();');
  assert.notEqual(source, instrumented, 'test hook could not be installed');
  vm.runInNewContext(instrumented, context, { filename: 'app.js' });
  await new Promise(resolve => setImmediate(resolve));
  return { ...context.testing, elements, calls, intervals, downloads, context };
}

test('real Go JSON casing renders names, opaque tags, verification and actions', async () => {
  const a = await app();
  a.renderOverview(fixture());
  const body = a.elements.get('keysBody');
  assert.equal(body.children.length, 1);
  assert.match(body.textContent, /Финляндия/);
  assert.equal(body.querySelector('small').textContent, 'main--VL-fi');
  assert.match(body.textContent, /Проверен без VPN/);
  assert.equal(a.elements.get('selectedName').textContent, '🇫🇮 Финляндия');
  a.setSession();
  await a.elements.get('pinSelectedButton').listeners.click();
  const action = a.calls.find(c => c.url === '/api/action');
  assert.deepEqual(JSON.parse(action.options.body), { action: 'pin', tag: 'main--VL-fi' });
});
test('status report is generated only on demand, rendered and downloadable', async () => {
  const a = await app();
  assert.equal(a.calls.some(call => call.url === '/api/diagnostics/report'), false);
  const report = { generated_at: '2026-10-08T08:00:00Z', sections: [{ title: 'Процессы и версии', lines: ['Xray: 1 процесс', 'Hot Watcher: 0.3.5'] }, { title: 'Активный ключ', lines: ['Проверка: 78 мс'] }], text: 'Hot Watcher\nXray: 1 процесс\n' };
  a.context.fetch = async (url) => { a.calls.push({ url }); return { ok: true, json: async () => report }; };
  a.setSession();
  await a.elements.get('generateStatusReportButton').listeners.click();
  assert.equal(a.calls.filter(call => call.url === '/api/diagnostics/report').length, 1);
  assert.match(a.elements.get('statusReportSections').textContent, /78 мс/);
  assert.equal(a.elements.get('statusReportActions').hidden, false);
  a.elements.get('downloadStatusTextButton').listeners.click();
  a.elements.get('downloadStatusJSONButton').listeners.click();
  assert.equal(a.downloads.length, 2);
  assert.equal(await a.downloads[0].text(), report.text);
  assert.deepEqual(JSON.parse(await a.downloads[1].text()), report);
});
test('auto mode preserves an emergency tagged selection and shows why key choice is delayed', async () => {
  const a = await app();
  const keys = Array.from({ length: 19 }, (_, i) => ({ tag: `main--VL-${i}`, name: i === 0 ? '-WestKost' : `Ключ ${i}`, Selected: i === 0, Applied: true, Emergency: i === 0, checked: false, verified: false }));
  a.renderOverview(fixture({ status: { adopted: true, selection_mode: 'auto', api_reachable: true, balancer_api_reachable: true }, keys: { Keys: keys, LastCheckSuccess: false }, recovery: { hard_sync: { stage: 'failed' }, suggested_command: 'hotwatcher recovery resume' } }));
  assert.equal(a.elements.get('modeTitle').textContent, 'Автовыбор включён');
  assert.match(a.elements.get('modeDescription').textContent, /прежний выбор/);
  assert.equal(a.elements.get('autoButton').textContent, 'Повторить выбор');
  assert.equal(a.elements.get('autoButton').disabled, false);
  assert.equal(a.elements.get('selectedName').textContent, '-WestKost');
  assert.equal(a.elements.get('selectedOrigin').hidden, false);
  assert.match(a.elements.get('emergencyCurrent').textContent, /сейчас выбран/);
  assert.match(a.elements.get('keysBody').textContent, /Аварийная пометка/);
  assert.match(a.elements.get('keysWarning').textContent, /журнал hard-sync/);
  assert.match(a.elements.get('keysWarning').textContent, /не блокирует смену ключа/);
  assert.match(a.elements.get('keysWarning').textContent, /Последняя синхронизация завершилась ошибкой/);
  assert.match(a.elements.get('keysWarning').textContent, /У всех 19 ключей нет результатов проверки/);
  assert.equal(a.elements.get('keysWarning').hidden, false);
  a.setSession();
  await a.elements.get('autoButton').listeners.click();
  const action = a.calls.find(c => c.url === '/api/action');
  assert.deepEqual(JSON.parse(action.options.body), { action: 'auto', tag: '' });
});
test('manual pin is shown separately from emergency provenance', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: { adopted: true, selection_mode: 'manual' }, keys: { Keys: [{ tag: 'main--VL-fi', name: '-WestKost', Selected: true, Applied: true, Emergency: true }] } }));
  assert.equal(a.elements.get('modeTitle').textContent, 'Закреплён вручную');
  assert.equal(a.elements.get('autoButton').textContent, 'Включить автовыбор');
  assert.equal(a.elements.get('selectedOrigin').hidden, false);
  assert.match(a.elements.get('emergencyCurrent').textContent, /сейчас выбран/);
});
test('legacy names and literal HTML-looking names stay text, search uses normalized tag', async () => {
  const a = await app();
  a.renderKeys({ Keys: [{ Tag: 'main--VL-legacy', Name: '<img onerror=alert(1)>', Applied: true }] });
  assert.match(a.elements.get('keysBody').textContent, /<img/);
  assert.equal(a.elements.get('keysBody').querySelectorAll('img').length, 0);
  a.elements.get('keySearch').value = 'main--VL-fi';
  a.renderKeys(fixture().keys);
  assert.equal(a.elements.get('keysBody').children.length, 1);
});
test('API failure is not reported as a stopped Xray process; keys remain visible', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: { api_reachable: false, balancer_api_reachable: false } }));
  assert.equal(a.elements.get('topStatus').textContent, 'Xray: процесс запущен');
  assert.match(a.elements.get('apiDetail').textContent, /не означает обрыв VPN/);
  assert.equal(a.elements.get('keysBody').children.length, 1);
  assert.equal(a.elements.get('xkeenTopStatus').textContent, 'XKeen: команда доступна');
});

test('stopped Xray is not presented as an applied live key', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: { api_reachable: false, balancer_api_reachable: false, adopted: true }, system: { installed: true, command_ok: true, checked_at: '2026-10-08T00:00:00Z', xray_running: false } }));
  assert.match(a.elements.get('systemDiagnosis').textContent, /Xray не запущен/);
  assert.equal(a.elements.get('xkeenTopStatus').textContent, 'XKeen: Xray остановлен');
  assert.match(a.elements.get('keysBody').textContent, /Сохранённый выбор/);
  assert.doesNotMatch(a.elements.get('keysBody').textContent, /Выбран в Xray/);
});

test('a restarted Xray without the saved balancer pin is not presented as the selected key', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: { api_reachable: true, balancer_api_reachable: true, selected_present: true, balancer_pin_matches: false, adopted: true }, system: { installed: true, command_ok: true, checked_at: '2026-10-08T00:00:00Z', xray_running: true } }));
  assert.match(a.elements.get('systemDiagnosis').textContent, /не закреплён/);
  assert.match(a.elements.get('keysBody').textContent, /Сохранённый выбор/);
  assert.doesNotMatch(a.elements.get('keysBody').textContent, /Выбран в Xray/);
});
test('pending or uninspectable health is not a false offline result', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: null, system: {} }));
  assert.equal(a.elements.get('topStatus').textContent, 'Xray: проверяю');
  assert.equal(a.elements.get('xkeenTopStatus').textContent, 'XKeen: проверяю');
  a.renderOverview(fixture({ status: { api_reachable: false, balancer_api_reachable: false }, system: { xray_running: null } }));
  assert.equal(a.elements.get('topStatus').textContent, 'Xray: ошибка проверки API');
});

test('reachable API with unknown process does not confirm Xray or a live selected key', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: { api_reachable: true, balancer_api_reachable: true, selected_present: true, balancer_pin_matches: true, adopted: true }, system: { xray_running: null } }));
  assert.match(a.elements.get('topStatus').textContent, /процесс не подтверждён/);
  assert.doesNotMatch(a.elements.get('topStatus').className, /online/);
  assert.match(a.elements.get('systemDiagnosis').textContent, /не удалось подтвердить/);
  assert.doesNotMatch(a.elements.get('systemDiagnosis').className, /ready/);
  assert.match(a.elements.get('keysBody').textContent, /Сохранённый выбор/);
});
test('global health refresh continues on the keys tab during jobs and site editing', async () => {
  const a = await app();
  a.setSession(); a.busy();
  a.renderOverview(fixture());
  a.elements.get('siteRows').replaceChildren();
  a.calls.length = 0;
  for (const timer of a.intervals) timer.fn();
  await new Promise(resolve => setImmediate(resolve));
  assert(a.calls.some(c => c.url === '/api/overview'));
  assert(a.calls.some(c => c.url === '/api/activity'));
  assert.equal(a.elements.get('siteRows').children.length, 0, 'dirty site input was overwritten');
});
test('activity panel distinguishes the lock from a web job and labels deferred pause', async () => {
  const a = await app();
  a.renderActivity({ lock: { busy: true, pid: 321, operation: 'sync' }, elapsed_seconds: 85, background_paused: false, stop_requested: false, can_stop: true, message: 'Загрузка подписки' });
  assert.match(a.elements.get('activityState').textContent, /Выполняется: sync/);
  assert.equal(a.elements.get('activityElapsed').textContent, '1 мин 25 сек');
  assert.match(a.elements.get('activityMessage').textContent, /Загрузка подписки/);
  assert.equal(a.elements.get('stopActivityButton').disabled, false);
  a.setWebJob({ action: 'pin', state: 'running', message: 'Ожидает блокировку' });
  assert.match(a.elements.get('activityWebJob').textContent, /Запрос из панели: pin · Ожидает блокировку/);
  assert.equal(a.elements.get('activityWebJob').hidden, false);
  a.setWebJob({ action: 'pin', state: 'waiting', message: 'Ожидает блокировку' });
  assert.match(a.elements.get('activityWebJob').textContent, /В очереди панели: pin/);
  a.renderActivity({ lock: { busy: true, operation: 'sync' }, elapsed_seconds: 90, stop_requested: true, can_stop: false });
  assert.match(a.elements.get('activityState').textContent, /Завершает перед паузой/);
  assert.equal(a.elements.get('stopActivityButton').disabled, true);
});
test('activity from another browser tab stays visible without a shared lock', async () => {
  const a = await app();
  a.renderActivity({ lock: { busy: false }, web_job: { id: 9, action: 'update-check', state: 'running', elapsed_seconds: 68 }, message: 'Задача панели выполняется или ожидает блокировки', can_stop: true });
  assert.match(a.elements.get('activityState').textContent, /Задача панели: update-check/);
  assert.equal(a.elements.get('activityElapsed').textContent, '1 мин 8 сек');
  assert.match(a.elements.get('activityWebJob').textContent, /Запрос из панели: update-check/);
  assert.equal(a.elements.get('activityWebJob').hidden, false);
  assert.doesNotMatch(a.elements.get('activityState').textContent, /Нет активных операций/);
  a.renderActivity({ lock: { busy: false }, message: 'Нет операции под общей блокировкой', can_stop: true });
  assert.equal(a.elements.get('activityState').textContent, 'Нет операции под общей блокировкой');
  assert.equal(a.elements.get('activityWebJob').hidden, true);
});
test('unknown Xray log settings are not presented as disabled logging', async () => {
  const a = await app();
  a.renderSystem({ installed: true, checked_at: '2026-10-08T00:00:00Z', xray_log_config_known: false, xray_error_path_known: false, xray_access_path_known: false });
  assert.match(a.elements.get('xrayLogDetail').textContent, /Путь не определён/);
  assert.match(a.elements.get('xrayLogText').textContent, /Не удалось прочитать настройки/);
  assert.match(a.elements.get('xrayAccessLogDetail').textContent, /Путь не определён/);
});
test('system shows LAN interception rules and packet deltas without claiming client success', async () => {
  const a = await app();
  const base = { installed: true, checked_at: '2026-10-08T00:00:00Z' };
  a.renderSystem({ ...base, lan_interception: { checked_at: '2026-10-08T00:01:00Z', tcp: { known: true, present: true, expected_port: 61219, ingress_packets: 10, redirected_packets: 4 }, udp: { known: true, present: false, expected_port: 61219, missing: 'prerouting_jump_missing' } } });
  assert.match(a.elements.get('lanTCPState').textContent, /Правило найдено/);
  assert.match(a.elements.get('lanUDPDetail').textContent, /PREROUTING/);
  a.renderSystem({ ...base, lan_interception: { checked_at: '2026-10-08T00:02:00Z', tcp: { known: true, present: true, expected_port: 61219, ingress_packets: 12, redirected_packets: 6 }, udp: { known: true, present: false, expected_port: 61219, missing: 'prerouting_jump_missing' }, tcp_ipv6: { known: false, missing: 'iptables_save_unavailable' }, udp_ipv6: { known: false, missing: 'iptables_save_unavailable' } } });
  assert.match(a.elements.get('lanTCPDetail').textContent, /с прошлого снимка \+2/);
  assert.match(a.elements.get('lanIPv6TCPState').textContent, /Проверка недоступна/);
  assert.doesNotMatch(a.elements.get('lanTCPDetail').textContent, /сайт работает/);
});
test('activity stop and resume use authenticated POST requests', async () => {
  const a = await app();
  a.setSession();
  a.renderActivity({ lock: { busy: false }, can_stop: true });
  await a.elements.get('stopActivityButton').listeners.click();
  const stop = a.calls.find(c => c.url === '/api/activity/stop');
  assert.equal(stop.options.method, 'POST');
  assert.equal(stop.options.headers['X-HW-CSRF'], 'test');
  a.renderActivity({ lock: { busy: false }, background_paused: true, can_stop: false });
  assert.equal(a.elements.get('resumeActivityButton').hidden, false);
  await a.elements.get('resumeActivityButton').listeners.click();
  const resume = a.calls.find(c => c.url === '/api/activity/resume');
  assert.equal(resume.options.method, 'POST');
  assert.equal(resume.options.headers['X-HW-CSRF'], 'test');
});
test('empty key inventories are rendered without throwing', async () => {
  const a = await app();
  a.renderOverview(fixture({ keys: { Keys: [] } }));
  assert.equal(a.elements.get('keysBody').children.length, 0);
  assert.equal(a.elements.get('keysEmpty').hidden, false);
});
test('isolated mode is selected by default and live checks require explicit opt-in', async () => {
  const a = await app();
  a.renderOverview(fixture());
  assert.equal(a.elements.get('economyChecks').checked, false);
  assert.equal(a.elements.get('economyChecks').disabled, true);
  a.renderOverview(fixture({ live_probes_allowed: true }));
  assert.equal(a.elements.get('economyChecks').disabled, false);
  a.setSession();
  a.elements.get('economyChecks').checked = true;
  await a.elements.get('economyChecks').listeners.change();
  const save = a.calls.find(c => c.url === '/api/probe-mode');
  assert.equal(save.options.method, 'PUT');
  assert.deepEqual(JSON.parse(save.options.body), { economy_checks: true });
});
test('URL Test shows live site progress and a completed report', async () => {
  const a = await app();
  const report = { tag: 'main--VL-fi', time: '2026-09-26T00:00:00Z', passed: false, progress_known: true, results: [
    { site: 'https://github.com/', ok: true, completed: true, status: 200, latency_ms: 45 },
    { site: 'https://chatgpt.com/', ok: false, completed: true, status: 403 },
    { site: 'https://youtube.com/', ok: false, reason: 'проверка не завершена' }
  ] };
  a.renderResults(report, true);
  assert.match(a.elements.get('resultSummary').textContent, /Проверено 2 из 3 · HTTPS-ответ 1 · ошибка проверки 1/);
  assert.match(a.elements.get('resultList').textContent, /HTTP 403/);
  assert.match(a.elements.get('resultList').textContent, /Ожидает проверки/);
  assert.equal(a.elements.get('downloadReportButton').disabled, true);
  a.renderResults(report);
  assert.match(a.elements.get('resultBadge').textContent, /Прервано/);
  assert.match(a.elements.get('resultList').textContent, /Не проверено/);
  assert.equal(a.elements.get('downloadReportButton').disabled, false);
  a.renderResults({ ...report, mode: 'main_xray', results: [{ site: 'https://example.com/', ok: false, completed: true, status: 200, reason: 'маршрут обошёл ключ' }] });
  assert.match(a.elements.get('resultList').textContent, /маршрут обошёл ключ/);
  assert.match(a.elements.get('resultSummary').textContent, /основной Xray/);
  assert.match(a.elements.get('resultSummary').textContent, /маршрут устройств в сети не проверен/);
});

test('exported URL Test describes an endpoint HTTPS check, not site availability', async () => {
  const a = await app();
  a.renderResults({ tag: 'main--VL-fi', time: '2026-10-08T00:00:00Z', progress_known: true, results: [
    { site: 'https://github.com/', completed: true, ok: true, status: 200 },
    { site: 'https://chatgpt.com/', completed: true, ok: false, status: 403 }
  ] });
  a.downloadReport();
  assert.equal(a.downloads.length, 1);
  const body = await a.downloads[0].text();
  assert.match(body, /Успешных HTTPS-проверок: 1/);
  assert.match(body, /Маршрут устройств в сети, их DNS и перехват трафика XKeen не проверены/);
  assert.match(body, /HTTPS-проверка не прошла \| https:\/\/chatgpt.com\//);
  assert.doesNotMatch(body, /Открывается|Не открывается/);
});

test('DNS page shows file state and probe results without treating a local DoH route as VLESS', async () => {
  const a = await app();
  a.renderDNS({ config_file: '/opt/etc/xray/configs/03_dns.json', managed: true, parallel_queries: true, servers: ['https+local://1.1.1.1/dns-query'], runtime_activation_unverified: true });
  assert.match(a.elements.get('dnsBadge').textContent, /подготовлен/);
  assert.match(a.elements.get('dnsNote').textContent, /ручной перезапуск/);
  assert.equal(a.elements.get('dnsOnButton').disabled, true);
  assert.equal(a.elements.get('dnsOffButton').disabled, false);
  a.renderJobResult({ action: 'dns-test', result: [{ name: 'Cloudflare', success: true, median_ms: 28, responses: 3 }] });
  assert.match(a.elements.get('dnsResult').textContent, /Cloudflare: доступен · 28 мс · 3\/3/);
  a.renderJobResult({ action: 'dns-verify', result: { direct: { success: true }, selected_vless: { checked: false, reason: 'неприменим' }, scope: 'Временный Xray' } });
  assert.match(a.elements.get('dnsResult').textContent, /Выбранный VLESS: неприменим/);
  a.setSession();
  await a.elements.get('dnsTestButton').listeners.click();
  const call = a.calls.find(c => c.url === '/api/action');
  assert.deepEqual(JSON.parse(call.options.body), { action: 'dns-test', tag: '' });
});

test('advanced update controls send distinct disable, pause and pin requests', async () => {
  const a = await app();
  a.setSession();
  a.elements.get('pinnedVersion').value = '0.3.4';
  await a.elements.get('pinUpdateButton').listeners.click();
  const pin = a.calls.find(c => c.url === '/api/update/pin');
  assert.deepEqual(JSON.parse(pin.options.body), { version: '0.3.4' });
  a.calls.length = 0;
  await a.elements.get('pauseInstallButton').listeners.click();
  const pause = a.calls.find(c => c.url === '/api/action');
  assert.equal(JSON.parse(pause.options.body).action, 'update-pause-on');
  a.calls.length = 0;
  await a.elements.get('pauseUpdateButton').listeners.click();
  const disable = a.calls.find(c => c.url === '/api/action');
  assert.equal(JSON.parse(disable.options.body).action, 'update-disable');
});
