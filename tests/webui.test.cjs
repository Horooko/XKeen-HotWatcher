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
    sites: ['https://example.com/'], warnings: [], ...overrides };
}
async function app() {
  const elements = new Map();
  const html = fs.readFileSync(path.join(__dirname, '../cmd/hotwatcher/ui/index.html'), 'utf8');
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*\bid="([^"]+)"[^>]*>/g)) elements.set(match[2], new Element(match[1]));
  const calls = [], intervals = [];
  const context = {
    document: { hidden: false, getElementById: id => { assert(elements.has(id), `unknown ID ${id}`); return elements.get(id); }, querySelectorAll: () => [],
      createElement: tag => { if (!/^[a-z][a-z0-9-]*$/i.test(tag)) throw new Error('Document.createElement: Invalid element name'); return new Element(tag); },
      createDocumentFragment: () => new Element('#fragment') },
    location: { hash: '#keys' }, window: { scrollTo() {}, addEventListener() {} },
    setInterval: (fn, delay) => { intervals.push({ fn, delay }); }, setTimeout() {}, console,
    fetch: async (url, options) => {
      calls.push({ url, options });
      const data = url === '/api/session' ? { authenticated: false } : url === '/api/overview' ? fixture() : url === '/api/system' ? fixture().system : url === '/api/action' ? { id: 1 } : { id: 1, state: 'succeeded', message: 'OK' };
      return { ok: true, json: async () => data };
    }
  };
  const source = fs.readFileSync(process.env.HW_UI_SOURCE || path.join(__dirname, '../cmd/hotwatcher/ui/app.js'), 'utf8');
  const instrumented = source.replace(/\}\)\(\);\s*$/, 'globalThis.testing = { renderOverview, renderKeys, refresh, refreshSystem, setSession: () => { csrf = "test"; }, busy: () => { activeJob = 1; sitesDirty = true; } };\n})();');
  assert.notEqual(source, instrumented, 'test hook could not be installed');
  vm.runInNewContext(instrumented, context, { filename: 'app.js' });
  await new Promise(resolve => setImmediate(resolve));
  return { ...context.testing, elements, calls, intervals, context };
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
  assert.equal(a.elements.get('xkeenTopStatus').textContent, 'XKeen: отвечает');
});
test('pending or uninspectable health is not a false offline result', async () => {
  const a = await app();
  a.renderOverview(fixture({ status: null, system: {} }));
  assert.equal(a.elements.get('topStatus').textContent, 'Xray: проверяю');
  assert.equal(a.elements.get('xkeenTopStatus').textContent, 'XKeen: проверяю');
  a.renderOverview(fixture({ status: { api_reachable: false, balancer_api_reachable: false }, system: { xray_running: null } }));
  assert.equal(a.elements.get('topStatus').textContent, 'Xray: ошибка проверки API');
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
  assert.equal(a.elements.get('siteRows').children.length, 0, 'dirty site input was overwritten');
});
test('empty key inventories are rendered without throwing', async () => {
  const a = await app();
  a.renderOverview(fixture({ keys: { Keys: [] } }));
  assert.equal(a.elements.get('keysBody').children.length, 0);
  assert.equal(a.elements.get('keysEmpty').hidden, false);
});
