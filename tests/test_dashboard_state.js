// Run with: node tests/test_dashboard_state.js
// Exercise asynchronous org switches and real chart markup without a server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../app/dashboard.html'), 'utf8');
const js = [...html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
new vm.Script(js);
const rename = js.slice(js.indexOf('let orgRenamePending ='), js.indexOf('function sendDomainAction('));
const trend = js.slice(js.indexOf('function drawTrend('), js.indexOf('function renderFactors('));
const login = js.slice(js.indexOf('let loginPending ='), js.indexOf('function doLogout('));

function setup(fetch) {
  const elements = {
    'ws-org-name': {value: 'New Acme', focus() {}},
    'ws-rename-status': {textContent: ''}, 'ws-rename': {disabled: false},
    orgsel: {options: [{value: 'acme', textContent: 'Acme'}, {value: 'beta', textContent: 'Beta'}]},
    'login-user': {value: 'admin'}, 'login-pass': {value: 'local-login-test!'},
    'login-msg': {textContent: ''}, 'login-btn': {disabled: false},
  };
  const ctx = {currentOrg: 'acme', orgNames: {acme: 'Acme', beta: 'Beta'},
    $: id => elements[id], authHeaders: () => ({'Content-Type': 'application/json'}),
    populateLogOrgs() {}, renderAiEgress() {}, renderPortfolio() {}, fetch,
    btoa: s => Buffer.from(s, 'binary').toString('base64'), hideLogin() {}, loadOrgs() {},
    esc: s => String(s).replace(/</g, '&lt;'), shortTs: s => s, hideTip() {}, showTip() {}};
  vm.createContext(ctx);
  vm.runInContext(rename + '\n' + trend + '\n' + login, ctx);
  return {ctx, elements};
}

async function run() {
  const requests = [];
  const {ctx, elements} = setup(async (url, options) => {
    requests.push({url, options});
    return {ok: true, json: async () => url === '/api/portfolio' ? {orgs: []} : {slug: 'acme', name: 'Example & Co'}};
  });
  await ctx.saveOrgName({preventDefault() {}});
  assert.equal(requests[0].url, '/api/orgs/acme');
  assert.equal(requests[0].options.method, 'PATCH');
  assert.equal(ctx.currentOrg, 'acme');
  assert.equal(ctx.orgNames.acme, 'Example & Co');
  assert.equal(elements.orgsel.options[0].textContent, 'Example & Co');
  assert.equal(elements['ws-rename-status'].textContent, 'Organization name saved.');
  assert.equal(elements['ws-rename'].disabled, false);

  let resolve;
  const switched = setup(url => url === '/api/portfolio'
    ? Promise.resolve({ok: true, json: async () => ({orgs: []})})
    : new Promise(r => { resolve = r; }));
  const pending = switched.ctx.saveOrgName({preventDefault() {}});
  assert.equal(switched.elements['ws-rename'].disabled, true);
  switched.ctx.currentOrg = 'beta';
  switched.ctx.refreshOrgNameField();
  resolve({ok: true, json: async () => ({slug: 'acme', name: '<script>name</script>'})});
  await pending;
  assert.equal(switched.ctx.orgNames.acme, '<script>name</script>');
  assert.equal(switched.elements.orgsel.options[0].textContent, '<script>name</script>');
  assert.equal(switched.ctx.orgNames.beta, 'Beta');
  assert.equal(switched.elements['ws-org-name'].value, 'Beta');
  assert.equal(switched.elements['ws-rename-status'].textContent, '');

  const failed = setup(async () => ({ok: false, json: async () => ({error: 'Could not save'})}));
  await failed.ctx.saveOrgName({preventDefault() {}});
  assert.equal(failed.ctx.orgNames.acme, 'Acme');
  assert.equal(failed.elements['ws-rename-status'].textContent, 'Could not save');
  assert.equal(failed.elements['ws-rename'].disabled, false);

  const blank = setup(() => { throw Error('Blank input must not make a request'); });
  blank.elements['ws-org-name'].value = '  ';
  await blank.ctx.saveOrgName({preventDefault() {}});
  assert.match(blank.elements['ws-rename-status'].textContent, /Enter an organization name/);

  const svgNode = {setAttribute() {}, addEventListener() {}};
  const el = {clientWidth: 520, innerHTML: '', querySelector: () => ({querySelector: () => svgNode})};
  ctx.drawTrend(el, [{score: 70, at: '2026-10-22'}, {score: 100, at: '2026-10-23', break_before: true}]);
  const series = el.innerHTML.match(/class="series" d="([^"]*)"/)[1];
  assert.equal((series.match(/M/g) || []).length, 2, 'A coverage gap must start a new path');
  assert(!series.includes('L'), 'Incomparable scores must not be joined');
  assert.match(el.innerHTML, /not directly comparable/);
  ctx.drawTrend(el, [{score: 70, at: '2026-10-22'}, {score: 80, at: '2026-10-23', break_before: false}]);
  assert.match(el.innerHTML.match(/class="series" d="([^"]*)"/)[1], /L/);
  assert(!html.match(/<input[^>]*id="login-user"[^>]*>/)[0].includes('value='));
  let loginResolve, loginCalls = 0;
  const signIn = setup((url, options) => {
    loginCalls++;
    assert.equal(url, '/api/login');
    assert.equal(Buffer.from(options.headers.Authorization.slice(6), 'base64').toString(), 'admin:local-login-test!');
    return new Promise(r => { loginResolve = r; });
  });
  const signingIn = signIn.ctx.doLogin();
  signIn.ctx.doLogin();
  assert.equal(loginCalls, 1, 'Duplicate clicks must not send extra login attempts');
  assert.equal(signIn.elements['login-btn'].disabled, true);
  loginResolve({ok: false, status: 429, headers: {get: () => '300'}, json: async () => ({})});
  await signingIn;
  assert.match(signIn.elements['login-msg'].textContent, /Wait 300 seconds/);
  assert.equal(signIn.elements['login-btn'].disabled, false);
  console.log('Dashboard rename, trend rendering and login checks passed');
}
run().catch(e => { console.error(e); process.exitCode = 1; });
