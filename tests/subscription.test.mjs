import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../workers.js', import.meta.url), 'utf8');
const token = 'subscription_test_token_1234567890';
const uuid = '11111111-1111-4111-8111-111111111111';

function harness(overrides = {}) {
  const context = vm.createContext({
    TextEncoder, TextDecoder, URL, URLSearchParams, Request, Response, Headers,
    ReadableStream, WritableStream, AbortController, atob, btoa,
    crypto: webcrypto, setTimeout, clearTimeout,
    console: { warn() {} },
    fetch: async () => new Response('', { status: 503 }),
  });
  vm.runInContext(source
    .replace("import { connect } from 'cloudflare:sockets';", 'const connect = () => { throw new Error("TCP disabled in tests"); };')
    .replace('export default {', 'globalThis.worker = {') + `
      globalThis.testing = {
        DEFAULT_CONFIG, PANEL_HTML, loginHTML, loadConfig, createSession,
        setQuota(value) { QUOTA_CACHE = value; }
      };
    `, context);
  const defaults = JSON.parse(JSON.stringify(context.testing.DEFAULT_CONFIG));
  const config = {
    ...defaults, uuid, path: 'panel', admin: 'test-password', enableTrojan: true,
    preferredDomains: '', preferredIPs: [{ ip: '104.16.128.11', port: 443, name: '香港 HK' }],
    ...overrides,
    optimizer: { ...defaults.optimizer, subMode: 'custom', ...overrides.optimizer },
    filter: { ...defaults.filter, ipType: ['IPv4'], ...overrides.filter },
  };
  const env = { SUB_TOKEN: token, K: { async get() { return JSON.stringify(config); } } };
  const request = (path = `/s/${token}/sub`, headers = {}) => context.worker.fetch(
    new Request(`https://example.com${path}`, { headers }), env, {},
  );
  const cookie = async () => 'luma_auth=' + await context.testing.createSession(await context.testing.loadConfig(env));
  return { context, config, request, cookie };
}

function vlessLines(body) {
  const lines = body.split('\n').filter(Boolean);
  assert.ok(lines.length > 0);
  for (const line of lines) assert.match(line, /^vless:\/\//);
  return lines.map(line => new URL(line));
}

test('all User-Agents and legacy query parameters receive plain VLESS', async () => {
  const h = harness();
  let expected;
  for (const agent of ['Mozilla/5.0', 'Clash', 'sing-box', 'Surge', 'Stash', 'Quantumult X']) {
    const response = await h.request(`/s/${token}/sub?format=clash`, { 'User-Agent': agent });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'text/plain; charset=utf-8');
    assert.equal(response.headers.get('Content-Disposition'), 'attachment; filename="cfnext-sub.txt"');
    const body = await response.text();
    const [node] = vlessLines(body);
    assert.equal(node.username, uuid);
    assert.equal(node.searchParams.get('host'), 'example.com');
    assert.equal(node.searchParams.get('path'), '/' + uuid);
    assert.equal(node.searchParams.get('security'), 'tls');
    assert.match(body, /香港/);
    expected ??= body;
    assert.equal(body, expected);
  }
});

test('WS and XHTTP remain VLESS, and Trojan does not consume the node limit', async () => {
  const h = harness({ enableXhttp: true, nodeLimitCount: 2 });
  const nodes = vlessLines(await (await h.request()).text());
  assert.equal(nodes.length, 2);
  assert.deepEqual(nodes.map(n => n.searchParams.get('type')), ['ws', 'xhttp']);
  assert.equal(nodes[1].searchParams.get('mode'), 'stream-one');
  assert.ok(JSON.parse(nodes[1].searchParams.get('extra')).xPaddingHeader);

  const xhttpOnly = harness({ enableVless: false, enableXhttp: true });
  assert.equal(vlessLines(await (await xhttpOnly.request()).text())[0].searchParams.get('type'), 'xhttp');
});

test('Trojan-only configuration returns an actionable subscription error', async () => {
  const h = harness({ enableVless: false, enableXhttp: false, enableTrojan: true });
  const response = await h.request();
  assert.equal(response.status, 400);
  assert.match((await response.json()).msg, /启用 VLESS/);
});

test('default, random, custom, and fallback paths only emit VLESS', async () => {
  for (const optimizer of [
    { subMode: '' }, { subMode: 'random' },
    { subMode: 'custom', subIncludeDefault: true }, { subMode: 'custom' },
  ]) {
    const h = harness({ preferredIPs: [], enableXhttp: true, nodeLimitCount: 7, optimizer });
    const response = await h.request();
    assert.equal(response.status, 200);
    assert.equal(vlessLines(await response.text()).length, 7);
  }
});

test('source URI credentials are not copied into the VLESS subscription', async () => {
  const h = harness({ preferredIPs: [], preferredDomains: 'https://source.example/nodes.txt' });
  h.context.fetch = async () => new Response('trojan://source-password@104.16.128.12:443#Tokyo JP');
  const response = await h.request();
  const body = await response.text();
  const nodes = vlessLines(body);
  assert.equal(nodes.length, 1);
  assert.equal(nodes[0].hostname, '104.16.128.12');
  assert.equal(nodes[0].username, uuid);
  assert.ok(!body.includes('source-password'));
});

test('IPv6 addresses and URI parameters survive plaintext output', async () => {
  const h = harness({
    host: 'sni.example', alpn: 'h2,http/1.1', ech: true,
    preferredIPs: [{ ip: '2606:4700::1111', port: 8443, name: '日本 #1' }],
    filter: { ipType: ['IPv6'] },
  });
  const [node] = vlessLines(await (await h.request()).text());
  assert.equal(node.hostname, '[2606:4700::1111]');
  assert.equal(node.port, '8443');
  assert.equal(node.searchParams.get('sni'), 'sni.example');
  assert.equal(node.searchParams.get('alpn'), 'h2,http/1.1');
  assert.ok(node.searchParams.get('ech'));
  assert.match(decodeURIComponent(node.hash), /日本 #1/);
});

test('client names no longer impose the removed 300-node format cap', async () => {
  const preferredIPs = Array.from({ length: 850 }, (_, i) => ({
    ip: `104.16.${Math.floor(i / 256)}.${i % 256}`, port: 443, name: `node-${i}`,
  }));
  const h = harness({ preferredIPs, nodeLimit: false });
  assert.equal(vlessLines(await (await h.request(undefined, { 'User-Agent': 'Clash' })).text()).length, 800);
  const limited = harness({ preferredIPs, nodeLimitCount: 350 });
  assert.equal(vlessLines(await (await limited.request(undefined, { 'User-Agent': 'sing-box' })).text()).length, 350);
});

test('canonical token, alias, and authenticated panel routes retain authorization', async () => {
  const h = harness({ subUrl: 'feed' });
  assert.equal((await h.request('/s/wrong/sub')).status, 403);
  assert.equal((await h.request('/feed/sub')).status, 403);
  assert.equal((await h.request('/panel/sub')).status, 403);
  const body = await (await h.request()).text();
  assert.equal(await (await h.request(`/feed/sub?token=${token}`)).text(), body);
  assert.equal(await (await h.request('/panel/sub', { Cookie: await h.cookie() })).text(), body);
  for (const path of [`/s/${token}/sub/clash`, `/s/${token}/sub/plain`, `/feed/sub/singbox`, '/panel/sub/surge']) {
    assert.equal((await h.request(path, { Cookie: await h.cookie() })).status, 404);
  }
});

test('preview uses the same rotation and quota policy as the subscription', async () => {
  const h = harness({
    polling: true, quotaAuto: true, cfAccountId: 'test-account', nodeLimitCount: 100,
    preferredIPs: Array.from({ length: 100 }, (_, i) => ({ ip: `104.16.0.${i}`, port: 443, name: `node-${i}` })),
  });
  h.context.testing.setQuota({ at: Date.now(), accountId: 'test-account', data: {
    updatedAt: new Date().toISOString(), today: { requests: 96000 }, percent: 96,
  } });
  const headers = { Cookie: await h.cookie(), 'User-Agent': 'same-client' };
  const response = await h.request('/panel/api/sub', headers);
  const preview = await response.json();
  const body = await (await h.request(undefined, headers)).text();
  assert.equal(preview.ok, true);
  assert.equal(preview.type, 'text/plain');
  assert.equal(preview.body, body);
  assert.equal(preview.nodeCount, 30);
  assert.equal(vlessLines(body).length, preview.nodeCount);
  assert.equal((await h.request('/panel/api/sub')).status, 403);
});

test('panel scripts parse and subscription controls use a single canonical URL', async () => {
  const h = harness();
  const html = h.context.testing.PANEL_HTML;
  assert.ok(!html.includes('subFmt'));
  assert.ok(!html.includes('install-config'));
  for (const page of [html, h.context.testing.loginHTML]) {
    for (const match of page.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
  }
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: '', style: {}, textContent: '' });
    return elements.get(id);
  };
  const downloads = [], qr = [], calls = [], copied = [];
  const ui = vm.createContext({
    CFG: { subToken: token, subUrl: '' }, location: { origin: 'https://example.com' },
    $: element, encodeURIComponent,
    copyText: value => copied.push(value),
    api: async path => { calls.push(path); return { ok: true, body: 'vless://example', nodeCount: 1 }; },
    qrcode: () => ({ addData: value => qr.push(value), make() {}, createImgTag: () => '<img>' }),
    document: { body: { appendChild() {} }, createElement: () => ({
      click() { downloads.push({ href: this.href, download: this.download }); }, remove() {},
    }) },
  });
  const block = html.slice(html.indexOf('function subUrlOf(){'), html.indexOf('/* ===== 优选配置 ===== */'));
  vm.runInContext(block + '\n' + html.match(/function copySub\(\)\{[^\n]+/)[0], ui);
  const url = `https://example.com/s/${token}/sub`;
  ui.copySub();
  assert.equal(copied[0], url);
  assert.equal(element('subUrl').value, url);
  ui.toggleQR();
  ui.downloadSub();
  assert.equal(qr[0], url);
  assert.deepEqual(downloads[0], { href: url, download: 'cfnext-sub.txt' });
  ui.CFG.subUrl = 'feed';
  ui.makeSub();
  assert.equal(qr.at(-1), `https://example.com/feed/sub?token=${token}`);
  ui.previewSub();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['sub']);
  assert.equal(element('prevType').textContent, '明文 VLESS');
  assert.equal(element('prevCount').textContent, '1 个节点');
});
