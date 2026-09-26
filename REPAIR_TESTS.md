# 2.0.1 可重复回归测试

测试日期：2026-09-26。验证环境：Node.js 24.19.0、Miniflare 4.20260730.0、compatibility date 2026-08-01。

仓库按要求只保留一个主脚本。测试程序收录为本文代码块，执行时提取到临时目录；依赖和产物不进入 Git。测试中的 UUID、密码和目标地址都是虚构数据。协议参考使用 Node crypto，网络/KV 使用内存替身或 Miniflare，本测试不访问生产部署。

覆盖结果：29 项基础功能/鉴权/预算/配置检查，5 组独立 SS/SOCKS5/HTTPS CONNECT 检查，11 项 workerd 检查。另经浏览器人工自动化验证登录、保存、默认 300 条订阅预览，以及敏感字段脱敏和环境变量锁定状态。

以下验证没有覆盖真实客户端版本兼容、真实代理服务、Cloudflare 账户 Analytics 权限、生产 CPU 上限或并发容量。外部源失败时的回退测试不构成任何 IP 可达性保证。

## 执行

在仓库根目录，使用 Node.js 24 与 Python 3：

```sh
export CFNEXT_ROOT="$PWD"
test_dir=$(mktemp -d /tmp/cfnext-tests.XXXXXX)
python3 - "$test_dir" <<'PYTHON'
import pathlib, re, sys
text = pathlib.Path('REPAIR_TESTS.md').read_text()
for name, code in re.findall(r'### ([\w-]+\.cjs)\n\n```javascript\n(.*?)\n```', text, re.S):
    pathlib.Path(sys.argv[1], name).write_text(code + '\n')
PYTHON
npm install --prefix "$test_dir" --cache "$test_dir/npm-cache" --no-audit --no-fund miniflare@4.20260730.0
node --input-type=module --check < workers.js
node "$test_dir/check.cjs"
node "$test_dir/protocol.cjs"
node "$test_dir/runtime.cjs"
```

如果包管理器禁止官方 workerd 安装脚本，请按本地包管理器策略安装其对应平台二进制；不要把运行时启动失败当作脚本测试通过。测试正常结束分别输出 `TOTAL 29 checks passed`、`PROTOCOL PASSED`、`RUNTIME PASSED`。

## 测试程序

### check.cjs

```javascript
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const source=fs.readFileSync(require('node:path').resolve(process.env.CFNEXT_ROOT || process.cwd(),'workers.js'),'utf8');
const U='11111111-1111-4111-8111-111111111111',ADMIN='local-test-password-123';
function make(){
 const c=vm.createContext({TextEncoder,TextDecoder,URL,URLSearchParams,Request,Response,Headers,ReadableStream,WritableStream,AbortController,AbortSignal,crypto:crypto.webcrypto,atob,btoa,setTimeout,clearTimeout,console:{warn(){}},fetch:async()=>{throw Error('network disabled')},connect:()=>{throw Error('network disabled')}});
 vm.runInContext(source.replace("import { connect } from 'cloudflare:sockets';",'').replace('export default {','globalThis.worker = {')+'\nglobalThis.t={loadConfig,requireAuth,createSession,generateSubscription,generateSurfboard,sha224hex,authenticateProxy,parseVlessHeader,parseTrojanHeader,resolvePreferredDomains,createIO,fetchTimeout,signValue,ssMasterKey,newSsAead,connectViaShadowsocks,parseProxyAddress,handleXhttpProxy,validateConfig,DEFAULT_CONFIG,DEFAULT_PREFERRED_DOMAINS,PANEL_HTML,loginHTML};',c);
 return c;
}
let count=0;function ok(name){count++;console.log('PASS '+name);}
const req=(path,options={})=>new Request('https://unit.invalid'+path,options);
const packet=(wrong=false)=>new Uint8Array([0,...Buffer.from((wrong?'0'.repeat(32):U.replaceAll('-','')),'hex'),0,1,1,187,2,3,97,98,99,65,66]);
(async()=>{
 let c=make(),t=c.t;
 const env={U,ADMIN};const cfg=await t.loadConfig(env);
 assert.equal((await c.worker.fetch(req('/version'),{},{})).status,200);ok('version does not require config or KV');
 let res=await c.worker.fetch(req('/'),env,{});assert.equal(res.status,404);assert.equal(res.headers.get('location'),null);ok('root does not disclose path');
 assert.equal((await c.worker.fetch(req('/'+U+'/api/config'),env,{})).status,403);
 assert.equal((await c.worker.fetch(req('/'+U+'/api/config'),{U},{})).status,403);ok('management fails closed without login or ADMIN');
 const cookie='luma_auth='+await t.createSession(cfg);
 assert.equal(await t.requireAuth(req('/',{headers:{cookie}}),cfg),true);
 assert.equal(await t.requireAuth(req('/',{headers:{cookie:cookie+'x'}}),cfg),false);
 const changed={...cfg,admin:'a-new-password'};assert.equal(await t.requireAuth(req('/',{headers:{cookie}}),changed),false);
 const payload='1700000000.'+U,signature=await t.signValue(cfg._sessionKey,'CFNext/session/v1|'+cfg.admin+'|'+payload);
 assert.equal(await t.requireAuth(req('/',{headers:{cookie:'luma_auth='+payload+'.'+signature}}),cfg),false);ok('signed sessions reject tamper expiry and password rotation');
 res=await c.worker.fetch(req('/login',{method:'POST',body:'password='+ADMIN+'&next=https://evil.invalid'}),env,{});
 assert.equal(res.status,200);assert.equal((await res.json()).next,'/'+U);ok('login uses signed cookie and safe local redirect');
 res=await c.worker.fetch(req('/'+U+'/api/config',{headers:{cookie}}),env,{});let data=(await res.json()).data;
 assert.equal(data.admin,'');assert.equal(data.secretConfigured.admin,true);assert.ok(data.subToken.length>=32);ok('config redacts stored credentials');
 res=await c.worker.fetch(req('/'+U+'/api/config',{method:'POST',headers:{cookie,'content-type':'application/json'},body:'{}'}),env,{});assert.equal(res.status,503);ok('save without KV is an error');
 let failEnv={U,ADMIN,K:{get:async()=>{throw Error('KV unavailable')}}};assert.equal((await c.worker.fetch(req('/'+U+'/api/config',{headers:{cookie}}),failEnv,{})).status,503);ok('KV read failure closes management');
 let store=null,puts=0;const kv={get:async()=>store,put:async(k,v)=>{puts++;store=v}};const savedEnv={U,ADMIN,K:kv};
 res=await c.worker.fetch(req('/'+U+'/api/config',{method:'POST',headers:{cookie,'content-type':'application/json'},body:JSON.stringify({admin:'',cfApiToken:'sensitive',subUrl:'public-alias'})}),savedEnv,{});assert.equal(res.status,200);
 res=await c.worker.fetch(req('/'+U+'/api/config',{method:'POST',headers:{cookie,'content-type':'application/json'},body:JSON.stringify({cfApiToken:''})}),savedEnv,{});assert.equal(res.status,200);assert.equal(JSON.parse(store).cfApiToken,'sensitive');ok('blank secrets preserve values; saving respects env priority');
 assert.equal((await c.worker.fetch(req('/public-alias/api/config',{headers:{cookie}}),savedEnv,{})).status,404);
 assert.equal((await c.worker.fetch(req('/'+U+'/sub'),savedEnv,{})).status,403);ok('subscription alias cannot access management; old unauthenticated subscription denied');
 assert.equal((await c.worker.fetch(req('/'+U+'/api/reset',{method:'POST',headers:{cookie,Origin:'https://evil.invalid'}}),savedEnv,{})).status,403);ok('cross-origin write rejected');
 const envProbe={U,ADMIN,PROBE_ALIVE:'0',K:{get:async()=>JSON.stringify({probeAlive:true})}};assert.equal((await t.loadConfig(envProbe)).probeAlive,false);ok('environment probe override survives KV');
 assert.throws(()=>t.authenticateProxy(t.parseVlessHeader(packet(true)),cfg,'vless'));
 assert.doesNotThrow(()=>t.authenticateProxy(t.parseVlessHeader(packet()),cfg,'vless'));
 assert.throws(()=>t.authenticateProxy(t.parseVlessHeader(packet()),{...cfg,enableVless:false},'vless'));ok('VLESS UUID and enable switch validated');
 assert.throws(()=>t.parseVlessHeader(packet().slice(0,24)),/头部过短/);ok('truncated domain is incomplete, never accepted');
 const tp=new Uint8Array([...Buffer.from('0'.repeat(56)+'\r\n'),1,1,1,2,3,4,1,187,13,10]);assert.throws(()=>t.authenticateProxy(t.parseTrojanHeader(tp),{...cfg,enableTrojan:true,trojanPassword:'different'},'trojan'));ok('wrong Trojan password rejected');
 c.calls=0;vm.runInContext('openOutbound=async()=>{calls++;return {writable:new WritableStream({write(){}}),readable:new ReadableStream({start(c){c.enqueue(new Uint8Array([42]));c.close()}}),close(){}}}',c);
 const chunked=new ReadableStream({start(ctrl){const p=packet();ctrl.enqueue(p.slice(0,3));ctrl.enqueue(p.slice(3,24));ctrl.enqueue(p.slice(24));ctrl.close();}});
 res=await t.handleXhttpProxy(req('/'+U,{method:'POST',body:chunked,duplex:'half'}),{...cfg,enableXhttp:true});assert.deepEqual([...new Uint8Array(await res.arrayBuffer())],[0,0,42]);assert.equal(c.calls,1);
 await assert.rejects(t.handleXhttpProxy(req('/'+U,{method:'POST',body:packet(true)}),{...cfg,enableXhttp:true}));assert.equal(c.calls,1);ok('fragmented XHTTP works and invalid identity creates no connection');
 c=make();t=c.t;let fetches=0,active=0,peak=0;
 c.fetch=async(url)=>{fetches++;active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,1));active--;const v6=new URL(url).searchParams.get('type')==='AAAA';return new Response(JSON.stringify({Status:0,Answer:[{type:v6?28:1,data:v6?'2606:4700::1':'104.16.0.1'}]}));};
 let io=t.createIO();await t.resolvePreferredDomains(t.DEFAULT_PREFERRED_DOMAINS,40,240,false,true,true,io);assert.equal(fetches,26);assert.ok(peak<=4);ok('13 domains use 26 fetches, concurrency <=4');
 let items=await t.resolvePreferredDomains('unit.example',40,240,false,true,false,t.createIO());items=await t.resolvePreferredDomains('unit.example',40,240,false,true,true,t.createIO());assert.ok(items.some(x=>x.ip.includes(':')));ok('DNS cache separates IPv4 and IPv6 modes');
 io=t.createIO();fetches=0;await Promise.all(Array.from({length:60},(_,i)=>t.fetchTimeout('https://budget.invalid/'+i,{},1000,io)));assert.equal(fetches,40);ok('all requests enforce 40 fetch budget');
 c.fetch=async()=>new Response(new Uint8Array(1024*1024+1));assert.equal(await t.fetchTimeout('https://large.invalid',{},1000,t.createIO()),null);ok('oversized upstream body rejected');
 c.fetch=async()=>new Response(new ReadableStream({start(){}}));let before=Date.now();assert.equal(await t.fetchTimeout('https://slow.invalid',{},20,t.createIO()),null);assert.ok(Date.now()-before<1000);ok('slow body deadline enforced after response headers');
 // Independent Node crypto reference, not self-encrypt/self-decrypt.
 for(const [method,len,nodeName] of [['AES-GCM',16,'aes-128-gcm'],['AES-GCM',32,'aes-256-gcm'],['CHACHA20-POLY1305',32,'chacha20-poly1305']]){
  const key=crypto.randomBytes(len),aead=await t.newSsAead(method,key);
  for(let n=0;n<3;n++){
   const plain=Buffer.from('payload-'+n),box=Buffer.from(await aead.seal(plain)),iv=Buffer.alloc(12);iv[0]=n;
   const dec=crypto.createDecipheriv(nodeName,key,iv,{authTagLength:16});dec.setAuthTag(box.subarray(-16));const out=Buffer.concat([dec.update(box.subarray(0,-16)),dec.final()]);assert.deepEqual(out,plain);
  }
 }ok('all SS AEAD algorithms match independent Node crypto including nonce progression');
 let expected=Buffer.alloc(0),prev=Buffer.alloc(0);while(expected.length<32){prev=crypto.createHash('md5').update(Buffer.concat([prev,Buffer.from('p@ss中文')])).digest();expected=Buffer.concat([expected,prev]);}assert.deepEqual(Buffer.from(t.ssMasterKey('p@ss中文',32)),expected.subarray(0,32));ok('SS EVP_BytesToKey matches independent reference');
 // UI inline scripts must parse independently of outer template literals.
 for(const html of [t.PANEL_HTML,t.loginHTML])for(const match of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))new vm.Script(match[1]);ok('panel and login inline JavaScript syntax');

 c=make();t=c.t;
 assert.equal(t.sha224hex('test-中文'),crypto.createHash('sha224').update('test-中文').digest('hex'));ok('Trojan SHA224 matches independent implementation');
 const scfg=await t.loadConfig({U,ADMIN});
 for(const bad of [{preferredIPs:[{ip:'not-an-ip'}]},{filter:null},{src:[]},{optimizer:{...scfg.optimizer,subMode:'invalid'}}])assert.throws(()=>t.validateConfig({...scfg,...bad}));ok('malformed nested configuration rejected');
 assert.throws(()=>t.generateSurfboard({...scfg,enableTrojan:false},[]));
 const surf=t.generateSurfboard({...scfg,host:'unit.invalid',enableTrojan:true,trojanPassword:'custom-password'},['vless://'+U+'@104.16.0.1:443?security=tls&type=ws#Test']);assert.ok(surf.includes('password=custom-password'));assert.ok(surf.includes('skip-cert-verify=false'));ok('Surfboard requires enabled Trojan and uses actual credential');
 c.fetch=async()=>new Response('',{status:503});
 const big={...scfg,probeAlive:false,polling:false,nodeLimitCount:800,src:{prefDomain:false,prefIp:true,native:true},_io:t.createIO()};
 const plain=await t.generateSubscription(big,'https://unit.invalid','plain','',null,{});assert.ok(plain.body.split('\n').length<=800);
 const sb=await t.generateSubscription({...big,_io:t.createIO()},'https://unit.invalid','singbox','',null,{});assert.ok(JSON.parse(sb.body).outbounds.filter(x=>['vless','trojan'].includes(x.type)).length<=300);ok('plain and structured caps survive polling disabled');
 let subPuts=0;const ke={U,ADMIN,K:{get:async()=>JSON.stringify({src:{native:true,prefDomain:false,prefIp:false},nodeLimitCount:5}),put:async()=>{subPuts++}}};const subCfg=await t.loadConfig(ke);
 for(let i=0;i<2;i++)assert.equal((await c.worker.fetch(req('/s/'+subCfg.subToken+'/sub/plain'),ke,{})).status,200);assert.equal(subPuts,0);ok('subscription refresh never writes KV');
 console.log('TOTAL '+count+' checks passed');
})().catch(e=>{console.error(e);process.exitCode=1});
```

### protocol.cjs

```javascript
const fs=require('fs'),vm=require('vm'),crypto=require('crypto'),assert=require('assert/strict');
let base=fs.readFileSync(require('node:path').join(__dirname,'check.cjs'),'utf8').split('(async()=>{')[0].replace('const fs=require','var fs=require').replace('function make()','function make()').replace('validateConfig,DEFAULT_CONFIG','connectViaSocks5,connectViaHttpProxy,generateSurfboard,validateConfig,DEFAULT_CONFIG');
const ctx={require,process,TextEncoder,TextDecoder,URL,URLSearchParams,Request,Response,Headers,ReadableStream,WritableStream,AbortController,AbortSignal,atob,btoa,setTimeout,clearTimeout,console,Buffer};vm.createContext(ctx);vm.runInContext(base+'\nglobalThis.make=make',ctx);
(async()=>{
for(const [method,keyLen] of [['aes-128-gcm',16],['aes-256-gcm',32],['chacha20-ietf-poly1305',32]]){
 const c=ctx.make(), writes=[];let ctrl,closed=false;c.socket={opened:Promise.resolve(),closed:new Promise(()=>{}),writable:new WritableStream({write(v){writes.push(Buffer.from(v));}}),readable:new ReadableStream({start(x){ctrl=x;}}),close(){closed=true;try{ctrl.close()}catch{}}};c.connect=()=>c.socket;
 const target={hostname:'example.org',port:443};const ss=await c.t.connectViaShadowsocks({host:'proxy.invalid',port:8388,method,password:'sample'},target);
 let master=Buffer.alloc(0),prev=Buffer.alloc(0);while(master.length<keyLen){prev=crypto.createHash('md5').update(Buffer.concat([prev,Buffer.from('sample')])).digest();master=Buffer.concat([master,prev]);}master=master.subarray(0,keyLen);
 const salt=writes[0];assert.equal(salt.length,keyLen);const key=Buffer.from(crypto.hkdfSync('sha1',master,salt,'ss-subkey',keyLen));let nonce=0;
 const dec=box=>{const iv=Buffer.alloc(12);iv.writeUInt32LE(nonce++);const d=crypto.createDecipheriv(method==='chacha20-ietf-poly1305'?'chacha20-poly1305':method,key,iv,{authTagLength:16});d.setAuthTag(box.subarray(-16));return Buffer.concat([d.update(box.subarray(0,-16)),d.final()]);};
 const first=writes[1];let len=dec(first.subarray(0,18)).readUInt16BE();assert.deepEqual(dec(first.subarray(18)),Buffer.from([3,11,...Buffer.from('example.org'),1,187]));assert.equal(len,15);
 const w=ss.writable.getWriter();await w.write(new Uint8Array(20000).fill(42));assert.equal(writes.length,4);let total=0;for(const frame of writes.slice(2)){let n=dec(frame.subarray(0,18)).readUInt16BE();assert.ok(n<=16383);assert.equal(dec(frame.subarray(18)).length,n);total+=n;}assert.equal(total,20000);
 const rsalt=crypto.randomBytes(keyLen),rkey=Buffer.from(crypto.hkdfSync('sha1',master,rsalt,'ss-subkey',keyLen));let rn=0;
 const enc=data=>{const iv=Buffer.alloc(12);iv.writeUInt32LE(rn++);const e=crypto.createCipheriv(method==='chacha20-ietf-poly1305'?'chacha20-poly1305':method,rkey,iv,{authTagLength:16});return Buffer.concat([e.update(data),e.final(),e.getAuthTag()]);};
 const reply=Buffer.concat([rsalt,enc(Buffer.from([0,5])),enc(Buffer.from('reply'))]);for(let i=0;i<reply.length;i+=3)ctrl.enqueue(new Uint8Array(reply.subarray(i,i+3)));
 const r=ss.readable.getReader();assert.equal(Buffer.from((await r.read()).value).toString(),'reply');await r.cancel();assert.equal(closed,true);w.releaseLock();console.log('PASS independent SS framing, address, fragmentation, cleanup: '+method);
}
for(const type of ['socks5','https']){
 const c=ctx.make(),writes=[];let opts;c.connect=(addr,o)=>{opts=o;return {opened:Promise.resolve(),closed:new Promise(()=>{}),writable:new WritableStream({write(v){writes.push(Buffer.from(v))}}),readable:new ReadableStream({start(x){x.enqueue(type==='https'?new TextEncoder().encode('HTTP/1.1 200 OK\r\n\r\nearly'):new Uint8Array([5,0,5,0,0,1,0,0,0,0,0,0,42]));}}),close(){}}};
 const sock=await (type==='https'?c.t.connectViaHttpProxy:c.t.connectViaSocks5)({type,host:'proxy.invalid',port:443},{hostname:'2001:db8::1',port:443});assert.ok(sock._preamble.length);assert.equal(opts.secureTransport,type==='https'?'on':'off');if(type==='https')assert.ok(writes[0].toString().startsWith('CONNECT [2001:db8::1]:443 '));else assert.equal(writes[1][3],4);console.log('PASS '+type+' IPv6, early bytes and transport options');
}
console.log('PROTOCOL PASSED');
})().catch(e=>{console.error(e);process.exitCode=1;});
```

### runtime.cjs

```javascript
const {Miniflare}=require('miniflare');const assert=require('node:assert/strict');
(async()=>{const mf=new Miniflare({cf:false,workers:[{name:"test",modules:true,scriptPath:require('node:path').resolve(process.env.CFNEXT_ROOT || process.cwd(),'workers.js'),compatibilityDate:'2026-08-01',bindings:{U:'11111111-1111-4111-8111-111111111111',ADMIN:'local-test-password-123'},kvNamespaces:['K'],outboundService:async()=>new Response('',{status:503})}]});
try{
 let r=await mf.dispatchFetch('https://unit.invalid/version');assert.equal(r.status,200);console.log('PASS workerd module boots',await r.text());
 r=await mf.dispatchFetch('https://unit.invalid/login',{method:'POST',body:'password=local-test-password-123'});assert.equal(r.status,200);const cookie=r.headers.get('set-cookie').split(';')[0];
 const url='https://unit.invalid/11111111-1111-4111-8111-111111111111';
 r=await mf.dispatchFetch(url+'/api/config',{headers:{cookie}});assert.equal(r.status,200);const cfg=(await r.json()).data;assert.equal(cfg.admin,'');console.log('PASS workerd login / KV / redacted config');
 r=await mf.dispatchFetch(url+'/api/config',{method:'POST',headers:{cookie,'content-type':'application/json'},body:JSON.stringify({src:{native:true,prefDomain:false,prefIp:false,customPref:false},nodeLimitCount:5})});assert.equal(r.status,200);console.log('PASS workerd KV configuration save');
 for(const format of ['plain','clash','singbox','surge','loon','quanx']){r=await mf.dispatchFetch('https://unit.invalid/s/'+cfg.subToken+'/sub/'+format);assert.equal(r.status,200,format+' '+await r.clone().text());const body=await r.text();assert.ok(body.length>50);if(format==='singbox')JSON.parse(body);console.log('PASS workerd subscription '+format);}
 r=await mf.dispatchFetch(url,{headers:{Upgrade:'websocket'}});assert.equal(r.status,101);const ws=r.webSocket;ws.accept();let closed=new Promise(resolve=>ws.addEventListener('close',resolve));ws.send(new Uint8Array([0,...new Uint8Array(16),0,1,1,187,1,1,1,1,1]));await Promise.race([closed,new Promise((_,reject)=>setTimeout(()=>reject(Error('WS not closed')),3000))]);console.log('PASS workerd invalid UUID WebSocket closes');

 r=await mf.dispatchFetch(url,{headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':Buffer.from([0,...new Uint8Array(16),0,1,1,187,1,1,1,1,1]).toString('base64url')}});assert.equal(r.status,101);const ew=r.webSocket;ew.accept();await Promise.race([new Promise(resolve=>ew.addEventListener('close',resolve)),new Promise((_,reject)=>setTimeout(()=>reject(Error('early data ignored')),3000))]);console.log('PASS workerd WebSocket early data authenticates and rejects invalid UUID');
 console.log('RUNTIME PASSED');
}finally{await mf.dispose();}})().catch(e=>{console.error(e);process.exitCode=1;});
```

