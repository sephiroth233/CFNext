//  === 面板集成：CFNext 新界面（独立设计）+ 配额安全（CF 用量监控）===
// ============================================================================
//  CFNext —— Cloudflare 代理管理面板 · 全新独立编写
//  ----------------------------------------------------------------------------
//  环境变量：
//    U            VLESS UUID（必填，同时用作面板访问路径，除非设置了 D）
//    D / PATH     自定义面板路径（可选）
//    ADMIN        管理面板必需的密码，建议使用 Secret（未设置则关闭管理面板）
//    HOST         自定义 SNI/Host（可选，默认使用 Worker 域名）
//    PROXYIP      自定义反代/落地 IP（可选，填写后作为固定出口优先使用；留空则直连失败时由内置地区反代兜底，格式 host 或 host:port）
//    S / OUTBOUND 出站代理（可选，socks5:// / http:// / ss:// 或 host:port）
//    ECH          设为 true/1 开启 ECH 加密（可选）
//    TROJAN       设为 true/1 开启 Trojan 协议（可选）
//    TROJAN_PASSWORD  Trojan 独立密码（留空时使用 UUID）
//    ALPN         自定义 ALPN 协商（可选）
//    YX           自定义优选 IP 列表（可选，格式 IP:port#名称，逗号分隔）
//    YXURL        优选器自定义数据源 URL（可选）
//    SUB_TOKEN    独立订阅令牌（32–128 位安全字符；未设置则由 UUID 派生）
//    SESSION_SECRET 会话签名密钥（可选，默认 ADMIN）；UPDATE_REPO 显式启用更新检查
//    CF_ACCOUNT_ID CF 账户监控：账户 ID（可选，与 CF_API_TOKEN 同时设置后可在面板查看当日用量）
//    CF_API_TOKEN  CF 账户监控：API 令牌（可选，需 Workers 用量分析读取权限，如 Account Analytics 读权限）
//    K            已绑定 KV 命名空间时读取图形化配置
//    RELAY_EXIT_PROBE  设为 0/false 关闭节点名里的地点后缀（可选；后缀按优选源国家码/机房码生成）
// ============================================================================
import { connect } from 'cloudflare:sockets';

const VERSION = '2.0.4';

const DEPLOY_EDITION = '明文版';
function deployKind() { return 'plain'; }
const UPDATE_CACHE = new Map();


function parseVer(v){
  const m = String(v || '').match(/(\d+)\.(\d+)\.(\d+)/);
  return m ? [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)] : null;
}
function cmpVer(a, b){
  const A = parseVer(a), B = parseVer(b);
  if (!A || !B) return 0;
  for (let i = 0; i < 3; i++){ if (A[i] !== B[i]) return A[i] < B[i] ? -1 : 1; }
  return 0;
}
function extractVersion(txt){
  // 版本号与 CFNext 源码同一位置：const VERSION = 'x.y.z ...'
  const m = txt.match(/const\s+VERSION\s*=\s*['"]([^'"]+)['"]/);
  return m ? m[1] : null;
}
async function checkUpdate(env) {
  const repo = String(env.UPDATE_REPO || '').trim();
  const branch = String(env.UPDATE_BRANCH || 'main');
  const file = String(env.UPDATE_FILE || 'workers.js');
  const base = { current: VERSION, kind: '明文', latest: null, hasUpdate: false, code: '' };
  if (!repo) return { ...base, error: '未配置 UPDATE_REPO，更新检测已关闭' };
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return { ...base, error: 'UPDATE_REPO 格式应为 owner/repo' };
  const url = 'https://raw.githubusercontent.com/' + repo + '/' + encodeURIComponent(branch) + '/' + file.split('/').map(encodeURIComponent).join('/');
  const cached = UPDATE_CACHE.get(url);
  if (cached && Date.now() - cached.at < 60000) return cached.data;
  try {
    const res = await fetchTimeout(url, {}, 6000, env._io);
    if (!res || !res.ok) throw new Error('更新来源不可用');
    const code = await res.text(), latest = extractVersion(code);
    if (!latest) throw new Error('更新来源缺少版本号');
    const data = { ...base, latest, hasUpdate: cmpVer(latest, VERSION) > 0, code, checkedAt: Date.now() };
    boundedSet(UPDATE_CACHE, url, { at: Date.now(), data }, 4);
    return data;
  } catch { return { ...base, error: '更新检测失败，请检查配置的仓库、分支和文件' }; }
}

const CLASH_TEMPLATE = `
# ==================== 锚点配置 ====================
# 代理提供者模板 - 订阅源基础配置

# 节点筛选正则表达式 - 仅保留常用地区
FilterHK: &FilterHK '^(?=.*(?i)(港|🇭🇰|HK|Hong|HKG))(?!.*5x).*$'
FilterSG: &FilterSG '^(?=.*(?i)(坡|🇸🇬|SG|Sing|SIN|XSP))(?!.*5x).*$'
FilterJP: &FilterJP '^(?=.*(?i)(日|🇯🇵|JP|Japan|NRT|HND|KIX|CTS|FUK))(?!.*(尼日利亚|5x)).*$'
FilterUS: &FilterUS '^(?=.*(?i)(美|🇺🇸|US|USA|JFK|SJC|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD))(?!.*(Plus|Australia|5x)).*$'
# 注意：🇼🇸 是萨摩亚旗帜，不是台湾，已移除，避免误匹配
FilterTW: &FilterTW '^(?=.*(?i)(台|🇹🇼|TW|tai|TPE|TSA|KHH))(?!.*5x).*$'

# ==================== 监听器 ====================
listeners:
  # Shadowsocks监听器 - 远程连接家庭网络，端口和密码使用时请修改（默认密码请勿用于公网）
  - {name: SS-IN,  type: shadowsocks, listen: '::', port: 10000, udp: true, password: Xf3#Lp9WqZ, cipher: aes-256-gcm}
  # Mixed监听器 - 分地区专用端口 玩法：本地浏览器插件或手机APP配置代理，实现分地区访问
  - {name: MIXED-SG, type: mixed, port: 50000, proxy: 新加坡节点}
  - {name: MIXED-US, type: mixed, port: 50001, proxy: 美国节点}
  - {name: MIXED-TW, type: mixed, port: 50002, proxy: 台湾节点}
  - {name: MIXED-HK, type: mixed, port: 50003, proxy: 香港节点}
  - {name: MIXED-JP, type: mixed, port: 50004, proxy: 日本节点}
  - {name: MIXED-AL, type: mixed, port: 50007, proxy: 一键连接}

# ==================== 核心配置 ====================
mode: rule
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: true
allow-lan: true
unified-delay: true
tcp-concurrent: true
log-level: warning
bind-address: '*'
find-process-mode: 'always'
keep-alive-interval: 15
keep-alive-idle: 600

# 认证配置（默认凭据请务必修改！）
authentication:
  - mihomo:yyds666
skip-auth-prefixes:
  - 192.168.1.0/24
  - 192.168.31.0/24
  - 192.168.100.0/24
  - 127.0.0.1/8

# 实验性功能
experimental:
  quic-go-disable-gso: true

# 管理面板配置
external-ui-url: https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip
external-ui-name: zashboard
external-ui: ui
external-controller: 127.0.0.1:9090
secret: yyds666    # 请修改为自定义密钥
# 允许网页面板跨域访问
external-controller-cors:
  allow-origins:
    - "*"
  allow-private-network: true

# 配置存储
profile:
  store-selected: true
  store-fake-ip: true

# 流量嗅探
sniffer:
  enable: true
  force-dns-mapping: true   # 强制 DNS 映射，提高分流准确度
  parse-pure-ip: true       # 解析纯 IP 连接
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "+.push.apple.com"

# TUN模式配置
tun:
  enable: false
  stack: mixed
  mtu: 1480
  dns-hijack:
    - "any:53"
    - "tcp://any:53"
  udp-timeout: 300
  auto-route: true
  strict-route: true
  auto-redirect: true
  auto-detect-interface: true
  # 提示：系统级防泄露的最强手段是开启 TUN（自动劫持全部 DNS 流量）；
  # 不开 TUN 时，请把系统 / LAN 设备的 DNS 指向 127.0.0.1:53（本机）或本机局域网 IP:53。

hosts:
  miwifi.com: 192.168.31.2
  "epdg.epc.mnc010.mcc234.pub.3gppnetwork.org": [87.194.8.8, 87.194.88.8, 87.194.89.8, 87.194.9.8]
  services.googleapis.cn: services.googleapis.com
  cn.bing.com: www4.bing.com

# ==================== DNS 配置 ====================
# 防泄露要点：
#   1) respect-rules: true：DNS 服务器连接遵循路由规则（国外 DoH 走代理隧道、国内 DoH 直连），
#      解析行为与规则分流一致，避免“规则走代理、解析却直连”的泄露。
#   2) 默认 nameserver 用国内 DoH；只有“将走代理”的规则集才用国外 DoH，
#      且其域名在 rules 中显式固定走代理。
#   3) fake-ip-filter 补齐系统连通性检测 / 时间同步 / 运营商登录等域名，防止系统误判断网而回退运营商 DNS。
dns:
  enable: true
  listen: 0.0.0.0:53        # 本机 / LAN 设备可把 DNS 指向此地址，避免走运营商 DNS
  ipv6: true
  prefer-h3: false          # respect-rules 下官方不推荐 DoH3；且 QUIC 已被规则拦截
  cache-algorithm: arc      # 性能更优的 ARC 缓存算法
  cache-size: 4096
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "+.lan"
    - "+.local"
    - "+.localhost"
    - "+.home.arpa"
    - "+.internal"
    # 系统连通性检测（防止 fake-ip 导致“无网络”判断，回退 ISP DNS 造成泄露）
    - "+.msftconnecttest.com"
    - "+.msftncsi.com"          # 通配已覆盖 dns.msftncsi.com
    - "captive.apple.com"
    - "connectivitycheck.gstatic.com"
    - "detectportal.firefox.com"
    # 时间同步
    - "time.nist.gov"
    - "+.pool.ntp.org"
    - "time.*.com"              # 通配已覆盖 time.windows.com
    - "ntp.*.com"               # 通配已覆盖 ntp.ubuntu.com
    # 运营商 Wi-Fi 登录页
    - "+.cmpassport.com"
    - "id6.me"
    - "open.e.189.cn"
    - "mdn.open.wo.cn"
    - "opencloud.wostore.cn"
    - "auth.wosms.cn"
    - "+.10099.com.cn"
    # 原配置保留项
    - "+.market.xiaomi.com"
    - "+.pub.3gppnetwork.org"
    - "+.push.apple.com"
    - "+.bing.com"
    - "+.miwifi.com"
    - "+.docker.io"
    # 国内应用登录（+.qq.com 已覆盖 localhost.ptlogin2.qq.com）
    - "+.qq.com"
    # 直连 / 国内类规则集：返回真实 IP
    - rule-set:Direct
    - rule-set:Private
    - rule-set:China
  use-hosts: true
  respect-rules: true
  # 引导用 DNS（解析 DoH/DoT 服务器自身的域名），必须是 IP
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  # 默认解析：未命中 nameserver-policy 的域名（国内 DoH，直连）
  nameserver:
    - "https://dns.alidns.com/dns-query"
    - "https://doh.pub/dns-query"
  # 直连出口的解析
  direct-nameserver:
    - "https://dns.alidns.com/dns-query"
    - "https://doh.pub/dns-query"
  # 解析代理节点域名（防套娃 / 防循环，用国内直连可达的 DoH）
  proxy-server-nameserver:
    - "https://dns.alidns.com/dns-query"
    - "https://doh.pub/dns-query"
  nameserver-policy:
    # 广告域名直接返回空应答
    "rule-set:Advertising,AWAvenueAds": rcode://success
    # 直连类：国内 DoH（微软已并入直连，微软域名走国内解析后直连）
    "rule-set:Direct,Private,China,Microsoft":
      - "https://dns.alidns.com/dns-query"
      - "https://doh.pub/dns-query"
    # 走代理类：国外 DoH（连接本身经代理隧道，不直连暴露查询）
    "rule-set:AI,Telegram,Twitter,SocialMedia,Netflix,YouTube,Spotify,TikTok,disney,Google,Proxy":
      - "https://dns.google/dns-query"
      - "https://cloudflare-dns.com/dns-query"

# ==================== 代理策略组（9 个可见 + 6 个隐藏自动子组） ====================
proxy-groups:
  # 主入口：默认自动选择，可手动切换各地区 / 故障转移 / 全部节点 / 直接连接
  - {name: 一键连接,     type: select, proxies: [自动选择, 故障转移, 香港节点, 台湾节点, 日本节点, 美国节点, 新加坡节点, 全部节点, 直接连接], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Static.png}
  # 自动选择：隐藏（面板不可手动选择），纯自动优选延时最低节点；故障转移：按序自动切换
  - {name: 自动选择,     type: url-test, include-all: true, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, hidden: true, empty-fallback: REJECT, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  - {name: 故障转移,     type: fallback, proxies: [香港节点, 台湾节点, 日本节点, 美国节点, 新加坡节点, 全部节点], url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/ULB.png}
  # 常用地区节点组（select：默认选中“XX自动”=自动优选该地区最快节点，也可手动指定单个节点）
  - {name: 香港节点,     type: select, include-all: true, filter: *FilterHK, proxies: [香港自动], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Hong_Kong.png}
  - {name: 台湾节点,     type: select, include-all: true, filter: *FilterTW, proxies: [台湾自动], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Taiwan.png}
  - {name: 日本节点,     type: select, include-all: true, filter: *FilterJP, proxies: [日本自动], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Japan.png}
  - {name: 美国节点,     type: select, include-all: true, filter: *FilterUS, proxies: [美国自动], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/United_States.png}
  - {name: 新加坡节点,   type: select, include-all: true, filter: *FilterSG, proxies: [新加坡自动], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Singapore.png}
  # 全部节点（手动挑选任意节点；首个选项“自动选择”=全部节点中最快）
  - {name: 全部节点,     type: select, include-all: true, proxies: [自动选择], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Global.png}
  # 各地区自动优选子组（隐藏，作为各地区分组内的“自动选择”选项）
  - {name: 香港自动,     type: url-test, include-all: true, filter: *FilterHK, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, hidden: true, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  - {name: 台湾自动,     type: url-test, include-all: true, filter: *FilterTW, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, hidden: true, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  - {name: 日本自动,     type: url-test, include-all: true, filter: *FilterJP, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, hidden: true, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  - {name: 美国自动,     type: url-test, include-all: true, filter: *FilterUS, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, hidden: true, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  - {name: 新加坡自动,   type: url-test, include-all: true, filter: *FilterSG, url: 'https://www.google.com/generate_204', interval: 200, lazy: true, empty-fallback: REJECT, hidden: true, icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Auto.png}
  # 直连分组（放在最下方）
  - {name: 直接连接,     type: select, proxies: [DIRECT], icon: https://github.com/Koolson/Qure/raw/master/IconSet/Color/Direct.png}

# ==================== 规则路由 ====================
rules:
  # 广告拦截（常用：直接拒绝；如需临时放行可改为一键连接）
  - RULE-SET,Tracking,REJECT
  - RULE-SET,AWAvenueAds,REJECT
  - RULE-SET,Advertising,REJECT

  # DNS 服务器域名：解析通道固定，避免 DNS 流量走错路径（防泄露关键）
  - DOMAIN-SUFFIX,alidns.com,直接连接
  - DOMAIN-SUFFIX,doh.pub,直接连接
  - DOMAIN,dns.google,一键连接
  - DOMAIN,cloudflare-dns.com,一键连接

  # 大陆直连优先（置于国外服务规则之前：大陆应用一律直连，不被国外服务规则集抢先命中）
  - RULE-SET,Private,直接连接
  - RULE-SET,Direct,直接连接
  - RULE-SET,Download,直接连接
  - RULE-SET,AppleCN,直接连接
  - RULE-SET,Microsoft,直接连接        # 微软全家桶直连（Office / OneDrive / Windows 更新 / Teams / Xbox 等）
  - RULE-SET,China,直接连接             # 国内域名直连
  # 阻止走代理的 QUIC（强制回退 TCP，避免 QUIC 绕过代理 / 被干扰）。
  # 放在直连规则之后：直连 QUIC（大陆 / 微软 / 苹果）不受影响。如需 Telegram 语音等 UDP，可删除此行。
  - AND,((DST-PORT,443),(NETWORK,UDP)),REJECT

  # 常用国外服务（统一走一键连接）
  - RULE-SET,AI,一键连接
  - RULE-SET,Telegram,一键连接
  - RULE-SET,Twitter,一键连接
  - RULE-SET,SocialMedia,一键连接
  - RULE-SET,Netflix,一键连接
  - RULE-SET,YouTube,一键连接
  - RULE-SET,Spotify,一键连接
  - RULE-SET,TikTok,一键连接
  - RULE-SET,disney,一键连接
  - RULE-SET,Google,一键连接
  - RULE-SET,github,一键连接
  - RULE-SET,Proxy,一键连接

  # IP规则
  - RULE-SET,PrivateIP,直接连接,no-resolve
  - RULE-SET,TelegramIP,一键连接,no-resolve
  - RULE-SET,ProxyIP,一键连接,no-resolve
  - RULE-SET,ChinaIP,直接连接,no-resolve

  # 大陆 IP 兜底直连：覆盖规则集未收录的域名 / 纯 IP 连接的大陆应用（GEOIP 库覆盖面更全）
  - GEOIP,CN,直接连接,no-resolve

  # 兜底规则：其余（国外）走一键连接
  - MATCH,一键连接

# ==================== 规则集 ====================
# 规则集行为模板
BehaviorDN: &BehaviorDN {type: http, behavior: domain, format: mrs, interval: 86400}
BehaviorDY: &BehaviorDY {type: http, behavior: domain, format: yaml, interval: 86400}
BehaviorIP: &BehaviorIP {type: http, behavior: ipcidr, format: mrs, interval: 86400}
ClassicalYaml: &ClassicalYaml {type: http, behavior: classical, interval: 3600, format: yaml, proxy: DIRECT}
BehaviorCL: &BehaviorCL {type: http, behavior: classical, interval: 86400, format: yaml, proxy: DIRECT}   # 经典规则集（blackmatrix7 等，DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/PROCESS-NAME）

# 规则提供者（仅保留常用）
rule-providers:
  # 广告
  Tracking:       {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Tracking.mrs}
  Advertising:    {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Advertising.mrs}
  AWAvenueAds:    {<<: *BehaviorDY, url: https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.yaml}
  # 直连 / 国内
  Direct:         {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Direct.mrs}
  Private:        {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Private.mrs}
  Download:       {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Download.mrs}
  AppleCN:        {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/AppleCN.mrs}
  China:          {<<: *BehaviorCL, url: https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_No_Resolve.yaml}   # 大陆直连全量：ChinaMaxNoIP（11万+ 域名，含大陆可达国际服务），每日更新
  # 常用国外服务
  AI:             {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/AI.mrs}
  Telegram:       {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Telegram.mrs}
  Twitter:        {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Twitter.mrs}
  SocialMedia:    {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/SocialMedia.mrs}
  Netflix:        {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Netflix.mrs}
  YouTube:        {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/YouTube.mrs}
  Google:         {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Google.mrs}
  Microsoft:      {<<: *BehaviorCL, url: https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Microsoft/Microsoft.yaml}   # 微软全家桶全量：blackmatrix7（Office/OneDrive/Xbox/Teams/Skype/Bing/Azure 等）
  Proxy:          {<<: *BehaviorDN, url: https://github.com/666OS/rules/raw/release/mihomo/domain/Proxy.mrs}
  # 媒体（DustinWin）
  Spotify:        {<<: *BehaviorDN, url: https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/spotify.mrs}
  TikTok:         {<<: *BehaviorDN, url: https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/tiktok.mrs}
  disney:         {<<: *BehaviorDN, url: https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/disney.mrs}
  # GitHub
  github:          {<<: *ClassicalYaml, url: https://rule.kelee.one/Clash/GitHub.yaml}
  # IP规则
  PrivateIP:      {<<: *BehaviorIP, url: https://github.com/666OS/rules/raw/release/mihomo/ip/Private.mrs}
  TelegramIP:     {<<: *BehaviorIP, url: https://github.com/666OS/rules/raw/release/mihomo/ip/Telegram.mrs}
  ProxyIP:        {<<: *BehaviorIP, url: https://github.com/666OS/rules/raw/release/mihomo/ip/Proxy.mrs}
  ChinaIP:        {<<: *BehaviorIP, url: https://github.com/666OS/rules/raw/release/mihomo/ip/China.mrs}

# ==================== EOF ====================

`;


// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------
// Cloudflare 官方 IPv4 地址段（入口 IP 校验 + 随机生成测速候选）
const CLOUDFLARE_CIDRS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
];

// 随机补足/随机优选只用这些新段：CF 老段（103.x/141.101/131.0/173.245 等）在国内大量不可达，
// 实测 90 个全段随机 IP 仅 5 个可达（5.6%）；新段命中率高得多
const REACHABLE_CIDRS = [
  '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '162.158.0.0/15', '188.114.96.0/20'
];

// Cloudflare 官方 IPv6 地址段（用于入口 IP 过滤）
const CLOUDFLARE_CIDRS_V6 = [
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
];
// IPv6 随机补足/随机优选专用段（筛选含 IPv6 时使用，与 IPv4 补足同一可达性原则）
const REACHABLE_CIDRS_V6 = [
  '2606:4700::/32', '2400:cb00::/32', '2803:f800::/32', '2a06:98c0::/29', '2c0f:f248::/32'
];
// Cloudflare 官方公开 IPv6 网段（https://www.cloudflare.com/ips-v6/ 动态拉取，6 小时缓存；
// 失败回退内置段；实测官方段随机地址 TCP+TLS 全端口可用，与 IPv4 补足同机制）
let OFFICIAL_V6_CIDRS = CLOUDFLARE_CIDRS_V6.slice();
let OFFICIAL_V6_CIDRS_T = 0;
async function refreshOfficialV6CIDRs(io) {
  const now = Date.now();
  if (OFFICIAL_V6_CIDRS_T && now - OFFICIAL_V6_CIDRS_T < 6 * 60 * 60 * 1000) return;
  try {
    const resp = await fetchTimeout('https://www.cloudflare.com/ips-v6/', {}, 4000, io);
    if (!resp || !resp.ok) return;
    const txt = await resp.text();
    const cidrs = String(txt).split('\n').map(s => s.trim()).filter(s => /^[0-9a-fA-F:.]+\/\d+$/.test(s) && s.indexOf(':') >= 0);
    if (cidrs.length >= 3) { OFFICIAL_V6_CIDRS = cidrs; OFFICIAL_V6_CIDRS_T = now; }
  } catch (e) { /* 拉取失败沿用内置/上次成功网段 */ }
}

// IPv6 CIDR 前缀匹配（展开为 16 进制组后按位比较）
function ipInCidrV6(ip, cidr) {
  const [net, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const expand = (a) => {
    const dbl = a.indexOf('::');
    let groups;
    if (dbl >= 0) {
      const left = a.slice(0, dbl).split(':').filter(Boolean);
      const right = a.slice(dbl + 2).split(':').filter(Boolean);
      const fill = 8 - left.length - right.length;
      groups = [...left, ...Array(fill).fill('0'), ...right];
    } else groups = a.split(':');
    return groups.map(g => g.padStart(4, '0'));
  };
  const bitStr = (groups) => groups.map(g => parseInt(g, 16).toString(2).padStart(16, '0')).join('');
  return bitStr(expand(ip)).slice(0, bits) === bitStr(expand(net)).slice(0, bits);
}

// 判断 IP 是否属于 Cloudflare Anycast 段：节点入口必须是 CF 边缘 IP，
// 非 CF IP（如各地区云服务器/落地 IP）无法把客户端 TLS 转发到 Worker，下发必然连不通
function isCloudflareIP(ip) {
  ip = String(ip || '');
  if (!isValidIp(ip)) return false;
  if (ip.indexOf(':') >= 0) return CLOUDFLARE_CIDRS_V6.some(cidr => ipInCidrV6(ip, cidr));
  const p = ip.split('.').map(Number);
  const n = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  return CLOUDFLARE_RANGES.some(([start, end]) => n >= start && n <= end);
}

// ISO 国家/地区码 → 中文（用于优选 API 数据源（bestcf 等 /random-region/XX/）下发的节点命名，以及按 Worker 机房标注节点地区前缀）
const REGION_CN = {
  HK: '香港', TW: '台湾', MO: '澳门', JP: '日本', SG: '新加坡', US: '美国', KR: '韩国', DE: '德国',
  FR: '法国', GB: '英国', CA: '加拿大', AU: '澳大利亚', SE: '瑞典', NL: '荷兰', FI: '芬兰',
  NO: '挪威', DK: '丹麦', CH: '瑞士', IT: '意大利', ES: '西班牙', PT: '葡萄牙', IE: '爱尔兰',
  BE: '比利时', AT: '奥地利', PL: '波兰', CZ: '捷克', RO: '罗马尼亚', HU: '匈牙利', GR: '希腊',
  RU: '俄罗斯', TR: '土耳其', UA: '乌克兰', IN: '印度', TH: '泰国', MY: '马来西亚', VN: '越南',
  PH: '菲律宾', ID: '印尼', BR: '巴西', MX: '墨西哥', AR: '阿根廷', CL: '智利', ZA: '南非',
  EG: '埃及', AE: '阿联酋', IL: '以色列', NZ: '新西兰', KZ: '哈萨克斯坦', SA: '沙特'
};

// 默认 6 条地区优选源（bestcf 在线优选池，社区维护的可达中转 IP，可用率高）
const DEFAULT_REGION_POOLS = [
  'https://bestcf.pages.dev/random-region/HK/100.txt',
  'https://bestcf.pages.dev/random-region/TW/100.txt',
  'https://bestcf.pages.dev/random-region/JP/100.txt',
  'https://bestcf.pages.dev/random-region/SG/100.txt',
  'https://bestcf.pages.dev/random-region/US/100.txt',
  'https://bestcf.pages.dev/random-region/KR/100.txt'
].join('\n');
// 识别 bestcf 地区池及天诚源 URL：允许这类来源包含非 CF 段中转节点，
// 允许绕过「仅 CF 段」过滤直接下发；其余来源仍保持 CF 段硬性要求
const TRUSTED_REGION_POOL_RE = /random-region\/[A-Z]{2,}\/\d+\.txt/i;
function isTrustedRegionPool(url) {
  try { const u = new URL(url); return u.protocol === 'https:' && u.hostname === 'bestcf.pages.dev' && (TRUSTED_REGION_POOL_RE.test(u.pathname) || u.pathname === '/tiancheng/all.txt'); } catch { return false; }
}

const DEFAULT_CONFIG = {
  uuid: '',
  path: '',            // 自定义路径，留空用 UUID
  admin: '',
  host: '',
  // 协议开关
  enableVless: true,
  enableTrojan: false,
  trojanPassword: '',
  enableXhttp: false,
  // 传输参数
  alpn: '',
  ech: false,
  echHost: 'cloudflare-ech.com',   // ECH 查询域名（默认 cloudflare-ech.com）
  echDns: '',                      // 自定义 ECH DNS：客户端获取 ECH 配置的 DoH 地址（留空用默认 223.5.5.5）
  tlsOnly: false,       // TLS 控制：关闭下发全部节点，开启仅下发 TLS 端口节点
  nodeLimit: true,      // 节点数量控制：默认开启，按 nodeLimitCount 精确限制节点总数
  nodeLimitCount: 300,  // 总节点上限；结构化格式还受 300 条硬上限约束
  polling: false,       // 每 15 分钟按配置版本和客户端标识轮换顺序，不写 KV；始终遵守数量上限
  probeAlive: false,    // ★ 节点测活（TCP 探测）总开关：默认关闭（推荐，对齐 V1.0.6）——订阅不做任何 TCP 握手/HTTP 探测与剔除，
                        //   按数据源原始顺序全量下发、客户端自行择优（秒回，v2rayNG/AsteriskNG 刷新正常）；面板开启或 PROBE_ALIVE=1 强制开启。
                        //   节点形态：所有模式统一按 1.0.6 机制——端口原样单端口下发（固定 443、不随机 TLS 端口、不追加明文端口变体）。
                        //   关闭：所有测活函数直接放行，不做任何 TCP 握手/HTTP 探测与剔除——节点的下发策略、出入站方式、
                        //   ProxyIP 等节点相关均按 V1.x 处理：按数据源原始顺序（bestcf 地区池行序 = 质量序）全量下发，客户端自行择优；
                        //   开启：对候选地址做 TCP 握手/HTTP 探测并剔除判死项，
                        //   含精选池/优选 IP/域名预检/ProxyIP 兜底各环节的测活剔除（自定义订阅 / 随机优选模式除外：不进行测活）。
                        //   注意：Cloudflare 运行时禁止出站连接 CF IP 段（官方文档：Outbound TCP sockets to
                        //   Cloudflare IP ranges are blocked），因此对 CF 段 IP 跳过 TCP 探测、直接视为可用——
                        //   精选池（实测 97% 可用）不会被误判清空，仅对非 CF 段（反代/ProxyIP）真实测活剔除死节点。
                        //   可用环境变量 PROBE_ALIVE=0 覆盖关闭
  // 配额安全（账户监控）：填写 CF 账户 ID 与 API 令牌后，面板可查询当日用量并按需自动收缩节点上限
  cfAccountId: '',      // CF 账户监控：账户 ID（Account Tag），留空则监控关闭；可用环境变量 CF_ACCOUNT_ID 覆盖
  cfApiToken: '',       // CF 账户监控：API 令牌（需 Workers 用量分析读取权限），可用环境变量 CF_API_TOKEN 覆盖
  quotaAuto: false,     // 配额安全：开启后当日用量 ≥ 60% 免费额度时自动收缩订阅节点上限，保护账户
  // 落地与出站
  proxyIP: '',
  outboundProxy: '',
  outboundMode: '',    // '' | 'no' | 'only'
  // 优选节点（保存后随订阅下发到客户端）
  preferredDomains: 'https://bestcf.pages.dev/random-region/HK/100.txt\nhttps://bestcf.pages.dev/random-region/TW/100.txt\nhttps://bestcf.pages.dev/random-region/JP/100.txt\nhttps://bestcf.pages.dev/random-region/SG/100.txt\nhttps://bestcf.pages.dev/random-region/US/100.txt\nhttps://bestcf.pages.dev/random-region/KR/100.txt',   // 自定义订阅模式下使用的地址（每行/逗号分隔）
  preferredIPs: [],       // [{ip, port, name}]
  // 优选器（在线测速参数）
  optimizer: {
    source: 'wetest_v4', // 预设数据源键，见 OPTIMIZE_SOURCES
    sourceURL: '',       // 自定义数据源 URL
    port: 443,
    threads: 4,
    count: 20,
    useCidr: true,
    fillCount: 0,        // 节点 IP 不足时用 CF CIDR 随机补足（0 关闭；默认关闭，只下发真实优选节点）
    subMode: '',         // 订阅模式：'' 关闭（使用面板默认）/ custom 自定义订阅（支持汇聚）/ random 随机优选
    subRandomCount: 16,  // random 模式随机优选数量
    subIncludeDefault: false // 自定义订阅模式下是否同时下发内置及默认地区节点（false 仅自定义）
  },
  // 订阅筛选（按节点名称中的地区/运营商标记 + 地址 IP 类型过滤下发）
  filter: {
    region: 'all',        // 'all' | 'HK' | 'TW' | 'US' | 'SG' | 'JP' | 'KR' | 'DE'
    ipType: ['IPv4', 'IPv6'],   // 勾选的 IP 类型集合（全选或空 = 不过滤）
    isp: ['移动', '联通', '电信']  // 勾选的运营商集合（全选 = 不过滤）
  }
};

// 内置官方直连域名：未配置任何优选节点时的回退，保证开箱即用
const BUILTIN_OFFICIAL_DOMAINS = ['cloudflare.com', 'www.cloudflare.com', 'speed.cloudflare.com'];

// 内置 Cloudflare 优选 IP 池：未配置优选节点时开箱即用的可用节点（部署即下发）
// 内置保底优选 IP：Cloudflare 官方任播段 IP，全部经实测（SNI=部署域名、443、HTTP 101）确认客户端可达，
// 固定 443 追加下发，保证订阅内始终有稳定可用节点（参考 TunnelBoard 内置优选思路，独立实测选取）
const BUILTIN_STABLE_IPS = [
  '104.16.128.11', '172.67.72.4', '104.17.201.77', '104.16.66.7', '104.16.88.7',
  '104.16.98.7', '104.17.2.7', '104.17.44.9', '104.18.34.34', '104.18.7.34',
  '104.19.191.31', '104.19.1.1', '104.20.15.15', '104.20.1.1', '104.21.23.1',
  '104.21.2.1', '104.24.12.10', '104.25.0.1', '104.26.1.1', '162.159.128.1'
];

// bestcf 区域优选池（实时测速过的优质 CF IP，可用性远高于随机 CIDR 生成）
const BESTCF_REGION_URLS = [
  { label: '香港', region: 'HK', url: 'https://bestcf.pages.dev/random-region/HK/100.txt', count: 12 },
  { label: '日本', region: 'JP', url: 'https://bestcf.pages.dev/random-region/JP/100.txt', count: 12 },
  { label: '美国', region: 'US', url: 'https://bestcf.pages.dev/random-region/US/100.txt', count: 12 },
  { label: '新加坡', region: 'SG', url: 'https://bestcf.pages.dev/random-region/SG/100.txt', count: 12 },
  { label: '台湾', region: 'TW', url: 'https://bestcf.pages.dev/random-region/TW/100.txt', count: 12 }
];


const BUILTIN_PREFERRED_IPS = [
  '104.17.127.180#优选IP-001', '104.16.123.96#优选IP-002', '104.16.124.96#优选IP-003', '104.16.125.96#优选IP-004',
  '104.16.126.96#优选IP-005', '104.16.127.96#优选IP-006', '104.16.132.229#优选IP-007', '104.16.248.248#优选IP-008',
  '104.16.249.249#优选IP-009', '162.159.0.1#优选IP-010', '188.114.96.1#优选IP-011', '104.17.24.252#优选IP-012',
  '188.114.99.52#优选IP-013', '162.159.94.229#优选IP-014', '162.159.5.175#优选IP-015', '104.18.119.34#优选IP-016',
  '104.21.213.24#优选IP-017', '104.17.234.5#优选IP-018', '104.16.245.187#优选IP-019', '172.67.64.211#优选IP-020',
  '172.67.64.12#优选IP-021', '104.18.43.224#优选IP-022', '104.18.40.93#优选IP-023', '104.18.37.92#优选IP-024',
  '104.18.47.234#优选IP-025', '104.18.42.54#优选IP-026', '172.64.144.49#优选IP-027', '172.64.146.15#优选IP-028',
  '104.17.185.207#优选IP-029', '104.17.101.139#优选IP-030', '162.159.44.215#优选IP-031', '162.159.44.214#优选IP-032',
  '104.18.217.109#优选IP-033', '172.65.127.225#优选IP-034', '104.18.184.243#优选IP-035', '162.159.137.205#优选IP-036',
  '172.65.64.7#优选IP-037', '104.25.45.44#优选IP-038', '104.19.88.253#优选IP-039', '162.159.136.73#优选IP-040',
  '104.18.185.40#优选IP-041', '104.25.141.168#优选IP-042', '104.25.246.123#优选IP-043', '104.24.54.254#优选IP-044',
  '104.19.123.4#优选IP-045', '188.114.98.144#优选IP-046', '188.114.99.18#优选IP-047', '104.17.127.106#优选IP-048',
  '162.159.4.175#优选IP-049', '104.18.255.187#优选IP-050', '172.65.173.221#优选IP-051', '104.18.176.111#优选IP-052',
  '104.25.122.6#优选IP-053', '188.114.96.116#优选IP-054', '104.25.214.211#优选IP-055', '104.16.223.195#优选IP-056',
  '104.25.101.186#优选IP-057', '172.64.81.44#优选IP-058', '104.25.143.238#优选IP-059', '188.114.99.114#优选IP-060',
  '104.19.169.53#优选IP-061', '104.16.113.211#优选IP-062', '104.27.40.81#优选IP-063', '188.114.98.91#优选IP-064',
  '162.159.236.5#优选IP-065', '104.25.44.144#优选IP-066', '162.159.46.167#优选IP-067', '104.18.84.180#优选IP-068',
  '104.18.196.199#优选IP-069', '104.24.155.234#优选IP-070', '162.159.228.244#优选IP-071', '162.159.235.27#优选IP-072',
  '104.19.214.25#优选IP-073', '104.19.168.107#优选IP-074', '104.24.244.237#优选IP-075', '104.27.66.179#优选IP-076',
  '104.24.2.253#优选IP-077', '104.21.61.179#优选IP-078', '104.21.114.216#优选IP-079', '188.114.98.53#优选IP-080',
  '172.65.145.187#优选IP-081', '188.114.96.255#优选IP-082', '104.25.245.147#优选IP-083', '172.66.161.31#优选IP-084',
  '104.18.133.24#优选IP-085', '188.114.99.155#优选IP-086', '172.64.34.109#优选IP-087', '172.64.145.202#优选IP-088',
  '104.19.78.30#优选IP-089', '104.17.118.180#优选IP-090', '104.17.13.179#优选IP-091', '172.65.35.169#优选IP-092',
  '104.16.0.133#优选IP-093', '104.16.238.98#优选IP-094', '104.18.28.140#优选IP-095', '104.19.115.243#优选IP-096',
  '104.24.58.243#优选IP-097', '104.27.207.36#优选IP-098', '104.21.192.230#优选IP-099', '104.25.20.146#优选IP-100',
  '104.27.113.151#优选IP-101', '104.24.230.144#优选IP-102', '172.65.134.100#优选IP-103', '188.114.96.94#优选IP-104',
  '104.25.197.107#优选IP-105', '104.16.108.18#优选IP-106', '172.64.233.36#优选IP-107', '172.67.163.14#优选IP-108',
  '104.24.230.213#优选IP-109', '104.19.106.1#优选IP-110', '104.27.72.4#优选IP-111', '104.21.57.47#优选IP-112',
  '172.65.162.213#优选IP-113', '172.67.255.83#优选IP-114', '172.67.189.246#优选IP-115', '162.159.230.149#优选IP-116',
  '162.159.197.16#优选IP-117', '172.67.103.87#优选IP-118', '162.159.237.243#优选IP-119', '104.25.193.135#优选IP-120',
  '104.18.141.27#优选IP-121', '172.65.11.191#优选IP-122', '104.24.184.158#优选IP-123', '188.114.97.52#优选IP-124',
  '104.27.4.144#优选IP-125', '104.25.93.154#优选IP-126', '172.66.199.166#优选IP-127', '172.67.64.94#优选IP-128',
  '104.27.94.231#优选IP-129', '104.24.168.96#优选IP-130', '104.18.173.224#优选IP-131', '172.67.173.89#优选IP-132',
  '104.17.107.217#优选IP-133', '188.114.97.91#优选IP-134', '104.17.195.184#优选IP-135', '162.159.14.18#优选IP-136',
  '172.67.229.44#优选IP-137', '104.24.51.58#优选IP-138', '104.19.97.238#优选IP-139', '104.25.161.217#优选IP-140',
  '104.17.146.117#优选IP-141', '172.67.161.136#优选IP-142', '104.17.99.0#优选IP-143', '104.25.100.203#优选IP-144',
  '104.19.23.222#优选IP-145', '188.114.96.141#优选IP-146', '104.19.247.23#优选IP-147', '104.25.24.66#优选IP-148',
  '104.16.123.26#优选IP-149', '104.27.23.242#优选IP-150', '104.25.36.200#优选IP-151', '104.17.195.133#优选IP-152',
  '104.16.68.175#优选IP-153', '188.114.98.19#优选IP-154', '104.16.218.231#优选IP-155', '104.18.28.48#优选IP-156',
  '162.159.143.225#优选IP-157', '162.159.19.201#优选IP-158', '104.25.166.112#优选IP-159', '104.16.201.45#优选IP-160',
  '104.16.91.33#优选IP-161', '172.67.82.86#优选IP-162', '104.16.11.246#优选IP-163', '188.114.97.61#优选IP-164',
  '104.17.240.245#优选IP-165', '172.66.157.150#优选IP-166', '104.17.25.173#优选IP-167', '104.18.26.28#优选IP-168',
  '104.18.123.15#优选IP-169', '104.25.124.155#优选IP-170', '188.114.96.64#优选IP-171', '104.18.18.214#优选IP-172',
  '104.17.46.187#优选IP-173', '104.17.153.58#优选IP-174', '188.114.96.89#优选IP-175', '172.67.174.143#优选IP-176',
  '104.25.251.220#优选IP-177', '104.27.195.79#优选IP-178', '162.159.153.10#优选IP-179', '104.25.129.238#优选IP-180',
  '172.65.3.67#优选IP-181', '172.67.232.109#优选IP-182', '104.18.178.193#优选IP-183', '104.19.78.144#优选IP-184',
  '104.18.63.107#优选IP-185', '104.19.69.150#优选IP-186', '104.25.73.92#优选IP-187', '172.67.195.152#优选IP-188',
  '172.65.184.114#优选IP-189', '172.65.202.216#优选IP-190', '172.65.21.190#优选IP-191', '104.19.32.220#优选IP-192',
  '104.18.211.8#优选IP-193', '104.17.160.131#优选IP-194', '162.159.6.39#优选IP-195', '162.159.43.223#优选IP-196',
  '104.21.224.5#优选IP-197', '104.25.18.216#优选IP-198', '162.159.6.246#优选IP-199', '104.24.46.127#优选IP-200',
  '104.17.87.46#优选IP-201', '188.114.97.80#优选IP-202', '188.114.97.108#优选IP-203', '162.159.241.11#优选IP-204',
  '188.114.97.0#优选IP-205', '188.114.99.14#优选IP-206', '104.19.68.127#优选IP-207', '162.159.10.45#优选IP-208',
  '104.25.181.74#优选IP-209', '104.24.178.200#优选IP-210', '188.114.96.164#优选IP-211', '104.24.41.240#优选IP-212',
  '104.17.97.72#优选IP-213', '104.16.77.112#优选IP-214', '104.19.181.118#优选IP-215', '172.67.165.245#优选IP-216',
  '104.17.169.109#优选IP-217', '172.65.44.103#优选IP-218', '188.114.97.63#优选IP-219', '172.65.47.182#优选IP-220',
  '104.17.245.237#优选IP-221', '162.159.2.86#优选IP-222', '188.114.96.151#优选IP-223', '172.65.139.108#优选IP-224',
  '172.65.118.105#优选IP-225', '104.21.7.133#优选IP-226', '162.159.134.174#优选IP-227', '104.18.194.107#优选IP-228',
  '188.114.97.21#优选IP-229', '162.159.9.18#优选IP-230', '104.18.41.168#优选IP-231', '162.159.192.111#优选IP-232',
  '162.159.240.54#优选IP-233', '104.17.0.4#优选IP-234', '104.25.86.143#优选IP-235', '104.27.97.130#优选IP-236',
  '172.67.127.122#优选IP-237', '104.25.33.126#优选IP-238', '104.25.223.90#优选IP-239', '104.25.123.130#优选IP-240',
  '172.65.167.52#优选IP-241', '172.67.159.243#优选IP-242', '104.25.113.22#优选IP-243', '188.114.98.27#优选IP-244',
  '162.159.198.200#优选IP-245', '104.17.76.49#优选IP-246', '104.21.215.255#优选IP-247', '172.67.131.200#优选IP-248',
  '162.159.135.234#优选IP-249', '172.65.45.102#优选IP-250', '172.66.164.60#优选IP-251', '162.159.26.248#优选IP-252',
  '162.159.90.82#优选IP-253', '172.65.50.167#优选IP-254', '162.159.236.19#优选IP-255', '104.19.143.220#优选IP-256',
  '104.17.151.244#优选IP-257', '104.17.121.245#优选IP-258', '104.18.144.168#优选IP-259', '162.159.228.231#优选IP-260',
  '104.17.100.40#优选IP-261', '104.27.116.114#优选IP-262', '162.159.199.220#优选IP-263', '104.20.17.160#优选IP-264',
  '104.25.62.39#优选IP-265', '104.27.20.220#优选IP-266', '172.65.118.85#优选IP-267', '104.19.83.33#优选IP-268',
  '188.114.96.238#优选IP-269', '162.159.42.67#优选IP-270', '104.27.46.114#优选IP-271', '104.25.126.144#优选IP-272',
  '104.25.173.14#优选IP-273', '104.24.46.107#优选IP-274', '104.25.109.0#优选IP-275', '162.159.137.71#优选IP-276',
  '104.25.238.28#优选IP-277', '104.27.124.239#优选IP-278', '104.24.34.149#优选IP-279', '104.19.246.234#优选IP-280',
  '162.159.10.243#优选IP-281', '104.27.96.232#优选IP-282', '172.65.78.200#优选IP-283', '104.24.25.178#优选IP-284',
  '104.24.84.86#优选IP-285', '104.25.238.237#优选IP-286', '104.16.45.249#优选IP-287', '104.16.234.241#优选IP-288',
  '104.24.18.62#优选IP-289', '172.65.45.248#优选IP-290', '104.25.169.144#优选IP-291', '104.27.27.106#优选IP-292',
  '162.159.43.85#优选IP-293', '172.67.71.106#优选IP-294', '162.159.228.164#优选IP-295', '104.24.250.89#优选IP-296',
  '104.18.185.26#优选IP-297', '104.27.21.175#优选IP-298', '104.24.49.39#优选IP-299', '172.67.85.54#优选IP-300',
];

// 内置默认优选池：未配置任何优选时自动 DoH 解析下发真实优选节点（而非 CF 随机补足）
// 2026-09 实测清洗：29 个候选中剔除 12 个已过期/NXDOMAIN 死链域名与 3 个非 CF 段域名（无法作入口），保留 14 个高可用活跃域名
// 默认优选域名：第三方 CNAME 域名，解析到 Cloudflare 边缘；
// 节点 server 直接下发域名（客户端连接时动态 DNS 解析，拿到当前最优 CF 边缘 IP，可用性远高于静态 IP 快照）
const DEFAULT_PREFERRED_DOMAINS = [
  'cloudflare.182682.xyz',
  'cf.0sm.com',
  'cf.090227.xyz',
  'cfip.1323123.xyz',
  'cnamefuckxxs.yuchen.icu',
  'cloudflare-ip.mofashi.ltd',
  'cdn.tzpro.xyz',
  'cf.877771.xyz',
  'xn--b6gac.eu.org',
  'bestcf.030101.xyz',
  'cdns.doon.eu.org',
  'fn.130519.xyz',
  'saas.sin.fan'
].join('\n');


// 明文 HTTP 端口：Cloudflare 边缘在这些端口上不支持 TLS，节点必须走明文 ws（否则握手失败连不通）
const HTTP_PORTS = new Set([80, 8080, 8880, 2052, 2082, 2086, 2095]);

// 优选器预设数据源：微测网接口 + 优选 IP 来源
const OPTIMIZE_SOURCES = {
  wetest_v4:    { label: '微测网 IPv4', url: 'https://www.wetest.vip/page/cloudflare/address_v4.html' },
  wetest_v6:    { label: '微测网 IPv6', url: 'https://www.wetest.vip/page/cloudflare/address_v6.html' },
  bestcf:       { label: '优选 IP 列表', url: 'https://cf.090227.xyz/ip.164746.xyz' },
  hostmonit:    { label: 'HostMonit 优选', url: 'https://stock.hostmonit.com/CloudFlareYes' },
  wetest_cname: { label: '微测网 优选域名', url: 'https://www.wetest.vip/page/cloudflare/cname.html' }
};

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------
const TE = new TextEncoder();
const TD = new TextDecoder();

// Base64 编码（出站 HTTP 代理认证用）
function b64FromBytes(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

// MD5（纯 JS 实现，RFC 1321；WebCrypto 不支持 MD5）
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];
const MD5_K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];
function rotl32(x, c) { return ((x << c) | (x >>> (32 - c))) >>> 0; }
function md5hex(str) {
  const bytes = str instanceof Uint8Array ? str : TE.encode(String(str));
  const bitLen = bytes.length * 8;
  const paddedLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const data = new Uint8Array(paddedLen);
  data.set(bytes);
  data[bytes.length] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(paddedLen - 8, bitLen >>> 0, true);
  dv.setUint32(paddedLen - 4, Math.floor(bitLen / 0x100000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let i = 0; i < paddedLen; i += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(i + j * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let j = 0; j < 64; j++) {
      let f, g;
      if (j < 16) { f = (b & c) | (~b & d); g = j; }
      else if (j < 32) { f = (d & b) | (~d & c); g = (5 * j + 1) % 16; }
      else if (j < 48) { f = b ^ c ^ d; g = (3 * j + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * j) % 16; }
      const sum = (a + f + MD5_K[j] + M[g]) >>> 0;
      const nb = (b + rotl32(sum, MD5_S[j])) >>> 0;
      a = d; d = c; c = b; b = nb;
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  let hex = '';
  for (const v of [a0, b0, c0, d0]) {
    hex += (v & 255).toString(16).padStart(2, '0');
    hex += ((v >>> 8) & 255).toString(16).padStart(2, '0');
    hex += ((v >>> 16) & 255).toString(16).padStart(2, '0');
    hex += ((v >>> 24) & 255).toString(16).padStart(2, '0');
  }
  return hex;
}

function uuidv4() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  return [...b].map((x, i) => (i === 4 || i === 6 || i === 8 || i === 10 ? '-' : '') + x.toString(16).padStart(2, '0')).join('');
}
function isUUID(str) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(str || '');
}
function parseHostPort(addr, defaultPort = 443) {
  addr = String(addr || '').trim();
  if (!addr) return { host: '', port: defaultPort };
  if (addr.startsWith('[')) {
    const m = addr.match(/^\[([^\]]+)\](?::(\d+))?$/);
    return { host: m ? m[1] : addr.replace(/^\[|\]$/g, ''), port: m && m[2] ? parseInt(m[2]) : defaultPort };
  }
  const idx = addr.lastIndexOf(':');
  if (idx > 0 && /^\d+$/.test(addr.slice(idx + 1))) {
    return { host: addr.slice(0, idx), port: parseInt(addr.slice(idx + 1)) };
  }
  return { host: addr, port: defaultPort };
}
// 严格校验 IPv4 / IPv6 地址
function isValidIp(str) {
  str = String(str || '').trim();
  if (!str) return false;
  const m4 = str.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m4) return m4.slice(1).every(n => Number(n) <= 255);
  if (!/^[0-9a-fA-F:]+$/.test(str)) return false;
  if ((str.match(/::/g) || []).length > 1) return false;
  const hasDbl = str.includes('::');
  const groups = str.replace(/::/g, ':').split(':').filter(Boolean);
  if (!hasDbl && groups.length !== 8) return false;
  if (hasDbl && (groups.length < 1 || groups.length > 7)) return false;
  return groups.every(g => /^[0-9a-fA-F]{1,4}$/.test(g));
}
function formatIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // 简单压缩：连续 0 组用 ::，仅压缩最长段
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (parts[i] === '0') {
      if (curStart < 0) { curStart = i; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen >= 2) {
    const head = parts.slice(0, bestStart).join(':');
    const tail = parts.slice(bestStart + bestLen).join(':');
    return (head ? head + '::' : '::') + tail;
  }
  return parts.join(':');
}
function cidrToRange(cidr) {
  const [ip, bits] = cidr.split('/');
  const b = ip.split('.').map(Number);
  const base = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const mask = bits >= 32 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const start = (base & mask) >>> 0;   // >>> 0 保证无符号：位运算结果可能为负（如 162.158.0.0），比较/加减前必须归一
  const end = (base | (~mask >>> 0)) >>> 0;
  return [start, end];
}
// CIDR 掩码表预编译：初始化时一次性把 CF 地址段编译为无符号整数区间数组，IP 校验变纯整数比较（性能提升数十倍，应对免费版 10ms CPU 硬限）
const CLOUDFLARE_RANGES = CLOUDFLARE_CIDRS.map(cidrToRange);
const _rangeCache = new Map();
function cidrRangeCached(cidr) {
  let r = _rangeCache.get(cidr);
  if (!r) { r = cidrToRange(cidr); _rangeCache.set(cidr, r); }
  return r;
}
function randomIPFromCidr(cidr) {
  if (String(cidr).indexOf(':') >= 0) return randomIP6FromCidr(cidr);   // IPv6 段：按前缀展开随机生成（参考 CFNext v1.0.5）
  const [start, end] = cidrRangeCached(cidr);
  const r = start + Math.floor(Math.random() * ((end - start) >>> 0));
  return `${(r >>> 24) & 255}.${(r >>> 16) & 255}.${(r >>> 8) & 255}.${r & 255}`;
}
// IPv6 随机地址生成：网络前缀位固定，主机位随机（16 进制组逐位置乱，返回压缩形式）
function randomIP6FromCidr(cidr) {
  const [net, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10) || 0;
  const expand = (a) => {
    const dbl = a.indexOf('::');
    let groups;
    if (dbl >= 0) {
      const left = a.slice(0, dbl).split(':').filter(Boolean);
      const right = a.slice(dbl + 2).split(':').filter(Boolean);
      const fill = 8 - left.length - right.length;
      groups = [...left, ...Array(fill).fill('0'), ...right];
    } else groups = a.split(':');
    return groups.map(g => g.padStart(4, '0'));
  };
  const g = expand(net).map(x => parseInt(x, 16));
  let b = 0;
  for (let i = 0; i < 8; i++) for (let k = 15; k >= 0; k--) {
    if (b >= bits) g[i] |= (Math.random() < 0.5 ? 1 : 0) << k;
    b++;
  }
  return g.map(x => x.toString(16)).join(':');
}
// IPv4-embedded IPv6（2606:4700::<hex>）：与对应 IPv4 路由到同一 CF 边缘，实测可达，
// 单选 IPv6 时内置实测池转此格式替代随机补足，实现"下发即用"
function ipv4ToEmbeddedV6(ipv4) {
  const p = String(ipv4 || '').split('.').map(n => parseInt(n, 10).toString(16).padStart(2, '0'));
  if (p.length !== 4 || p.some(x => x === 'NaN')) return null;
  return '2606:4700::' + p[0] + p[1] + ':' + p[2] + p[3];
}
function randomIPsFromCidrs(cidrs, count) {
  const seen = new Set();
  const out = [];
  let guard = 0;
  while (out.length < count && guard++ < count * 20) {
    const ip = randomIPFromCidr(cidrs[Math.floor(Math.random() * cidrs.length)]);
    if (!seen.has(ip)) { seen.add(ip); out.push(ip); }
  }
  return out;
}

// 解析 "1.2.3.4:443#名称, 5.6.7.8" 这类优选列表（仅接受合法 IP 行，过滤 HTML 等杂质）
function parseIPList(text) {
  const items = [];
  const seen = new Set();   // 按 IP 去重（忽略端口）：同一 IP 无论端口/名称只保留第一条
  String(text || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean).forEach(s => {
    let name = '';
    if (s.includes('#')) {
      const [a, n] = s.split('#');
      s = a; name = n;
    }
    const { host, port } = parseHostPort(s, 443);
    if (host && isValidIp(host) && !seen.has(host)) { seen.add(host); items.push({ ip: host, port, name, ...parseRegionMetadata(name) }); }
  });
  return items;
}

// 出站代理地址解析：socks5:// / http(s):// / ss:// 或 host:port，可带 user:pass@
function parseProxyAddress(addr) {
  if (!addr) return null;
  let type = 'socks5', rest = String(addr).trim();
  const m = rest.match(/^(socks5|http|https|ss):\/\/(.+)$/i);
  if (m) { type = m[1].toLowerCase(); rest = m[2]; }
  if (type === 'ss') return parseSsProxy(rest);
  let user = '', pass = '';
  if (rest.includes('@')) {
    const [u, h] = rest.split('@');
    // 修复：用户名/密码可能经 URL 编码（密码含 %40/@、%28/() 等特殊字符时），解码后再用于认证，
    // 否则 socks5 用户名密码 / HTTP Basic 认证会失败
    const dec = (s) => { try { return decodeURIComponent(s); } catch (e) { return s; } };
    const idx = u.indexOf(':');
    if (idx >= 0) { user = dec(u.slice(0, idx)); pass = dec(u.slice(idx + 1)); }
    else user = dec(u);
    rest = h;
  }
  const defaultPort = type === 'http' ? 80 : type === 'https' ? 443 : 1080;
  const { host, port } = parseHostPort(rest, defaultPort);
  return { type, host, port, user, pass };
}

// SS 出站解析：SIP002（ss://method:password@host:port#name 或 ss://BASE64(method:password)@host:port#name）
// 及旧格式 ss://BASE64(method:password@host:port)（整段无 @）。密码支持 percent-encoding。
function parseSsProxy(rest) {
  let hostPort = rest, userinfo = '';
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) hostPort = rest.slice(0, hashIdx);
  const atIdx = hostPort.lastIndexOf('@');
  if (atIdx >= 0) { userinfo = hostPort.slice(0, atIdx); hostPort = hostPort.slice(atIdx + 1); }
  else {
    const dec = b64ToUtf8(hostPort);   // 旧格式：整段 BASE64(method:password@host:port)
    if (dec && dec.includes('@')) {
      const at2 = dec.lastIndexOf('@');
      userinfo = dec.slice(0, at2); hostPort = dec.slice(at2 + 1);
    }
  }
  let method = '', password = '';
  if (userinfo) {
    let ui = b64ToUtf8(userinfo) || userinfo;   // SIP002 userinfo 可为 BASE64(method:password) 或明文
    try { ui = decodeURIComponent(ui); } catch (e) { /* 保持原样 */ }
    const ci = ui.indexOf(':');
    if (ci > 0) { method = ui.slice(0, ci); password = ui.slice(ci + 1); }
    else method = ui;
  }
  const { host, port } = parseHostPort(hostPort, 8388);
  return { type: 'ss', host, port, method, password };
}
function b64ToUtf8(s) {
  try {
    const bin = atob(String(s).replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) { return null; }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 配置优先级：默认值 < KV < 显式环境变量。
// 每次 KV get 都计入读操作；5 秒本地缓存只减少同 isolate 重复读取。
// 保存仅更新本地缓存，其他地区仍受 KV 最终一致性与边缘缓存影响。
// ---------------------------------------------------------------------------
class AppError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const CONFIG_CACHE = new WeakMap();
const PRIVATE_FIELDS = ['admin', 'trojanPassword', 'outboundProxy', 'cfApiToken'];
const ENV_FIELDS = { U: 'uuid', D: 'path', PATH: 'path', ADMIN: 'admin', admin: 'admin', S: 'outboundProxy', OUTBOUND: 'outboundProxy', TROJAN_PASSWORD: 'trojanPassword', CF_API_TOKEN: 'cfApiToken', CF_ACCOUNT_ID: 'cfAccountId' };
async function kvGetConfigCached(env) {
  if (!env.K) return null;
  const hit = CONFIG_CACHE.get(env.K);
  if (hit && Date.now() - hit.at < 5000) return hit.value;
  try {
    const raw = await withTimeout(env.K.get('config', { cacheTtl: 30 }), 3000, '配置读取超时');
    const value = raw === null ? null : JSON.parse(raw);
    if (value !== null && (!value || typeof value !== 'object' || Array.isArray(value))) throw new Error('配置格式错误');
    CONFIG_CACHE.set(env.K, { at: Date.now(), value });
    return value;
  } catch { throw new AppError(503, '配置存储暂不可用，访问已暂停'); }
}
function invalidateConfigCache(env) { if (env.K) CONFIG_CACHE.delete(env.K); }
function publicConfig(cfg, env) {
  const out = JSON.parse(JSON.stringify(cfg, (key, value) => key.startsWith('_') ? undefined : value));
  out.secretConfigured = {};
  for (const key of PRIVATE_FIELDS) { out.secretConfigured[key] = Boolean(cfg[key]); out[key] = key === 'outboundProxy' ? cfg[key] : ''; }
  out.lockedFields = [...new Set(Object.entries(ENV_FIELDS).filter(([k]) => env[k] !== undefined && env[k] !== '').map(([, v]) => v))];
  out.version = VERSION;
  return out;
}
function validateConfig(cfg) {
  if (!isUUID(cfg.uuid)) throw new AppError(503, '请配置有效的 U（UUID）');
  for (const key of ['path', 'subUrl']) {
    if (cfg[key] && (!/^[A-Za-z0-9_.~-]{1,128}$/.test(cfg[key]) || ['s','login','version','favicon.ico'].includes(cfg[key]))) throw new AppError(400, '面板路径和订阅别名必须是单个非保留路径段');
  }
  for (const key of ['enableVless','enableTrojan','enableXhttp','polling','probeAlive','nodeLimit','quotaAuto','tlsOnly','ech']) {
    if (typeof cfg[key] !== 'boolean') throw new AppError(400, '配置开关格式错误: ' + key);
  }
  if (!Array.isArray(cfg.preferredIPs) || cfg.preferredIPs.length > 2000) throw new AppError(400, '优选 IP 最多 2000 条');
  if (typeof cfg.preferredDomains !== 'string' || cfg.preferredDomains.length > 16384) throw new AppError(400, '优选来源过长');
  if (!cfg.optimizer || typeof cfg.optimizer !== 'object' || Array.isArray(cfg.optimizer)) throw new AppError(400, '优选配置格式错误');
  for (const key of ['admin','host','trojanPassword','outboundProxy','outboundMode','proxyIP','cfApiToken','cfAccountId','alpn','echHost','echDns']) {
    if (typeof cfg[key] !== 'string' || cfg[key].length > 4096 || /[\r\n\0]/.test(cfg[key])) throw new AppError(400, '配置字段格式错误: ' + key);
  }
  if (!['','no','only'].includes(cfg.outboundMode)) throw new AppError(400, '出站模式无效');
  if (cfg.preferredIPs.some(p => !p || typeof p !== 'object' || !isValidIp(p.ip) || (p.port !== undefined && (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535)) || (p.name !== undefined && (typeof p.name !== 'string' || p.name.length > 256)))) throw new AppError(400, '优选 IP 格式错误');
  if (!cfg.filter || typeof cfg.filter !== 'object' || Array.isArray(cfg.filter) || !Array.isArray(cfg.filter.ipType) || !Array.isArray(cfg.filter.isp) || cfg.filter.ipType.some(v => !['IPv4','IPv6'].includes(v)) || cfg.filter.isp.some(v => !['移动','联通','电信'].includes(v))) throw new AppError(400, '筛选配置格式错误');
  if (cfg.src !== undefined && (!cfg.src || typeof cfg.src !== 'object' || Array.isArray(cfg.src) || Object.values(cfg.src).some(v => typeof v !== 'boolean'))) throw new AppError(400, '地址来源配置格式错误');
  if (!['','custom','random'].includes(cfg.optimizer.subMode) || typeof cfg.optimizer.sourceURL !== 'string' || cfg.optimizer.sourceURL.length > 4096) throw new AppError(400, '优选来源格式错误');
  cfg.optimizer.count = Math.max(1, Math.min(200, Number(cfg.optimizer.count) || 20));
  cfg.optimizer.threads = Math.max(1, Math.min(4, Number(cfg.optimizer.threads) || 4));
  cfg.optimizer.fillCount = Math.max(0, Math.min(800, Number(cfg.optimizer.fillCount) || 0));
  cfg.nodeLimitCount = Math.max(1, Math.min(800, Number(cfg.nodeLimitCount) || 300));
}
async function loadConfig(env) {
  const cfg = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  const stored = await kvGetConfigCached(env);
  if (stored) {
    for (const key of Object.keys(stored)) if (!key.startsWith('_') && !['__proto__','constructor','prototype'].includes(key)) cfg[key] = stored[key];
    cfg.optimizer = { ...DEFAULT_CONFIG.optimizer, ...stored.optimizer };
  }
  for (const [key, field] of Object.entries(ENV_FIELDS)) if (env[key] !== undefined && env[key] !== '') cfg[field] = String(env[key]);
  if (env.HOST) cfg.host = String(env.HOST).replace(/^https?:\/\//, '').split('/')[0];
  if (env.PROXYIP) cfg.proxyIP = String(env.PROXYIP);
  if (env.ECH !== undefined) cfg.ech = /^(1|true)$/.test(String(env.ECH));
  if (env.TROJAN !== undefined) cfg.enableTrojan = /^(1|true)$/.test(String(env.TROJAN));
  if (env.ALPN) cfg.alpn = String(env.ALPN);
  if (env.YX) cfg.preferredIPs = parseIPList(env.YX);
  if (env.YXURL) cfg.optimizer.sourceURL = String(env.YXURL);
  if (env.PROBE_ALIVE !== undefined) cfg.probeAlive = /^(1|true)$/.test(String(env.PROBE_ALIVE));
  cfg._noExitProbe = /^(0|false)$/.test(String(env.RELAY_EXIT_PROBE || ''));
  cfg.uuid = String(cfg.uuid || '').toLowerCase();
  cfg.path = String(cfg.path || cfg.uuid).replace(/^\/+|\/+$/g, '');
  cfg.subUrl = String(cfg.subUrl || '').trim().replace(/^\/+|\/+$/g, '').replace(/\/sub$/, '');
  delete cfg.fragment; delete cfg.fragmentParam;
  validateConfig(cfg);
  cfg.subToken = String(env.SUB_TOKEN || await signValue(cfg.uuid, 'CFNext/subscription/v1'));
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(cfg.subToken)) throw new AppError(503, 'SUB_TOKEN 必须是 32–128 位字母、数字、下划线或连字符');
  cfg._sessionKey = String(env.SESSION_SECRET || cfg.admin || '');
  cfg._io = env._io || createIO();
  return cfg;
}
async function saveConfig(env, cfg) {
  if (!env.K || typeof env.K.put !== 'function') throw new AppError(503, '未绑定 KV K，无法保存配置');
  validateConfig(cfg);
  const clone = JSON.parse(JSON.stringify(cfg, (key, value) => key.startsWith('_') ? undefined : value));
  for (const key of ['subToken','secretConfigured','lockedFields','version']) delete clone[key];
  for (const [key, field] of Object.entries(ENV_FIELDS)) if (env[key] !== undefined && env[key] !== '') delete clone[field];
  clone.configVersion = uuidv4();
  await withTimeout(env.K.put('config', JSON.stringify(clone)), 5000, '配置写入超时');
  CONFIG_CACHE.set(env.K, { at: Date.now(), value: clone });
  return true;
}
async function signValue(secret, value) {
  const key = await crypto.subtle.importKey('raw', TE.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', key, TE.encode(value)))].map(x => x.toString(16).padStart(2,'0')).join('');
}
function constantEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  for (let i=0; i<Math.max(a.length,b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
async function sessionSignature(cfg, payload) {
  return signValue(cfg._sessionKey, 'CFNext/session/v1|' + cfg.admin + '|' + payload);
}
async function createSession(cfg) {
  const payload = Math.floor(Date.now()/1000 + 86400) + '.' + uuidv4();
  return payload + '.' + await sessionSignature(cfg, payload);
}

// ---------------------------------------------------------------------------
// 配额安全：CF 账户用量监控（参考 CF-Workers-Monitor 的 GraphQL Analytics 思路，
// 代码独立编写）—— 查询当日 Workers + Pages 请求量，对比免费额度 100,000 次/日
// ---------------------------------------------------------------------------
let QUOTA_CACHE = null;    // 模块级缓存：5 分钟内不重复请求 CF API（多 isolate 各自缓存，可接受）
let QUOTA_BACKOFF = 0;    // 429 限流退避截止时间戳（限流后 15 分钟不再请求，避免拉长限流窗口）
const QUOTA_LIMIT = 100000;
const QUOTA_TTL = 300000;         // 正常缓存 5 分钟（GraphQL Analytics 有账户级日请求配额，低频查询更稳）
const QUOTA_BACKOFF_TTL = 900000; // 429 退避 15 分钟

async function getQuota(env, cfg) {
  const accountId = String((env.CF_ACCOUNT_ID || (cfg && cfg.cfAccountId) || '')).trim();
  const token = String((env.CF_API_TOKEN || (cfg && cfg.cfApiToken) || '')).trim();
  if (!accountId || !token) return { configured: false };
  const now = Date.now();
  if(QUOTA_CACHE?.data?.updatedAt && QUOTA_CACHE.data.updatedAt.slice(0,10)!==new Date(now).toISOString().slice(0,10))QUOTA_CACHE=null;
  if(QUOTA_CACHE && (QUOTA_CACHE.accountId!==accountId || QUOTA_CACHE.tokenTag!==md5hex(token))){QUOTA_CACHE=null;QUOTA_BACKOFF=0;}
  // 限流退避窗口内：优先沿用上次成功缓存（stale 标记），无缓存则明确提示稍后再试
  if (now < QUOTA_BACKOFF) {
    if (QUOTA_CACHE && QUOTA_CACHE.data) {
      return Object.assign({}, QUOTA_CACHE.data, { stale: true, error: 'CF API 限流(429)，显示缓存数据（可能滞后）' });
    }
    return { configured: true, error: 'CF API 限流(429)，请 15 分钟后再试' };
  }
  if (QUOTA_CACHE && QUOTA_CACHE.accountId===accountId && QUOTA_CACHE.tokenTag===md5hex(token) && QUOTA_CACHE.at && (now - QUOTA_CACHE.at) < (QUOTA_CACHE.data.error ? 60000 : QUOTA_TTL)) return QUOTA_CACHE.data;
  try {
    const start = new Date(); start.setUTCHours(0, 0, 0, 0);
    const end = new Date();
    const query = {
      query: `query getBillingMetrics($accountId: string!) {
        viewer { accounts(filter:{accountTag:$accountId}) {
          workersInvocationsAdaptive(limit:10000, filter:{datetime_geq:"${start.toISOString()}",datetime_leq:"${end.toISOString()}"}) { sum { requests subrequests } quantiles { cpuTimeP50 } }
          pagesFunctionsInvocationsAdaptiveGroups(limit:1000, filter:{datetime_geq:"${start.toISOString()}",datetime_leq:"${end.toISOString()}"}) { sum { requests } }
        } }
      }`,
      variables: { accountId }
    };
    const res = await fetchTimeout('https://api.cloudflare.com/client/v4/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify(query)
    },5000,cfg._io);
    if (!res) throw new Error('监控请求超时或预算耗尽');
    if (!res.ok) throw new Error('CF API HTTP ' + res.status);
    const data = await res.json();
    if (data.errors && data.errors.length) throw new Error('GraphQL: ' + JSON.stringify(data.errors).slice(0, 200));
    const accounts = (data && data.data && data.data.viewer && data.data.viewer.accounts) || [];
    if (!accounts.length) throw new Error('未找到账户数据（检查账户 ID 与令牌权限）');
    const acc = accounts[0];
    const rows = acc.workersInvocationsAdaptive || [];
    const w = rows[0] || {};
    const p = (acc.pagesFunctionsInvocationsAdaptiveGroups || []).reduce((s, g) => s + ((g && g.sum && g.sum.requests) || 0), 0);
    const requests = rows.reduce((s,g)=>s+(g?.sum?.requests||0),0) + p;
    const cpuTime = (w.quantiles && w.quantiles.cpuTimeP50) || 0;
    const subrequests = rows.reduce((s,g)=>s+(g?.sum?.subrequests||0),0);
    const percent = QUOTA_LIMIT > 0 ? Math.round((requests / QUOTA_LIMIT) * 1000) / 10 : 0;
    const dataOut = {
      configured: true,
      limit: QUOTA_LIMIT,
      today: { requests, cpuTime, subrequests },
      percent,                                            // 0 - 100（一位小数）
      remaining: Math.max(0, QUOTA_LIMIT - requests),
      updatedAt: end.toISOString()
    };
    QUOTA_CACHE = { at: now,accountId,tokenTag:md5hex(token),data:dataOut };
    return dataOut;
  } catch (e) {
    const msg = (e && e.message) || String(e);
    if (msg.indexOf('429') >= 0) {
      QUOTA_BACKOFF = now + QUOTA_BACKOFF_TTL;
      if (QUOTA_CACHE && QUOTA_CACHE.data) {
        return Object.assign({}, QUOTA_CACHE.data, { stale: true, error: 'CF API 限流(429)，显示缓存数据（可能滞后）' });
      }
      return { configured: true, error: 'CF API 限流(429)，请 15 分钟后再试' };
    }
    const failed={configured:true,error:msg};QUOTA_CACHE={at:now,accountId,tokenTag:md5hex(token),data:failed};return failed;
  }
}

// ---------------------------------------------------------------------------
// VLESS / Trojan 请求头解析
// ---------------------------------------------------------------------------
function needBytes(data, length) { if (data.length < length) throw new AppError(400, '头部过短'); }
function readAddress(data, view, offset, atyp) {
  if (atyp === 1) { needBytes(data, offset+4); return { addr: [...data.subarray(offset,offset+4)].join('.'), len:4 }; }
  if (atyp === 2) {
    needBytes(data, offset+1); const len = view.getUint8(offset);
    if (!len) throw new AppError(400, '空域名');
    needBytes(data, offset+1+len);
    const addr = TD.decode(data.subarray(offset+1,offset+1+len));
    if (!/^[A-Za-z0-9.-]+$/.test(addr)) throw new AppError(400, '域名格式错误');
    return { addr, len:1+len };
  }
  if (atyp === 3) { needBytes(data,offset+16); return { addr:formatIPv6(data.subarray(offset,offset+16)),len:16 }; }
  throw new AppError(400, '地址类型不支持');
}
function parseVlessHeader(data) {
  needBytes(data,18);
  if (data[0] !== 0) throw new AppError(400,'不支持的 VLESS 版本');
  const uuid = [...data.subarray(1,17)].map(x=>x.toString(16).padStart(2,'0')).join('');
  const view = new DataView(data.buffer,data.byteOffset,data.byteLength);
  let offset=18+data[17]; needBytes(data,offset+4);
  const command=data[offset++], port=view.getUint16(offset); offset+=2;
  const atyp=data[offset++], address=readAddress(data,view,offset,atyp); offset+=address.len;
  if (!port) throw new AppError(400,'端口错误');
  return { command,port,addr:address.addr,uuid,headerLength:offset,earlyData:data.subarray(offset) };
}
function parseTrojanHeader(data) {
  needBytes(data,60);
  if (data[56]!==13 || data[57]!==10) throw new AppError(400,'Trojan 头格式错误');
  const view=new DataView(data.buffer,data.byteOffset,data.byteLength);
  const command=data[58], atyp=({1:1,3:2,4:3})[data[59]];
  const address=readAddress(data,view,60,atyp);
  let offset=60+address.len; needBytes(data,offset+4);
  const port=view.getUint16(offset); offset+=2;
  if (!port || data[offset]!==13 || data[offset+1]!==10) throw new AppError(400,'Trojan 地址格式错误');
  return {command,port,addr:address.addr,password:TD.decode(data.subarray(0,56)),headerLength:offset+2};
}
function authenticateProxy(parsed, cfg, protocol) {
  if (protocol==='trojan') {
    if (!cfg.enableTrojan || !constantEqual(parsed.password, trojanPasswordHash(cfg.trojanPassword || cfg.uuid))) throw new AppError(403,'代理认证失败');
  } else {
    if (!(protocol==='xhttp' ? cfg.enableXhttp : cfg.enableVless) || !constantEqual(parsed.uuid,cfg.uuid.replace(/-/g,''))) throw new AppError(403,'代理认证失败');
  }
  if (parsed.command !== 1) throw new AppError(400,'当前仅支持 TCP，请在客户端使用本地 DNS/DoH');
}


// Trojan 协议密码使用 SHA-224（56 字节 hex）——Cloudflare WebCrypto 不支持 SHA-224，手写实现（SHA-256 结构 + SHA-224 初始值）
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
function sha224hex(str) {
  const bytes = str instanceof Uint8Array ? str : TE.encode(String(str));
  const bitLen = bytes.length * 8;
  const paddedLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const data = new Uint8Array(paddedLen);
  data.set(bytes);
  data[bytes.length] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);   // SHA-2 大端 64 位长度
  dv.setUint32(paddedLen - 4, bitLen >>> 0, false);
  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939,
      h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let i = 0; i < paddedLen; i += 64) {
    const w = new Uint32Array(64);
    for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);  // 大端读消息字
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[j] + w[j]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  let hex = '';
  for (const v of [h0, h1, h2, h3, h4, h5, h6]) {
    hex += (v >>> 24 & 255).toString(16).padStart(2, '0');
    hex += (v >>> 16 & 255).toString(16).padStart(2, '0');
    hex += (v >>> 8 & 255).toString(16).padStart(2, '0');
    hex += (v & 255).toString(16).padStart(2, '0');
  }
  return hex;
}
// Trojan 密码 SHA-224 摘要缓存：同一密码只计算一次，避免 WebSocket 每帧连接重复跑完整 SHA-224
let _trojanPassC = '', _trojanHashC = '';
function trojanPasswordHash(pass) {
  if (pass !== _trojanPassC) { _trojanPassC = pass; _trojanHashC = sha224hex(pass); }
  return _trojanHashC;
}
// Trojan 头判定（v1.0.5 修复）：56 字节 SHA224 hex + CRLF；密码匹配或纯 hex 特征均可识别
function detectTrojan(pending, cfg) {
  if (!pending || pending.length < 58) return false;
  return /^[0-9a-fA-F]{56}\r\n$/.test(TD.decode(pending.subarray(0,58)));
}

// DoH 端点池（UDP/DNS → DoH 转换用；v1.0.5 修复：V2rayNG 关闭「本地 DNS」时远端 DNS 不可用）
const DOH_ENDPOINTS = [
  'https://doh.pub/dns-query',
  'https://dns.alidns.com/resolve',
  'https://1.1.1.1/dns-query',
  'https://8.8.8.8/dns-query',
  'https://dns.google/dns-query',
  'https://cloudflare-dns.com/dns-query'
];
// IPv6 字符串 → 16 字节（支持 :: 压缩）
function ipv6ToBytes(ip) {
  const sp = String(ip).split('::');
  const h = sp[0] ? sp[0].split(':').filter(Boolean) : [];
  const t = sp[1] ? sp[1].split(':').filter(Boolean) : [];
  const parts = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  const out = new Uint8Array(16);
  parts.forEach((p, i) => { const n = parseInt(p, 16) || 0; out[i * 2] = (n >> 8) & 255; out[i * 2 + 1] = n & 255; });
  return out;
}
// 解析标准 DNS 查询（12B 头 + QNAME + QTYPE + QCLASS），经 DoH 查询后构造标准 DNS 响应（仅 A/AAAA 单查询）
async function dnsToDoH(query) {
  if (!query || query.byteLength < 17) return null;
  const view = new DataView(query.buffer, query.byteOffset, query.byteLength);
  const id = view.getUint16(0);
  if (view.getUint16(2) & 0x8000) return null;           // 非查询报文直接忽略
  if (view.getUint16(4) !== 1) return null;               // 仅支持单问题查询
  let off = 12, labels = [];
  while (off < query.byteLength) {
    const len = view.getUint8(off);
    if (len === 0) { off++; break; }
    if ((len & 0xC0) === 0xC0) { off += 2; break; }       // 压缩指针（罕见，直接略过）
    if (off + 1 + len > query.byteLength) return null;
    labels.push(TD.decode(query.subarray(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  if (off + 4 > query.byteLength || labels.length === 0) return null;
  const qtype = view.getUint16(off);                      // 1=A 28=AAAA
  const qclass = view.getUint16(off + 2);
  const qEnd = off + 4;
  if (qtype !== 1 && qtype !== 28) return null;           // 仅 A/AAAA
  const name = labels.join('.');
  const question = query.subarray(12, qEnd);              // 响应中原样回显
  let answer = null;
  for (const ep of DOH_ENDPOINTS) {
    try {
      const r = await fetchTimeout(ep + '?name=' + encodeURIComponent(name) + '&type=' + qtype,
        { headers: { accept: 'application/dns-json' } }, 5000);
      if (!r || !r.ok) continue;
      const j = await r.json();
      if (!j || j.Status !== 0) continue;
      const an = (j.Answer || []).filter(a => a.type === qtype && (a.type === 1 ? isValidIp(String(a.data)) : /^[0-9a-fA-F:]+$/.test(String(a.data))));
      if (an.length) { answer = an; break; }
    } catch (e) { /* 尝试下一个 DoH 端点 */ }
  }
  if (!answer) return null;
  const header = new Uint8Array(12);
  const dv = new DataView(header.buffer);
  dv.setUint16(0, id); dv.setUint16(2, 0x8180); dv.setUint16(4, 1); dv.setUint16(6, answer.length);
  const chunks = [header, question];
  for (const a of answer) {
    const data = String(a.data);
    const rdata = a.type === 1 ? Uint8Array.from(data.split('.').map(Number)) : ipv6ToBytes(data);
    if (rdata.length !== (a.type === 1 ? 4 : 16)) continue;
    const h = new Uint8Array(10);
    const dh = new DataView(h.buffer);
    dh.setUint16(0, 0xC00C); dh.setUint16(2, a.type); dh.setUint16(4, qclass === 0 ? 1 : qclass);
    dh.setUint32(6, Number(a.TTL) || 300);
    chunks.push(h, new Uint8Array([(rdata.length >> 8) & 255, rdata.length & 255]), rdata);
  }
  let total = 0; chunks.forEach(c => total += c.byteLength);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

// ---------------------------------------------------------------------------
// 出站连接：直连 / SOCKS5 / HTTP CONNECT / 反代 IP 中继
// ---------------------------------------------------------------------------
// 通用超时助手：promise 超时即 reject（出站层兜底，避免目标 SYN 被静默丢弃时永久阻塞）
function withTimeout(promise, ms, msg) {
  let timer;
  return Promise.race([promise,new Promise((_,reject)=>{ timer=setTimeout(()=>reject(new AppError(504,msg || '操作超时')),ms || 6000); })]).finally(()=>clearTimeout(timer));
}
function closeSocket(socket) { if (socket) { try { Promise.resolve(socket.close()).catch(()=>{}); } catch {} } }
async function connectWithTimeout(hostname, port, ms, secure = false) {
  if (!hostname || !Number.isInteger(Number(port)) || port<1 || port>65535) throw new AppError(400,'目标地址错误');
  const socket = connect({hostname,port:Number(port)}, {secureTransport:secure ? 'on':'off', allowHalfOpen:true});
  socket.closed.catch(()=>{});
  try { await withTimeout(socket.opened,ms || 6000,'连接超时'); return socket; }
  catch (e) { closeSocket(socket); throw e; }
}

async function connectDirect(target, timeoutMs) {
  return connectWithTimeout(target.hostname, target.port, timeoutMs || 6000);
}

async function connectProxyTransport(proxy, timeoutMs, secure = false) {
  try { return await connectWithTimeout(proxy.host, proxy.port, timeoutMs, secure); }
  catch (error) { error.proxyUnavailable = true; throw error; }
}

// 通过 SOCKS5 代理建立到目标的连接
async function connectViaSocks5(proxy, target, timeoutMs = 6000) {
  // TCP 与代理握手共享期限，失效 IP 不能分别耗尽两轮超时。
  const deadline = Date.now() + timeoutMs;
  const socket = await connectProxyTransport(proxy, timeoutMs);
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let targetRequested = false;
  const handshake = async () => {
  // 带缓存的读取器：多余字节保留，避免丢失后续 VLESS 数据流
  let pending = new Uint8Array(0);
  const readN = async (n) => {
    while (pending.length < n) {
      const { done, value } = await reader.read();
      if (done) throw new Error('连接被关闭');
      pending = concatBytes(pending, value);
      if (pending.length > RESOURCE_LIMITS.bufferBytes) throw new Error('SOCKS5 缓冲超限');
    }
    const out = pending.slice(0, n);
    pending = pending.subarray(n);
    return out;
  };
  // 握手：声明支持的方法（有凭据则同时声明无认证+用户名密码，服务器选择其一）
  const methods = proxy.user ? [5, 2, 0, 2] : [5, 1, 0];
  await writer.write(new Uint8Array(methods));
  const h1 = await readN(2);
  if (h1[0] !== 5 || h1[1] === 0xff) throw new Error('SOCKS5 握手失败');
  if (h1[1] === 2) { // 服务器选择用户名密码认证（RFC 1929）
    if (!proxy.user) throw new Error('SOCKS5 服务器要求认证但未提供凭据');
    const u = TE.encode(proxy.user), p = TE.encode(proxy.pass);
    if (u.length > 255 || p.length > 255) throw new Error('SOCKS5 凭据过长');
    const auth = new Uint8Array([1, u.length, ...u, p.length, ...p]);
    await writer.write(auth);
    const h2 = await readN(2);
    if (h2[0] !== 1 || h2[1] !== 0) throw new Error('SOCKS5 认证失败');
  } else if (h1[1] !== 0) {
    throw new Error('SOCKS5 不支持的认证方法 ' + h1[1]);
  }
  // CONNECT 请求
  const connReq = new Uint8Array([5,1,0,...encodeSocksAddress(target)]);
  targetRequested = true;
  await writer.write(connReq);
  const rep = await readN(4);
  if (rep[0] !== 5 || rep[2] !== 0 || ![1,3,4].includes(rep[3]) || rep[1] !== 0) throw new Error('SOCKS5 连接失败 码' + rep[1]);
  // 跳过 BND.ADDR + BND.PORT（必须完整消费否则残留字节污染后续 VLESS 数据流）
  if (rep[3] === 1) await readN(6);
  else if (rep[3] === 3) { const l = (await readN(1))[0]; await readN(l + 2); }
  else if (rep[3] === 4) await readN(18);
  // 修复：握手期间多读的字节（目标端早期数据）不能直接丢弃，挂到 socket._preamble，
  // 由 WebSocket / xhttp 转发前先补发给客户端，避免 Telegram 等 TLS 握手中途被截断
  if (pending.byteLength > 0) socket._preamble = pending;
  return socket;
  };
  try { return await withTimeout(handshake(),Math.max(1,deadline-Date.now()),'代理握手超时'); }
  catch(e) { if(!targetRequested)e.proxyUnavailable=true; closeSocket(socket); throw e; }
  finally { try { writer.releaseLock(); } catch {} try { reader.releaseLock(); } catch {} }
}

// 通过 HTTP/HTTPS CONNECT 代理建立连接
async function connectViaHttpProxy(proxy, target, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  const socket = await connectProxyTransport(proxy, timeoutMs, proxy.type === 'https');
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const handshake = async () => {
  let authHeader = '';
  if (proxy.user) authHeader = 'Proxy-Authorization: Basic ' + b64FromBytes(TE.encode(`${proxy.user}:${proxy.pass}`)) + '\r\n';
  const authority = (target.hostname.includes(':') ? '[' + target.hostname + ']' : target.hostname) + ':' + target.port;
  const connectReq = `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${authHeader}\r\n`;
  await writer.write(TE.encode(connectReq));
  // 读取响应头直到空行；空行后同包多读的字节（目标端早期数据）一并保留
  const { head, leftover } = await readUntilCRLFCRLF(reader);
  if (!/^HTTP\/\d\.\d\s+2\d\d/i.test(head)) throw new Error('HTTP 代理 CONNECT 失败: ' + head.split('\r\n')[0]);
  // 修复：残留字节挂 socket._preamble，由 WebSocket / xhttp 转发前先补发给客户端
  if (leftover && leftover.byteLength > 0) socket._preamble = leftover;
  return socket;
  };
  try { return await withTimeout(handshake(),Math.max(1,deadline-Date.now()),'代理握手超时'); }
  catch(e) { closeSocket(socket); throw e; }
  finally { try { writer.releaseLock(); } catch {} try { reader.releaseLock(); } catch {} }
}

// ---------------------------------------------------------------------------
// Shadowsocks AEAD 出站代理客户端（ss://）：aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
// 协议：salt 长度等于密钥长度；EVP_BytesToKey + HKDF-SHA1(ss-subkey)。
// 首个加密负载为目标地址；2B 大端长度和负载分别认证；12B nonce 从零按小端递增。
// ---------------------------------------------------------------------------
function ssCipherAlgo(method) {
  const m = String(method || '').toLowerCase().replace(/_/g, '-');
  if (m === 'aes-128-gcm' || m === 'aes-128gcm') return { name: 'AES-GCM', keyLen: 16 };
  if (m === 'aes-256-gcm' || m === 'aes-256gcm') return { name: 'AES-GCM', keyLen: 32 };
  if (m === 'chacha20-ietf-poly1305' || m === 'chacha20-poly1305' || m === 'chacha20poly1305') return { name: 'CHACHA20-POLY1305', keyLen: 32 };
  return null;
}
// ---------- SS 加密原语（纯 JS，兼容 CF Workers / Node / 浏览器） ----------
// CF Workers 的 crypto.subtle 官方支持矩阵不含 CHACHA20-POLY1305（SS 最常用的 chacha20-ietf-poly1305
// 用 WebCrypto 会抛 NotSupportedError → 出站全超时），故 chacha20-poly1305（RFC 8439）与
// HKDF-SHA1 用纯 JS 实现，不依赖 WebCrypto；AES-GCM 保留 WebCrypto（CF 明确支持、性能好）。
// （rotl32 复用文件已有的 MD5 实现 737 行 function rotl32）

// SHA-1（FIPS 180-4）
function sha1Bytes(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const ml = bytes.length, lenBits = ml * 8;
  const padded = new Uint8Array((((ml + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[ml] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(lenBits / 0x100000000), false);
  dv.setUint32(padded.length - 4, lenBits >>> 0, false);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 80; i++) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const tmp = (rotl32(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20), ov = new DataView(out.buffer);
  ov.setUint32(0, h0, false); ov.setUint32(4, h1, false); ov.setUint32(8, h2, false);
  ov.setUint32(12, h3, false); ov.setUint32(16, h4, false);
  return out;
}
// HMAC-SHA1（RFC 2104）
function hmacSha1(key, data) {
  const block = 64;
  let k = key;
  if (k.length > block) k = sha1Bytes(k);
  const ipad = new Uint8Array(block), opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) { ipad[i] = (i < k.length ? k[i] : 0) ^ 0x36; opad[i] = (i < k.length ? k[i] : 0) ^ 0x5c; }
  return sha1Bytes(concatBytes(opad, sha1Bytes(concatBytes(ipad, data))));
}
// HKDF-SHA1（RFC 5869，info="ss-subkey"）：SS AEAD 会话密钥派生
function hkdfSha1(ikm, salt, keyLen) {
  const prk = hmacSha1(salt && salt.length ? salt : new Uint8Array(20), ikm);
  let t = new Uint8Array(0), okm = new Uint8Array(0);
  for (let i = 1; okm.length < keyLen; i++) {
    const ti = new Uint8Array([i]);
    t = hmacSha1(prk, concatBytes(concatBytes(t, TE.encode('ss-subkey')), ti));
    okm = concatBytes(okm, t);
  }
  return okm.slice(0, keyLen);
}

// ---------- ChaCha20-Poly1305 AEAD（RFC 8439，纯 JS） ----------
function chacha20Block(key32, counter, nonce12) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  const dv = new DataView(key32.buffer, key32.byteOffset, 32);
  for (let i = 0; i < 8; i++) st[4 + i] = dv.getUint32(i * 4, true);
  st[12] = counter >>> 0;
  const nv = new DataView(nonce12.buffer, nonce12.byteOffset, 12);
  st[13] = nv.getUint32(0, true); st[14] = nv.getUint32(4, true); st[15] = nv.getUint32(8, true);
  const w = st.slice();
  const qr = (a, b, c, d) => {
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 16);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 12);
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 8);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = new Uint8Array(64), odv = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) { w[i] = (w[i] + st[i]) >>> 0; odv.setUint32(i * 4, w[i], true); }
  return out;
}
function chacha20Xor(key32, nonce12, counterStart, data) {
  const out = new Uint8Array(data);
  const blocks = Math.ceil(data.length / 64);
  for (let b = 0; b < blocks; b++) {
    const ks = chacha20Block(key32, counterStart + b, nonce12);
    const off = b * 64, n = Math.min(64, out.length - off);
    for (let i = 0; i < n; i++) out[off + i] ^= ks[i];
  }
  return out;
}
// Poly1305（RFC 8439 §2.5，BigInt 实现，简洁可靠）
function poly1305(key32, msg) {
  let r = 0n, p = 0n;
  // RFC 8439 §2.5：r = le_bytes_to_num(key[0..16))，s = le_bytes_to_num(key[16..32))（小端）
  for (let i = 0; i < 16; i++) { r |= BigInt(key32[i]) << BigInt(8 * i); p |= BigInt(key32[16 + i]) << BigInt(8 * i); }
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  let h = 0n;
  const MOD = (1n << 130n) - 5n;
  // RFC 8439 §2.5.1：每块 n_i = 块内容 || 0x01（小端）。完整 16B 块 → 内容 + 2^128；
  // 不足 16B 的最后一块不补齐 → 内容 + 2^(8*实际字节数)。
  for (let i = 0; i < msg.length; i += 16) {
    const n = Math.min(16, msg.length - i);
    let c = 1n;
    for (let j = n - 1; j >= 0; j--) c = (c << 8n) | BigInt(msg[i + j]);
    h = ((h + c) * r) % MOD;
  }
  h = (h + p) & ((1n << 128n) - 1n);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) tag[i] = Number((h >> BigInt(8 * i)) & 0xffn);
  return tag;
}
// AEAD_CHACHA20_POLY1305（RFC 8439 §2.8）；输出 = 密文 || 16B tag
function chacha20Poly1305Seal(key32, nonce12, plaintext, aad) {
  const aadB = aad || new Uint8Array(0);
  const polyKey = chacha20Xor(key32, nonce12, 0, new Uint8Array(32));
  const ct = chacha20Xor(key32, nonce12, 1, plaintext);
  const pad16 = (len) => new Uint8Array((16 - (len % 16)) % 16);
  const le64 = (n) => {
    const b = new Uint8Array(8), dv = new DataView(b.buffer);
    dv.setUint32(0, n >>> 0, true); dv.setUint32(4, Math.floor(n / 0x100000000), true);
    return b;
  };
  const macData = concatBytes(aadB, concatBytes(pad16(aadB.length), concatBytes(ct,
    concatBytes(pad16(ct.length), concatBytes(le64(aadB.length), le64(ct.length))))));
  const tag = poly1305(polyKey, macData);
  return concatBytes(ct, tag);
}
function chacha20Poly1305Open(key32, nonce12, data, aad) {
  if (data.length < 16) throw new Error('SS AEAD 数据过短');
  const ct = data.subarray(0, data.length - 16);
  const got = data.subarray(data.length - 16);
  const aadB = aad || new Uint8Array(0);
  const polyKey = chacha20Xor(key32, nonce12, 0, new Uint8Array(32));
  const pad16 = (len) => new Uint8Array((16 - (len % 16)) % 16);
  const le64 = (n) => {
    const b = new Uint8Array(8), dv = new DataView(b.buffer);
    dv.setUint32(0, n >>> 0, true); dv.setUint32(4, Math.floor(n / 0x100000000), true);
    return b;
  };
  const macData = concatBytes(aadB, concatBytes(pad16(aadB.length), concatBytes(ct,
    concatBytes(pad16(ct.length), concatBytes(le64(aadB.length), le64(ct.length))))));
  const expect = poly1305(polyKey, macData);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= expect[i] ^ got[i];
  if (diff !== 0) return null;
  return chacha20Xor(key32, nonce12, 1, ct);
}
async function newSsAead(algoName, keyBytes) {
  const nonce = new Uint8Array(12);
  const next = () => {
    const n = nonce.slice();
    for (let i = 0; i < nonce.length; i++) { nonce[i]++; if (nonce[i] !== 0) break; }
    return n;
  };
  if (algoName === 'CHACHA20-POLY1305') {
    // 纯 JS：CF Workers 的 crypto.subtle 不支持该算法
    return {
      seal(data) { return chacha20Poly1305Seal(keyBytes, next(), data); },
      open(data) {
        const plain = chacha20Poly1305Open(keyBytes, next(), data);
        if (!plain) throw new Error('SS AEAD 解密失败（密码/加密方式与服务器不匹配）');
        return plain;
      }
    };
  }
  // AES-GCM：WebCrypto（CF 明确支持）
  const ck = await crypto.subtle.importKey('raw', keyBytes, { name: algoName }, false, ['encrypt', 'decrypt']);
  return {
    async seal(data) { return new Uint8Array(await crypto.subtle.encrypt({ name: algoName, iv: next() }, ck, data)); },
    async open(data) {
      try { return new Uint8Array(await crypto.subtle.decrypt({ name: algoName, iv: next() }, ck, data)); }
      catch (e) { throw new Error('SS AEAD 解密失败（密码/加密方式与服务器不匹配）'); }
    }
  };
}
async function ssSealChunk(aead, data) {
  const len = new Uint8Array([(data.length >> 8) & 255, data.length & 255]);
  return concatBytes(await aead.seal(len), await aead.seal(data));
}


// 通过 SS 出站代理建立到目标的加密隧道；返回兼容 socket 语义的包装（readable 已解密 / writable 自动加密）
function ssMasterKey(password, length) {
  const passwordBytes=TE.encode(password); let prev=new Uint8Array(0), key=new Uint8Array(0);
  while(key.length<length) {
    const hex=md5hex(concatBytes(prev,passwordBytes));
    prev=Uint8Array.from(hex.match(/../g), x=>parseInt(x,16)); key=concatBytes(key,prev);
  }
  return key.slice(0,length);
}
function encodeSocksAddress(target) {
  let addr;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target.hostname)) addr=new Uint8Array([1,...target.hostname.split('.').map(Number)]);
  else if (target.hostname.includes(':')) addr=new Uint8Array([4,...ipv6ToBytes(target.hostname)]);
  else { const host=TE.encode(target.hostname); if(!host.length || host.length>255) throw new AppError(400,'目标域名过长'); addr=new Uint8Array([3,host.length,...host]); }
  return new Uint8Array([...addr,(target.port>>8)&255,target.port&255]);
}
async function connectViaShadowsocks(proxy, target, timeoutMs = 6000) {
  const algo=ssCipherAlgo(proxy.method);
  if(!algo || !proxy.password) throw new AppError(400,'SS 配置不完整或算法不支持');
  const deadline=Date.now()+timeoutMs;
  const raw=await connectProxyTransport(proxy,timeoutMs);
  const rw=raw.writable.getWriter(), rr=raw.readable.getReader();
  const master=ssMasterKey(proxy.password,algo.keyLen);
  let pending=new Uint8Array(0), ended=false, serverAead;
  const take=async(n)=>{
    while(pending.length<n) {
      const {done,value}=await rr.read();
      if(done) { if(pending.length===0) return null; throw new Error('SS 数据被截断'); }
      pending=concatBytes(pending,value);
      if(pending.length>RESOURCE_LIMITS.bufferBytes) throw new Error('SS 缓冲超限');
    }
    const out=pending.slice(0,n);pending=pending.subarray(n);return out;
  };
  const required=async(n)=>{ const out=await take(n); if(!out) throw new Error('SS 数据被截断'); return out; };
  const cleanup=()=>{ if(ended)return;ended=true;closeSocket(raw);try{rw.releaseLock()}catch{}try{rr.releaseLock()}catch{} };
  try {
    const salt=crypto.getRandomValues(new Uint8Array(algo.keyLen));
    const clientAead=await newSsAead(algo.name,hkdfSha1(master,salt,algo.keyLen));
    await withTimeout((async()=>{
      await rw.write(salt);
      await rw.write(await ssSealChunk(clientAead,encodeSocksAddress(target)));
    })(),Math.max(1,deadline-Date.now()),'SS 握手写入超时');
    const readable=new ReadableStream({
      async pull(controller) {
        try {
          if(!serverAead) { const salt=await required(algo.keyLen); serverAead=await newSsAead(algo.name,hkdfSha1(master,salt,algo.keyLen)); }
          const lengthBox=await take(18);
          if(!lengthBox) {controller.close();cleanup();return;}
          const lb=await serverAead.open(lengthBox), len=(lb[0]<<8)|lb[1];
          if(len>0x3fff) throw new Error('SS 分片超限');
          controller.enqueue(await serverAead.open(await required(len+16)));
        } catch(e) {controller.error(e);cleanup();}
      }, cancel(){cleanup();}
    },{highWaterMark:RESOURCE_LIMITS.bufferBytes,size:chunk=>chunk.byteLength});
    const writable=new WritableStream({
      async write(chunk) {
        try {
          const data=new Uint8Array(chunk);
          for(let off=0;off<data.length;off+=0x3fff) await withTimeout(rw.write(await ssSealChunk(clientAead,data.subarray(off,off+0x3fff))),15000,'SS 写入超时');
        }catch(e){cleanup();throw e;}
      }, async close(){await rw.close();}, abort(){cleanup();}
    },{highWaterMark:RESOURCE_LIMITS.bufferBytes,size:chunk=>chunk.byteLength});
    return {readable,writable,close:cleanup};
  } catch(e){cleanup();throw e;}
}

async function readN(reader, n) {
  const out = new Uint8Array(n);
  let got = 0;
  while (got < n) {
    const { done, value } = await reader.read();
    if (done) throw new Error('连接被关闭');
    const need = n - got;
    out.set(value.subarray(0, Math.min(need, value.length)), got);
    got += Math.min(need, value.length);
  }
  return out;
}
async function readUntilCRLFCRLF(reader) {
  let buf = new Uint8Array(0);
  while (buf.length < 65536) {
    const { done, value } = await reader.read();
    if (done) break;
    buf = concatBytes(buf, value);
    const idx = findBytes(buf, [13, 10, 13, 10]);
    // 修复：返回头部文本 + 空行之后同一包内多读的残留字节（不再丢弃）
    if (idx >= 0) return { head: TD.decode(buf.subarray(0, idx)), leftover: buf.subarray(idx + 4) };
  }
  throw new Error('HTTP 代理响应头不完整或超限');
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
function findBytes(hay, needle) {
  outer:
  for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// 内置地区反代域名池：proxyip.<地区>.cmliussss.net 社区反代服务（解析为非 Cloudflare IP）
// 出站兜底：直连与自定义反代均失败后使用，透明代理模式发送去掉 VLESS 头部的原始
// TLS 数据，由对端按 SNI 路由到目标
// ---------------------------------------------------------------------------
const RELAY_DOMAINS = {
  // 【键序 = 兜底顺序】openOutbound 取 [primary, ...本表键序] 的前 3 个依次尝试。
  // 2026-09-25：HK 从第 1 位移到 GB 之后 —— 香港出口被 ChatGPT / Claude / Gemini 等封禁，
  // 不能出现在任何机房的兜底前排（原来 primary=US 时会按 US→HK→AU 试，第一兜底就是香港）。
  AU: 'proxyip.au.cmliussss.net',
  US: 'proxyip.us.cmliussss.net',
  SG: 'proxyip.sg.cmliussss.net',
  JP: 'proxyip.jp.cmliussss.net',
  KR: 'proxyip.kr.cmliussss.net',
  DE: 'proxyip.de.cmliussss.net',
  SE: 'proxyip.se.cmliussss.net',
  NL: 'proxyip.nl.cmliussss.net',
  FI: 'proxyip.fi.cmliussss.net',
  GB: 'proxyip.gb.cmliussss.net',
  HK: 'proxyip.hk.cmliussss.net',
  Oracle: 'proxyip.oracle.cmliussss.net',
  DigitalOcean: 'proxyip.digitalocean.cmliussss.net',
  Vultr: 'proxyip.vultr.cmliussss.net',
  Multacom: 'proxyip.multacom.cmliussss.net'
};

// 根据 Worker 所在机房 colo（IATA 代码）选择最近的地区反代（RELAY_DOMAINS 的键）。
//
// 【修正 2026-09-25】原实现用 startsWith 前缀匹配，导致 **5 个机房**被判到错误地区，
// 出站会走错地区的反代 —— 其中被判到香港的会被 ChatGPT / Claude / Gemini 等大量服务判为不可用地区：
//   ① SJC（圣何塞，美西）被兜底那行归为 HK  → 应 US。该行除 SJC 外全部与上面几行重复，实际只对 SJC 生效。
//   ② SEA（西雅图，美西）被 startsWith('SE') 判为 SE（瑞典）→ 应 US。
//   ③ DEN（丹佛，美西）被 startsWith('DE') 判为 DE（德国）→ 应 US。
//   ④ ATL（亚特兰大，美东）被兜底正则里的 AT（奥地利）判为 DE → 应 US。
//   ⑤ DEL（德里，印度）被同一条正则里的 DE 判为 DE → 应 US（原实现的默认值）。
// 根因：对 3 字 IATA 码做前缀匹配必然误伤（任意短前缀都可能撞上别的城市码）。
// 现改为按 3 字码**精确匹配**（request.cf.colo 恒为 3 字码），表内未收录的码统一默认 US
// （美区反代对 AI 服务最安全，也是原实现的默认值）。
// 【出口归并】某些机房的流量改由别的地区反代出 —— 仅在某机房本地出口被目标站封禁时才需要。
//   当前为**空表**（没有任何机房被归并）：
//     TPE 于 2026-09-25 撤销（台湾本来就没有可用的地区反代池）；
//     HKG 随后按用户要求一并撤销 —— 香港出口就写香港。COLO_REGION_MAP 本就把 HKG 判为 HK，
//     撤销后香港机房的 primary 反代即 proxyip.hk.cmliussss.net，名字与实际出口一致。
// 归并生效时必须两边同源：运行时用目标地区反代（selectRelayRegion），节点名也写目标地区（geoNameSuffix），
// 否则名字会与「网站实际看到的地点」不符。
// 需要重新归并时在下面加一项即可（例：HKG 归并到 JP 写作 HKG: 'JP'）—— COLO_REGION_MAP 的地理真相不受影响。
const EXIT_VIA_REGION = {};

// 各反代地区的「代表出口地点」，用于归并后的节点命名。
// 注意：出口是**反代机**（不在 CF 机房），这里的 code 只是该地区的代表码，
// 不表示流量真的经过那个 CF 机房。JP 取东京 —— 实测 jp 池 46 条 A 记录里东京占 81%
// （Tokyo 28 + 港区/千代田等 6），其余为大阪 6、横滨 1。
const REGION_EXIT_GEO = {
  JP: { zh: '日本', cc: 'JP', city: '东京', code: 'TYO' },
  HK: { zh: '中国香港', cc: 'HK', city: '香港', code: 'HKG' },
  SG: { zh: '新加坡', cc: 'SG', city: '新加坡', code: 'SIN' },
  KR: { zh: '韩国', cc: 'KR', city: '首尔', code: 'ICN' },
  US: { zh: '美国', cc: 'US', city: '洛杉矶', code: 'LAX' },
  AU: { zh: '澳大利亚', cc: 'AU', city: '悉尼', code: 'SYD' },
  DE: { zh: '德国', cc: 'DE', city: '法兰克福', code: 'FRA' },
  SE: { zh: '瑞典', cc: 'SE', city: '斯德哥尔摩', code: 'ARN' },
  NL: { zh: '荷兰', cc: 'NL', city: '阿姆斯特丹', code: 'AMS' },
  FI: { zh: '芬兰', cc: 'FI', city: '赫尔辛基', code: 'HEL' },
  GB: { zh: '英国', cc: 'GB', city: '伦敦', code: 'LHR' }
};

const COLO_REGION_MAP = (() => {
  const m = Object.create(null);
  const put = (region, codes) => { for (const c of [].concat(codes)) m[c] = region; };
  put('HK', 'HKG');
  // 澳洲（本轮新增）：实测 proxyip.au.cmliussss.net 可达且 loc=AU；原实现无澳洲映射 →
  // SYD/MEL 落兜底 'US'，澳洲节点被反向绕到美国（延迟 +150ms，且名字写成「美国」）
  put('AU', ['SYD', 'MEL', 'BNE', 'PER', 'ADL', 'CBR', 'HBA', 'LST', 'DRW', 'CNS', 'MCY']);
  put('SG', 'SIN');
  put('JP', ['NRT', 'HND', 'KIX', 'TYO', 'OSA', 'NGO', 'CTS', 'FUK', 'OKA']);
  put('KR', ['ICN', 'SEL', 'PUS']);
  put('DE', ['FRA', 'MUC', 'DUS', 'BER', 'HAM', 'STR', 'VIE', 'ZRH', 'CDG', 'MAD', 'MXP', 'FCO', 'PRG', 'WAW']);
  put('SE', 'ARN');
  put('NL', 'AMS');
  put('FI', 'HEL');
  put('GB', ['LHR', 'LGW', 'MAN', 'EDI']);
  // 北美（含加拿大 / 拉美）：SJC、SEA、DEN、ATL 四处修正后归此
  put('US', ['LAX', 'SJC', 'SFO', 'SEA', 'PDX', 'SAN', 'LAS', 'PHX', 'SLC', 'DEN',
    'DFW', 'IAH', 'AUS', 'ORD', 'MSP', 'DTW', 'STL', 'MCI', 'ATL', 'MIA', 'MCO', 'BNA',
    'CLT', 'IAD', 'BOS', 'EWR', 'JFK', 'PHL', 'YYZ', 'YVR', 'YUL', 'MEX', 'GRU']);
  return m;
})();
// 兼容直接写地区名（如面板/环境变量传入 'HK'、'us'）
const COLO_REGION_ALIAS = { HK: 'HK', SG: 'SG', JP: 'JP', KR: 'KR', DE: 'DE', SE: 'SE', NL: 'NL', FI: 'FI', GB: 'GB', US: 'US', AU: 'AU' };
function selectRelayRegion(colo) {
  const c = String(colo || '').toUpperCase();
  if (!c) return 'US';
  if (EXIT_VIA_REGION[c]) return EXIT_VIA_REGION[c];   // ① 出口归并（当前空表；HKG / TPE 均不归并）
  if (COLO_REGION_MAP[c]) return COLO_REGION_MAP[c];   // 3 字 IATA 码：精确匹配
  if (COLO_REGION_ALIAS[c]) return COLO_REGION_ALIAS[c];
  return 'US';   // 未知机房：默认美区（原实现默认值）
}

const COLO_GEO = (() => {
  const m = Object.create(null);
  const rows = [
  'AAE|安纳巴|阿尔及利亚 DZ',
  'ABJ|阿比让|科特迪瓦 CI',
  'ABQ|阿尔伯克基|美国 US',
  'ACC|阿克拉|加纳 GH',
  'ACX|兴义|中国 CN',
  'ADB|伊兹密尔|土耳其 TR',
  'ADD|亚的斯亚贝巴|埃塞俄比亚 ET',
  'ADL|阿德莱德|澳大利亚 AU',
  'AGR|阿格拉|印度 IN',
  'AIP|贾朗达尔|印度 IN',
  'AKL|奥克兰|新西兰 NZ',
  'AKX|阿克托别|哈萨克斯坦 KZ',
  'ALA|阿拉木图|哈萨克斯坦 KZ',
  'ALG|阿尔及尔|阿尔及利亚 DZ',
  'AMD|艾哈迈达巴德|印度 IN',
  'AMM|安曼|约旦 JO',
  'AMS|阿姆斯特丹|荷兰 NL',
  'ANC|安克雷奇|美国 US',
  'ARI|阿里卡|智利 CL',
  'ARN|斯德哥尔摩|瑞典 SE',
  'ARU|阿拉萨图巴|巴西 BR',
  'ASK|亚穆苏克罗|科特迪瓦 CI',
  'ASU|亚松森|巴拉圭 PY',
  'ATH|雅典|希腊 GR',
  'ATL|亚特兰大|美国 US',
  'AUS|奥斯汀|美国 US',
  'AVA|安顺|中国 CN',
  'BAH|麦纳麦|巴林 BH',
  'BAQ|巴兰基亚|哥伦比亚 CO',
  'BBI|布巴内斯瓦尔|印度 IN',
  'BCN|巴塞罗那|西班牙 ES',
  'BDQ|贾姆讷格尔|印度 IN',
  'BEG|贝尔格莱德|塞尔维亚 RS',
  'BEL|贝伦|巴西 BR',
  'BEY|贝鲁特|黎巴嫩 LB',
  'BGI|布里奇顿|巴巴多斯 BB',
  'BGR|班戈|美国 US',
  'BGW|巴格达|伊拉克 IQ',
  'BKK|曼谷|泰国 TH',
  'BLR|班加罗尔|印度 IN',
  'BNA|纳什维尔|美国 US',
  'BNE|布里斯班|澳大利亚 AU',
  'BOD|波尔多|法国 FR',
  'BOG|波哥大|哥伦比亚 CO',
  'BOM|孟买|印度 IN',
  'BOS|波士顿|美国 US',
  'BRU|布鲁塞尔|比利时 BE',
  'BSB|巴西利亚|巴西 BR',
  'BSR|巴士拉|伊拉克 IQ',
  'BTS|布拉迪斯拉发|斯洛伐克 SK',
  'BUD|布达佩斯|匈牙利 HU',
  'BUF|布法罗|美国 US',
  'BWN|斯里巴加湾市|文莱 BN',
  'CAI|开罗|埃及 EG',
  'CAN|广州|中国 CN',
  'CAW|坎普斯|巴西 BR',
  'CBR|堪培拉|澳大利亚 AU',
  'CCU|加尔各答|印度 IN',
  'CDG|巴黎|法国 FR',
  'CEB|宿务|菲律宾 PH',
  'CFC|卡萨多尔|巴西 BR',
  'CGB|库亚巴|巴西 BR',
  'CGD|常德|中国 CN',
  'CGK|雅加达|印度尼西亚 ID',
  'CGO|郑州|中国 CN',
  'CGP|吉大港|孟加拉国 BD',
  'CGY|卡加延德奥罗|菲律宾 PH',
  'CHC|基督城|新西兰 NZ',
  'CJB|哥印拜陀|印度 IN',
  'CKG|重庆|中国 CN',
  'CLE|克利夫兰|美国 US',
  'CLO|卡利|哥伦比亚 CO',
  'CLT|夏洛特|美国 US',
  'CMB|科伦坡|斯里兰卡 LK',
  'CMH|哥伦布|美国 US',
  'CNF|贝洛奥里藏特|巴西 BR',
  'CNN|坎努尔|印度 IN',
  'CNX|清迈|泰国 TH',
  'COK|科钦|印度 IN',
  'COR|科尔多瓦|阿根廷 AR',
  'CPH|哥本哈根|丹麦 DK',
  'CPT|开普敦|南非 ZA',
  'CRK|打拉|菲律宾 PH',
  'CSX|长沙|中国 CN',
  'CTU|成都|中国 CN',
  'CVG|辛辛那提|美国 US',
  'CWB|库里蒂巴|巴西 BR',
  'CZL|君士坦丁|阿尔及利亚 DZ',
  'CZX|常州|中国 CN',
  'DAC|达卡|孟加拉国 BD',
  'DAD|岘港|越南 VN',
  'DAR|达累斯萨拉姆|坦桑尼亚 TZ',
  'DEL|新德里|印度 IN',
  'DEN|丹佛|美国 US',
  'DFW|达拉斯|美国 US',
  'DKR|达喀尔|塞内加尔 SN',
  'DLA|杜阿拉|喀麦隆 CM',
  'DLC|大连|中国 CN',
  'DME|莫斯科|俄罗斯 RU',
  'DMM|达曼|沙特阿拉伯 SA',
  'DOH|多哈|卡塔尔 QA',
  'DPS|登巴萨|印度尼西亚 ID',
  'DTW|底特律|美国 US',
  'DUB|都柏林|爱尔兰 IE',
  'DUR|德班|南非 ZA',
  'DUS|杜塞尔多夫|德国 DE',
  'DXB|迪拜|阿联酋 AE',
  'DYU|杜尚别|塔吉克斯坦 TJ',
  'EBB|坎帕拉|乌干达 UG',
  'EBL|埃尔比勒|伊拉克 IQ',
  'EVN|埃里温|亚美尼亚 AM',
  'EWR|纽瓦克|美国 US',
  'EZE|布宜诺斯艾利斯|阿根廷 AR',
  'FCO|罗马|意大利 IT',
  'FIH|金沙萨|刚果金 CD',
  'FLN|弗洛里亚诺波利斯|巴西 BR',
  'FOC|福州|中国 CN',
  'FOR|福塔莱萨|巴西 BR',
  'FRA|法兰克福|德国 DE',
  'FRU|比什凯克|吉尔吉斯斯坦 KG',
  'FSD|苏福尔斯|美国 US',
  'FUK|福冈|日本 JP',
  'FUO|佛山|中国 CN',
  'GBE|哈博罗内|博茨瓦纳 BW',
  'GDL|瓜达拉哈拉|墨西哥 MX',
  'GEO|乔治敦|圭亚那 GY',
  'GIG|里约热内卢|巴西 BR',
  'GND|圣乔治|格林纳达 GD',
  'GOT|哥德堡|瑞典 SE',
  'GRU|圣保罗|巴西 BR',
  'GUA|危地马拉城|危地马拉 GT',
  'GUM|阿加尼亚|关岛 GU',
  'GVA|日内瓦|瑞士 CH',
  'GYD|巴库|阿塞拜疆 AZ',
  'GYE|瓜亚基尔|厄瓜多尔 EC',
  'GYN|戈亚尼亚|巴西 BR',
  'HAK|海口|中国 CN',
  'HAM|汉堡|德国 DE',
  'HAN|河内|越南 VN',
  'HBA|霍巴特|澳大利亚 AU',
  'HEL|赫尔辛基|芬兰 FI',
  'HFA|海法|以色列 IL',
  'HGH|绍兴|中国 CN',
  'HNL|檀香山|美国 US',
  'HRE|哈拉雷|津巴布韦 ZW',
  'HYD|海得拉巴|印度 IN',
  'HYN|台州|中国 CN',
  'IAD|华盛顿|美国 US',
  'IAH|休斯敦|美国 US',
  'ICN|首尔|韩国 KR',
  'IND|印第安纳波利斯|美国 US',
  'ISB|伊斯兰堡|巴基斯坦 PK',
  'IST|伊斯坦布尔|土耳其 TR',
  'ISU|苏莱曼尼亚|伊拉克 IQ',
  'IXC|昌迪加尔|印度 IN',
  'JAX|杰克逊维尔|美国 US',
  'JDO|北茹阿泽鲁|巴西 BR',
  'JED|吉达|沙特阿拉伯 SA',
  'JHB|新山|马来西亚 MY',
  'JIB|吉布提市|吉布提 DJ',
  'JNB|约翰内斯堡|南非 ZA',
  'JOG|日惹|印度尼西亚 ID',
  'JOI|若因维利|巴西 BR',
  'JRG|桑巴尔普尔|印度 IN',
  'JXG|嘉兴|中国 CN',
  'KBP|基辅|乌克兰 UA',
  'KCH|古晋|马来西亚 MY',
  'KEF|雷克雅未克|冰岛 IS',
  'KGL|基加利|卢旺达 RW',
  'KHI|卡拉奇|巴基斯坦 PK',
  'KHN|新余|中国 CN',
  'KIN|金斯敦|牙买加 JM',
  'KIV|基希讷乌|摩尔多瓦 MD',
  'KIX|大阪|日本 JP',
  'KMG|昆明|中国 CN',
  'KNU|坎普尔|印度 IN',
  'KTM|加德满都|尼泊尔 NP',
  'KUL|吉隆坡|马来西亚 MY',
  'KWE|贵阳|中国 CN',
  'KWI|科威特城|科威特 KW',
  'LAD|罗安达|安哥拉 AO',
  'LAS|拉斯维加斯|美国 US',
  'LAX|洛杉矶|美国 US',
  'LCA|尼科西亚|塞浦路斯 CY',
  'LED|圣彼得堡|俄罗斯 RU',
  'LHE|拉合尔|巴基斯坦 PK',
  'LHR|伦敦|英国 GB',
  'LHW|兰州|中国 CN',
  'LIM|利马|秘鲁 PE',
  'LIS|里斯本|葡萄牙 PT',
  'LJU|卢布尔雅那|斯洛文尼亚 SI',
  'LLK|阿斯塔拉|阿塞拜疆 AZ',
  'LLW|利隆圭|马拉维 MW',
  'LOS|拉各斯|尼日利亚 NG',
  'LPB|拉巴斯|玻利维亚 BO',
  'LUH|卢迪亚纳|印度 IN',
  'LUN|卢萨卡|赞比亚 ZM',
  'LUX|卢森堡市|卢森堡 LU',
  'LYA|洛阳|中国 CN',
  'LYS|里昂|法国 FR',
  'MAA|金奈|印度 IN',
  'MAD|马德里|西班牙 ES',
  'MAN|曼彻斯特|英国 GB',
  'MAO|马瑙斯|巴西 BR',
  'MBA|蒙巴萨|肯尼亚 KE',
  'MCI|堪萨斯城|美国 US',
  'MCT|马斯喀特|阿曼 OM',
  'MDE|麦德林|哥伦比亚 CO',
  'MEL|墨尔本|澳大利亚 AU',
  'MEM|孟菲斯|美国 US',
  'MEX|墨西哥城|墨西哥 MX',
  'MIA|迈阿密|美国 US',
  'MLA|圣韦内拉|马耳他 MT',
  'MLE|马累|马尔代夫 MV',
  'MLG|玛琅|印度尼西亚 ID',
  'MNL|马尼拉|菲律宾 PH',
  'MPM|马普托|莫桑比克 MZ',
  'MRS|马赛|法国 FR',
  'MRU|路易港|毛里求斯 MU',
  'MSP|明尼阿波利斯|美国 US',
  'MSQ|明斯克|白俄罗斯 BY',
  'MUC|慕尼黑|德国 DE',
  'MXP|米兰|意大利 IT',
  'NAG|那格浦尔|印度 IN',
  'NBO|内罗毕|肯尼亚 KE',
  'NJF|纳杰夫|伊拉克 IQ',
  'NOU|努美阿|新喀里多尼亚 NC',
  'NQN|内乌肯|阿根廷 AR',
  'NQZ|阿斯塔纳|哈萨克斯坦 KZ',
  'NRT|东京|日本 JP',
  'NVT|廷博|巴西 BR',
  'OKA|那霸|日本 JP',
  'OKC|俄克拉何马城|美国 US',
  'OMA|奥马哈|美国 US',
  'ORD|芝加哥|美国 US',
  'ORF|诺福克|美国 US',
  'ORN|奥兰|阿尔及利亚 DZ',
  'OSL|奥斯陆|挪威 NO',
  'OTP|布加勒斯特|罗马尼亚 RO',
  'OUA|瓦加杜古|布基纳法索 BF',
  'PAT|巴特那|印度 IN',
  'PBH|廷布|不丹 BT',
  'PBM|帕拉马里博|苏里南 SR',
  'PDX|波特兰|美国 US',
  'PER|珀斯|澳大利亚 AU',
  'PHL|费城|美国 US',
  'PHX|凤凰城|美国 US',
  'PIT|匹兹堡|美国 US',
  'PKX|廊坊|中国 CN',
  'PMO|巴勒莫|意大利 IT',
  'PMW|帕尔马斯|巴西 BR',
  'PNH|金边|柬埔寨 KH',
  'PNQ|浦那|印度 IN',
  'POA|阿雷格里港|巴西 BR',
  'POS|西班牙港|特立尼达和多巴哥 TT',
  'PPT|塔希提|法属波利尼西亚 PF',
  'PRG|布拉格|捷克 CZ',
  'PTY|巴拿马城|巴拿马 PA',
  'QRO|克雷塔罗|墨西哥 MX',
  'QWJ|亚美利加纳|巴西 BR',
  'RAO|里贝朗普雷图|巴西 BR',
  'RDU|达勒姆|美国 US',
  'REC|累西腓|巴西 BR',
  'RIC|里士满|美国 US',
  'RIX|里加|拉脱维亚 LV',
  'RUH|利雅得|沙特阿拉伯 SA',
  'RUN|圣但尼|留尼汪 RE',
  'SAN|圣迭戈|美国 US',
  'SAP|圣佩德罗苏拉|洪都拉斯 HN',
  'SAT|圣安东尼奥|美国 US',
  'SCL|圣地亚哥|智利 CL',
  'SDQ|圣多明各|多米尼加 DO',
  'SEA|西雅图|美国 US',
  'SFO|旧金山|美国 US',
  'SGN|胡志明市|越南 VN',
  'SHA|上海|中国 CN',
  'SIN|新加坡|新加坡 SG',
  'SJC|圣何塞|美国 US',
  'SJK|圣若泽杜斯坎普斯|巴西 BR',
  'SJO|圣何塞|哥斯达黎加 CR',
  'SJP|圣若泽杜里奥普雷图|巴西 BR',
  'SJU|圣胡安|波多黎各 PR',
  'SJW|衡水|中国 CN',
  'SKG|塞萨洛尼基|希腊 GR',
  'SKP|斯科普里|北马其顿 MK',
  'SLC|盐湖城|美国 US',
  'SMF|萨克拉门托|美国 US',
  'SOD|索罗卡巴|巴西 BR',
  'SOF|索非亚|保加利亚 BG',
  'SSA|萨尔瓦多|巴西 BR',
  'STI|圣地亚哥-德洛斯卡巴列罗斯|多米尼加 DO',
  'STL|圣路易斯|美国 US',
  'STR|斯图加特|德国 DE',
  'SUV|苏瓦|斐济 FJ',
  'SYD|悉尼|澳大利亚 AU',
  'SZX|深圳|中国 CN',
  'TAO|青岛|中国 CN',
  'TBS|第比利斯|格鲁吉亚 GE',
  'TEN|铜仁|中国 CN',
  'TGU|特古西加尔巴|洪都拉斯 HN',
  'TIA|地拉那|阿尔巴尼亚 AL',
  'TLH|塔拉哈西|美国 US',
  'TLL|塔林|爱沙尼亚 EE',
  'TLV|特拉维夫|以色列 IL',
  'TNA|济南|中国 CN',
  'TNR|塔那那利佛|马达加斯加 MG',
  'TPA|坦帕|美国 US',
  'TUN|突尼斯市|突尼斯 TN',
  'TXL|柏林|德国 DE',
  'TYN|阳泉|中国 CN',
  'UDI|乌贝兰迪亚|巴西 BR',
  'UDR|乌代布尔|印度 IN',
  'UIO|基多|厄瓜多尔 EC',
  'ULN|乌兰巴托|蒙古 MN',
  'URT|素叻他尼|泰国 TH',
  'VCP|坎皮纳斯|巴西 BR',
  'VIE|维也纳|奥地利 AT',
  'VIX|维多利亚|巴西 BR',
  'VNO|维尔纽斯|立陶宛 LT',
  'VTE|万象|老挝 LA',
  'WAW|华沙|波兰 PL',
  'WDH|温得和克|纳米比亚 NA',
  'WLG|惠灵顿|新西兰 NZ',
  'WRO|弗罗茨瓦夫|波兰 PL',
  'XAP|沙佩科|巴西 BR',
  'XFN|襄阳|中国 CN',
  'XIY|宝鸡|中国 CN',
  'XNH|纳西里耶|伊拉克 IQ',
  'YHZ|哈利法克斯|加拿大 CA',
  'YUL|蒙特利尔|加拿大 CA',
  'YVR|温哥华|加拿大 CA',
  'YWG|温尼伯|加拿大 CA',
  'YXE|萨斯卡通|加拿大 CA',
  'YYC|卡尔加里|加拿大 CA',
  'YYZ|多伦多|加拿大 CA',
  'ZAG|萨格勒布|克罗地亚 HR',
  'ZRH|苏黎世|瑞士 CH',
  'HKG|香港|中国 CN',
  'TPE|台北|中国 CN',
  'MFM|澳门|中国 CN'
  ];
  for (const s of rows) { const i = s.indexOf('|'); const j = s.indexOf('|', i + 1);
    m[s.slice(0, i)] = { city: s.slice(i + 1, j), country: s.slice(j + 1) }; }
  return m;
})();
// ─────────────────────────────────────────────────────────────────────────────
// 节点地点后缀来自订阅源的备注，不代表探测到的真实出站地址。
// 已知机房码可查静态城市表；仅有国家/地区码时只显示地区，不猜城市。
// 这些标签用于命名和筛选，不控制连接的实际出口。
const RELAY_GEO_ZH = {
  US: '美国', HK: '中国香港', TW: '中国台湾', MO: '中国澳门', SG: '新加坡', JP: '日本',
  KR: '韩国', DE: '德国', SE: '瑞典', NL: '荷兰', FI: '芬兰', GB: '英国', AU: '澳大利亚',
  CA: '加拿大', FR: '法国', PL: '波兰', CH: '瑞士', IN: '印度', BR: '巴西', RU: '俄罗斯', NZ: '新西兰'
};
// 港澳台在 CF 官方 PoP 表里国家字段是 CN，这里按规范写法强制归到对应地区码
const EXIT_FORCE_CC = { HKG: 'HK', TPE: 'TW', MFM: 'MO' };
const REGION_NAMES = (() => {
  const names = Object.create(null);
  for (const geo of Object.values(COLO_GEO)) {
    const match = geo.country.match(/^(.*)\s+([A-Z]{2})$/);
    if (match) names[match[2]] = match[1];
  }
  return Object.assign(names, REGION_CN, RELAY_GEO_ZH);
})();
const REGION_NAME_MATCHERS = Object.entries({
  ...Object.fromEntries(Object.entries(REGION_NAMES).map(([cc, name]) => [name, cc])),
  ...Object.fromEntries(Object.entries(REGION_CN).map(([cc, name]) => [name, cc])),
  'United States': 'US', 'United Kingdom': 'GB', 'Hong Kong': 'HK',
  Taiwan: 'TW', Singapore: 'SG', Japan: 'JP', 'South Korea': 'KR', Germany: 'DE',
  Australia: 'AU', Canada: 'CA', France: 'FR', Netherlands: 'NL',
  '台灣': 'TW', '美國': 'US', '韓國': 'KR'
}).sort((a,b) => b[0].length-a[0].length).map(([name,cc]) => ({
  cc, pattern: new RegExp(/[A-Za-z]/.test(name) ? '\\b'+name+'\\b' : name, 'i')
}));
function countryCodeForColo(colo) {
  return EXIT_FORCE_CC[colo] || ((COLO_GEO[colo]?.country || '').match(/([A-Z]{2})$/) || [])[1] || '';
}
// 只解析来源备注，不做 IP 定位：独立国家码 > 旗帜 > 机房码 > 标准地区名。
// 国家码按完整词元匹配，避免把 CUSTOM / RUSSIA / CF-B-163 中的片段当地区。
function parseRegionMetadata(rawName) {
  const name = String(rawName || '').normalize('NFKC');
  if (!name) return {};
  const tokens = name.split(/[^A-Za-z0-9]+/).filter(Boolean);
  const fields = name.split('|').map(s => s.trim().toUpperCase());
  let cc = fields.find(s => s.length===2 && REGION_NAMES[s])
    || tokens.find(s => /^[A-Z]{2}$/.test(s) && REGION_NAMES[s]) || '';
  let colo = tokens.find(s => /^[A-Z]{3}$/.test(s) && COLO_GEO[s]) || '';
  if (!cc) {
    const flag = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
    if (flag) {
      const code = [...flag[0]].map(c => String.fromCharCode(c.codePointAt(0)-0x1F1E6+65)).join('');
      if (REGION_NAMES[code]) cc=code;
    }
  }
  if (!cc && colo) cc=countryCodeForColo(colo);
  if (!cc) cc=REGION_NAME_MATCHERS.find(({pattern}) => pattern.test(name))?.cc || '';
  if (cc==='CN' && EXIT_FORCE_CC[colo]) cc=EXIT_FORCE_CC[colo];
  // 来源国家码与机房冲突时只保留国家，避免生成“美国 东京”这种组合。
  if (colo && cc!==countryCodeForColo(colo)) colo='';
  return cc ? {cc, ...(colo ? {colo} : {})} : {};
}
// 有机房码才显示城市；只有国家/地区码时只显示地区后缀。
function geoNameSuffix(colo, cc) {
  const c = String(colo || '').toUpperCase();
  // 若配置了地区归并则显示配置标签；这不是出口实测结果。当前归并表为空。
  const via = EXIT_VIA_REGION[c];
  if (via) {
    const r = REGION_EXIT_GEO[via];
    return r ? ' | ' + [r.zh, r.cc, r.city, r.code].join(' ') : '';
  }
  const g = c ? COLO_GEO[c] : null;
  const code = EXIT_FORCE_CC[c] || String(cc || '').toUpperCase() || ((g?.country || '').match(/([A-Z]{2})\s*$/) || [])[1] || '';
  if (!g || code!==countryCodeForColo(c)) return REGION_NAMES[code] ? ' | '+REGION_NAMES[code]+' '+code : '';
  const zh = (RELAY_GEO_ZH[code] || REGION_CN[code] || g.country || '').replace(/\s+[A-Z]{2}$/, '');
  const parts = zh ? [zh] : [];
  if (code) parts.push(code);
  parts.push(g.city, c);
  return ' | ' + parts.join(' ');
}
// PROXYIP 反代 IP 解析缓存（TTL 5 分钟：域名 → DoH TXT/A 解析结果）
const PROXYIP_CACHE = new Map();

// 解析反代域名为 IP 候选列表：
//   - IP 字面量直接返回
//   - 域名先查 TXT：TXT 含逗号/换行分隔的 IP 列表则解析为多候选；
//     TXT 为 @edtunnel 标记（反代服务约定）或无有效 TXT 时查 A 记录
//   - 结果缓存 5 分钟，避免每次连接都触发 DoH
async function resolveProxyIPs(host, port, io) {
  port = port || 443;
  if (isValidIp(host)) return [{ hostname: host, port }];
  const cacheKey = host + ':' + port;
  const now = Date.now();
  const hit = PROXYIP_CACHE.get(cacheKey);
  if (hit && now - hit.t < 5 * 60 * 1000) return hit.ips;

  const dohs = ['https://cloudflare-dns.com/dns-query', 'https://dns.alidns.com/resolve', 'https://doh.pub/dns-query'];
  const dohQuery = async (type,filterType) => {
    for(const url of dohs){
      const res=await fetchTimeout(url+'?name='+encodeURIComponent(host)+'&type='+type,{headers:{accept:'application/dns-json'}},2500,io);
      if(!res || !res.ok)continue;
      try{const j=await res.json();if(j.Status!==0)continue;return (j.Answer||[]).filter(a=>a.type===filterType).map(a=>a.data);}catch{}
    }
    return [];
  };
  const txtRecords=await dohQuery('TXT',16);
  let aRecords=[];
  let targets = [];
  // 1) TXT 记录：反代服务约定——TXT 存逗号/换行分隔的 IP 列表（支持 ip:port），或 @edtunnel 标记
  for (const raw of txtRecords) {
    // DNS TXT 转义：\010 是八进制换行符，需还原为分隔符；去掉首尾引号
    const val = String(raw).replace(/^"|"$/g, '').replace(/\\010/g, ',').replace(/\n/g, ',').trim();
    if (!val) continue;
    if (val === '@edtunnel') {
      // @edtunnel 是反代服务标记：实际反代 IP 在 A 记录中
      aRecords = await dohQuery('A',1);
      targets = aRecords.filter(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip)).map(ip => ({ hostname: ip, port }));
      break;
    }
    // TXT 值为逗号/分号/空格分隔的条目，每条可为 IP 或 IP:port
    const entries = val.split(/[,;\s]+/).map(s => s.trim()).filter(Boolean);
    const parsed = [];
    for (const entry of entries) {
      const { host: h, port: p } = parseHostPort(entry, port);
      if (isValidIp(h)) parsed.push({ hostname: h, port: p });
    }
    if (parsed.length) { targets = parsed; break; }
  }

  // 2) 无有效 TXT 时用 A 记录
  if (!targets.length) {
    aRecords = await dohQuery('A',1);
      targets = aRecords.filter(ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip)).map(ip => ({ hostname: ip, port }));
  }

  // 3) 无 A 记录时回退 AAAA（IPv6 反代）
  if (!targets.length) {
    const aaaaRecs = await dohQuery('AAAA', 28);
    targets = aaaaRecs.filter(ip => isValidIp(ip)).map(ip => ({ hostname: ip, port }));
  }

  // 去重（按 hostname:port）
  const seen = new Set();
  const result = targets.filter(t => { const k = t.hostname + ':' + t.port; if (seen.has(k)) return false; seen.add(k); return true; });
  if (result.length) boundedSet(PROXYIP_CACHE,cacheKey,{t:now,ips:result});
  return result;
}

// 仅缓存代理端点自身的失败；目标网站拒绝 CONNECT 不应影响其他目标。
// isolate 内短暂避开已知失效的地址，修改代理配置后立即重新尝试。
const OUTBOUND_PROXY_FAILURES = new Map();
const OUTBOUND_PROXY_FALLBACK_MS = 2000;
const OUTBOUND_PROXY_COOLDOWN_MS = 30000;

// 出站代理连接真实目标；失败后复用未配置代理时的完整出站路径。
async function openOutbound(parsed, cfg, colo, isVless) {
  const proxy = parseProxyAddress(cfg.outboundProxy);
  const mode = cfg.outboundMode || '';
  if (!proxy) {
    if (mode === 'only') throw new AppError(503,'仅代理模式缺少出站代理');
    return openDirectOutbound(parsed,cfg,colo);
  }
  const destination = {hostname:parsed.addr,port:parsed.port};
  const proxyKey = md5hex(cfg.outboundProxy);
  const viaProxy = async () => {
    if (mode !== 'only' && (OUTBOUND_PROXY_FAILURES.get(proxyKey) || 0) > Date.now()) {
      throw new AppError(503,'代理端点暂不可用，使用兜底路径');
    }
    const timeoutMs = mode === 'only' ? 6000 : OUTBOUND_PROXY_FALLBACK_MS;
    try {
      const socket = await (proxy.type === 'http' || proxy.type === 'https'
        ? connectViaHttpProxy(proxy,destination,timeoutMs)
        : proxy.type === 'ss'
          ? connectViaShadowsocks(proxy,destination,timeoutMs)
          : connectViaSocks5(proxy,destination,timeoutMs));
      OUTBOUND_PROXY_FAILURES.delete(proxyKey);
      return socket;
    } catch (error) {
      if (error.proxyUnavailable) boundedSet(OUTBOUND_PROXY_FAILURES,proxyKey,Date.now()+OUTBOUND_PROXY_COOLDOWN_MS);
      throw error;
    }
  };
  if (mode === 'only') return viaProxy();
  // 直连优先仍先连接真实目标，失败后再使用代理和中继。
  if (mode === 'no') {
    try { return await connectDirect(destination,6000); } catch {}
  }
  try { return await viaProxy(); } catch {}
  // 代理等待不占用兜底的 15 秒/4 次连接预算。
  return openDirectOutbound(parsed,cfg,colo,mode==='no');
}

// 自定义透明反代 → 直连真实目标 → 内置地区反代。
// 与清空出站代理后的路径一致；透明反代直接连接，不再经过失效代理。
async function openDirectOutbound(parsed, cfg, colo, skipDirect = false) {
  let lastErr, attemptsMade=0;
  const deadline=Date.now()+15000;
  const tryConnect = async (target,timeoutMs) => {
    if(attemptsMade++>=4 || Date.now()>=deadline)throw new AppError(504,'出站重试预算耗尽');
    try { return await connectDirect(target,Math.max(1,Math.min(timeoutMs,deadline-Date.now()))); }
    catch(e){lastErr=e;return null;}
  };
  const resolveTargets = async (host,port) => {
    if(Date.now()>=deadline)throw new AppError(504,'出站重试预算耗尽');
    try { return await withTimeout(resolveProxyIPs(host,port,cfg._io),Math.max(1,deadline-Date.now()),'反代解析超时'); }
    catch(e){lastErr=e;return [];}
  };

  // 1) 用户自定义 proxyIP 透明代理。
  const relay = cfg.proxyIP ? parseHostPort(cfg.proxyIP, 443) : null;
  if (relay && relay.host) {
    let customTargets = await resolveTargets(relay.host, relay.port);
    if (!customTargets.length) customTargets = [{ hostname: relay.host, port: relay.port }];
    for (const target of customTargets) {
      const r = await tryConnect(target,6000);
      if (r) return r;
    }
  }

  // 2) 直连目标；直连优先模式已在上方尝试，避免重复等待。
  //    6s 连接超时：目标 SYN 被丢弃 / 直连被回环保护拦截时不再无限挂起，及时进入反代兜底
  if (!skipDirect) {
    const directResult = await tryConnect({hostname:parsed.addr,port:parsed.port},6000);
    if (directResult) return directResult;
  }

  // 3) 兜底内置地区反代（透明代理：发送去掉 VLESS/Trojan 头部的原始 TLS 数据，对端按 SNI 路由到目标）
  //    多地区轮询：本地区域优先，失败后依次尝试其余区域；单个反代失效不再导致
  //    （尤其 CF 托管站点直连被回环保护拦截时）流量为 0；VLESS / Trojan / XHTTP 均启用
  //    （对齐 1.0.6：Trojan 无反代兜底时 Clash Verge 测速 gstatic.com 被回环保护拦截 → 节点全部超时）
  {
    const primary = selectRelayRegion(colo);
    const regions = [primary, ...Object.keys(RELAY_DOMAINS).filter(r => r !== primary)].slice(0, 3);
    for (const region of regions) {
      const relayDomain = RELAY_DOMAINS[region];
      if (!relayDomain) continue;
      const relayTargets = await resolveTargets(relayDomain, 443);
      if (!relayTargets.length) continue;
      for (const target of relayTargets) {
        const r = await tryConnect(target,5000);
        if (r) return r;
      }
    }
  }

  throw lastErr || new Error('所有出站方式均失败');
}

// 双向管道：socket 可读 → send 回调；结束调用 onDone
async function pumpToReader(reader, send, onDone) {
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      send(value);
    }
  } catch (e) { /* 忽略 */ }
  try { if (onDone) onDone(); } catch (e) { /* 忽略 */ }
}

// ---------------------------------------------------------------------------
// WebSocket 代理（VLESS / Trojan）
// ---------------------------------------------------------------------------
async function handleWebSocketProxy(request, cfg) {
  const earlyHeader=request.headers.get('Sec-WebSocket-Protocol')||'';
  let earlyData;
  if(earlyHeader){
    if(earlyHeader.length>4096 || !/^[A-Za-z0-9_=-]+$/.test(earlyHeader))throw new AppError(400,'Early Data 格式错误');
    try{earlyData=Uint8Array.from(atob(earlyHeader.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}catch{throw new AppError(400,'Early Data 格式错误');}
    if(earlyData.length>2048)throw new AppError(413,'Early Data 超限');
  }
  const [client,server]=Object.values(new WebSocketPair());
  server.accept(); server.binaryType='arraybuffer';
  let socket,writer,reader,pending=new Uint8Array(0),ready=false,closed=false,queued=0;
  let chain=Promise.resolve();
  const cleanup=(code=1000)=>{
    if(closed)return;closed=true;clearTimeout(handshakeTimer);pending=new Uint8Array(0);
    closeSocket(socket);
    try{server.close(code);}catch{}
    try{writer?.releaseLock();}catch{} try{reader?.releaseLock();}catch{}
  };
  const handshakeTimer=setTimeout(()=>cleanup(1008),10000);
  const send=(data)=>{
    if(closed || server.readyState!==1) throw new Error('WebSocket 已关闭');
    if((server.bufferedAmount || 0)+data.byteLength>RESOURCE_LIMITS.bufferBytes) throw new Error('客户端读取过慢');
    server.send(data);
  };
  const consume=async(chunk)=>{
    if(closed)return;
    if(!ready) {
      pending=concatBytes(pending,chunk);
      if(pending.length>RESOURCE_LIMITS.bufferBytes) throw new Error('握手缓冲超限');
      let parsed,protocol;
      try {
        if(pending[0]!==0 && pending.length<58) return;
        protocol=detectTrojan(pending,cfg)?'trojan':'vless';
        parsed=protocol==='trojan'?parseTrojanHeader(pending):parseVlessHeader(pending);
      }catch(e){if(e.message==='头部过短' && pending.length<=1024)return;throw e;}
      authenticateProxy(parsed,cfg,protocol);
      // 10 秒只约束客户端提交协议头；出站连接和兜底有各自的超时预算。
      clearTimeout(handshakeTimer);
      socket=await openOutbound(parsed,cfg,request.cf?.colo,protocol==='vless');
      if(closed){closeSocket(socket);return;}
      writer=socket.writable.getWriter();reader=socket.readable.getReader();
      if(protocol==='vless')send(new Uint8Array([0,0]));
      if(socket._preamble?.length)send(socket._preamble);
      if(pending.length>parsed.headerLength)await withTimeout(writer.write(pending.subarray(parsed.headerLength)),15000,'写入超时');
      pending=new Uint8Array(0);ready=true;clearTimeout(handshakeTimer);
      // WebSocket 生命周期维持转发；每个后台 Promise 都有显式错误处理。
      void (async()=>{try{while(!closed){const {done,value}=await reader.read();if(done)break;send(value);}}finally{cleanup();}})().catch(()=>cleanup(1011));
    } else await withTimeout(writer.write(chunk),15000,'写入超时');
  };
  server.addEventListener('message',ev=>{
    if(closed)return;
    if(typeof ev.data==='string'){cleanup(1003);return;}
    const chunk=new Uint8Array(ev.data);queued+=chunk.byteLength;
    if(queued>RESOURCE_LIMITS.bufferBytes){cleanup(1009);return;}
    chain=chain.then(()=>consume(chunk)).catch(()=>cleanup(1008)).finally(()=>{queued-=chunk.byteLength;});
  });
  if(earlyData?.length){queued+=earlyData.length;chain=chain.then(()=>consume(earlyData)).catch(()=>cleanup(1008)).finally(()=>{queued-=earlyData.length;});}
  server.addEventListener('close',()=>cleanup());server.addEventListener('error',()=>cleanup(1011));
  return new Response(null,{status:101,webSocket:client,headers:earlyHeader?{'Sec-WebSocket-Protocol':earlyHeader}:{}});
}
async function handleXhttpProxy(request,cfg) {
  if(!request.body)throw new AppError(400,'缺少请求体');
  const bodyReader=request.body.getReader(); let pending=new Uint8Array(0),parsed,conn,writer,reader,closed=false;
  const cleanup=()=>{
    if(closed)return;closed=true;request.signal.removeEventListener('abort',cleanup);
    void bodyReader.cancel().catch(()=>{});closeSocket(conn);
    try{bodyReader.releaseLock()}catch{}try{reader?.releaseLock()}catch{}try{writer?.releaseLock()}catch{}
  };
  request.signal.addEventListener('abort',cleanup,{once:true});
  try {
    await withTimeout((async()=>{
      while(!parsed){
        const {done,value}=await bodyReader.read();if(done)throw new AppError(400,'协议头不完整');
        pending=concatBytes(pending,value);
        if(pending.length>RESOURCE_LIMITS.bufferBytes)throw new AppError(413,'握手缓冲超限');
        try{parsed=parseVlessHeader(pending);}catch(e){if(e.message==='头部过短'&&pending.length<=1024)continue;throw e;}
      }
    })(),10000,'协议头读取超时');
    authenticateProxy(parsed,cfg,'xhttp');
    conn=await openOutbound(parsed,cfg,request.cf?.colo,true);
    if(closed || request.signal.aborted){closeSocket(conn);throw new AppError(499,'客户端已断开');}
    writer=conn.writable.getWriter();reader=conn.readable.getReader();
    if(pending.length>parsed.headerLength)await withTimeout(writer.write(pending.subarray(parsed.headerLength)),15000,'写入超时');
    pending=new Uint8Array(0);
    void (async()=>{
      while(!closed){const {done,value}=await bodyReader.read();if(done)break;await withTimeout(writer.write(value),15000,'写入超时');}
      if(!closed)await writer.close();
    })().catch(cleanup);
    let prefix=true;
    const stream=new ReadableStream({
      async pull(controller){
        try {
          if(prefix){prefix=false;controller.enqueue(new Uint8Array([0,0]));if(conn._preamble?.length)controller.enqueue(conn._preamble);return;}
          const {done,value}=await reader.read();
          if(done){controller.close();cleanup();}else controller.enqueue(value);
        }catch(e){controller.error(e);cleanup();}
      },cancel(){cleanup();}
    },{highWaterMark:65536,size:chunk=>chunk.byteLength});
    return new Response(stream,{headers:{'Content-Type':'application/octet-stream','Cache-Control':'no-store','X-Accel-Buffering':'no'}});
  }catch(e){cleanup();throw e;}
}

// ---------------------------------------------------------------------------
// 优选器：候选提取（txt / HTML 多源）+ TCP 延迟测试
// ---------------------------------------------------------------------------
// 从任意数据源文本提取 IP 候选（兼容 txt 行式、HTML 表格、JSON 文本；仅保留合法 IPv4/IPv6）
// 内容解码：优先 UTF-8（fatal 严格解码），否则按 GBK 解码（对齐 edgetunnel 请求优选API 的编码检测；
// 国内优选 API 常返回 GB2312/GBK 编码，直接 text() 会乱码导致解析不到 IP）
// 重要：不使用 U+FFFD 替换符字符串字面量判定（该转义会被部分混淆器改写为空格，导致 UTF-8 源被误判 GBK 而乱码），
// 改用 TextDecoder('utf-8', { fatal: true }) 严格解码：非法字节直接抛错才落入 GBK 兜底，混淆后行为不变
function decodeUtf8OrGbk(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) { /* 非 UTF-8（GB2312/GBK 等）→ 尝试 GBK */ }
  try { return new TextDecoder('gbk').decode(bytes); } catch (e2) { /* 兜底 */ }
  return new TextDecoder().decode(bytes);
}

function extractCandidates(text) {
  const seen = new Set();
  const out = [];
  const add = (ip, port, name) => {
    if (!isValidIp(ip)) return;
    if (seen.has(ip)) return;   // 按 IP 去重（忽略端口）
    seen.add(ip);
    out.push({ ip, port: port || 443, name: name || '' });
  };
  parseIPList(text).forEach(x => add(x.ip, x.port, x.name));
  // IPv4：点分四段（HTML/JSON 文本中散落的合法 IP）
  const re4 = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
  let m;
  while ((m = re4.exec(text))) {
    const { host, port } = parseHostPort(m[0], 443);
    if (host) add(host, port, '');
  }
  // IPv6：冒号分隔的连续 token（微测网 IPv6 源为裸地址）
  const re6 = /[0-9a-fA-F:]+/g;
  while ((m = re6.exec(text))) {
    const t = m[0];
    if (t.includes(':') && t.split(':').length >= 3 && isValidIp(t)) add(t, 443, '');
  }
  return out;
}

// 从文本提取域名（用于微测网优选域名源，支持 *. 通配前缀）
function extractDomains(text) {
  const seen = new Set();
  const out = [];
  const re = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;
  let m;
  while ((m = re.exec(text))) {
    const d = m[0].toLowerCase();
    if (!seen.has(d) && (d.includes('cloudflare') || d.includes('bestcf') || d.includes('182682') || d.includes('090227') || d.endsWith('.xyz') || d.endsWith('.top'))) {
      seen.add(d); out.push(d);
    }
  }
  return out.slice(0, 10);
}

// 订阅时自动拉取最新优选 IP：HostMonit 优选源，10 分钟缓存；
// 失败返回 null，由内置优选池兜底。保证 IP 节点为「当前优选」而非静态过期快照，显著提升可用率。
const SUBPREF_CACHE = { t: 0, ips: null };
async function fetchLatestPreferredIPs(maxCount, io) {
  maxCount = Math.max(1, parseInt(maxCount) || 150);
  if (Date.now() - SUBPREF_CACHE.t < 10 * 60 * 1000) return SUBPREF_CACHE.ips?.slice(0,maxCount);
  const res = await fetchTimeout('https://stock.hostmonit.com/CloudFlareYes', { headers: { 'User-Agent': 'Mozilla/5.0' } }, 6000, io);
  if (res && res.ok) {
    const arr = extractCandidates(await res.text()).filter(x => x.ip && isCloudflareIP(x.ip));
    const seen = new Set(); const out = [];
    for (const x of arr) { if (seen.has(x.ip)) continue; seen.add(x.ip); out.push(x); if (out.length >= 200) break; }
    SUBPREF_CACHE.t = Date.now(); SUBPREF_CACHE.ips = out;
    return out.slice(0,maxCount);
  }
  return null;
}

// 按数据源键 + 自定义 URL 收集候选 IP
async function collectCandidates(opt) {
  opt = opt || {};
  const io = opt._io || createIO();
  opt = { ...opt, count: Math.max(1,Math.min(200,Number(opt.count)||20)) };
  const out = [];
  // 源拉取统计：预设源 / 自定义源 各自拉到的 IP 数与失败原因（前端展示，便于排查"源未生效"）
  const stats = { preset: 0, presetErr: '', custom: 0, customErr: '', cidr: 0 };
  // 统一使用所选测速端口：忽略源文本自带端口，保证测速结果只出现所选端口；
  // 仅保留 Cloudflare Anycast IP：非 CF IP 无法作为 Worker 入口，测速/加入优选均无意义
  const push = (x) => { if (x && x.ip && isCloudflareIP(x.ip)) out.push({ ip: x.ip, port: opt.port || x.port || 443, name: x.name || '' }); };
  if (opt.source && OPTIMIZE_SOURCES[opt.source]) {
    const res = await fetchTimeout(OPTIMIZE_SOURCES[opt.source].url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, 6000, io);
    if (res && res.ok) {
      const arr = extractCandidates(await res.text());
      arr.forEach(push);
      stats.preset = arr.length;
    } else stats.presetErr = res ? ('HTTP ' + res.status) : '超时/网络错误';
  }
  if (opt.sourceURL) {
    const res = await fetchTimeout(opt.sourceURL, { headers: { 'User-Agent': 'Mozilla/5.0' } }, 6000, io);
    if (res && res.ok) {
      const arr = extractCandidates(await res.text());
      arr.forEach(push);
      stats.custom = arr.length;
    } else stats.customErr = res ? ('HTTP ' + res.status) : '超时/网络错误';
  }
  // 按 IP 去重（忽略端口）：同一 IP 无论来源/端口如何只保留一条，避免候选框出现重复 IP
  const seen = new Set();
  const dedup = [];
  for (const x of out) {
    if (seen.has(x.ip)) continue;
    seen.add(x.ip);
    dedup.push(x);
  }
  // 高可用补足：去重后仍不足目标数量时，优先并入 bestcf 区域优选池（实时测速过的优质 IP），
  // 其次才用 CF CIDR 随机生成（参考 TunnelBoard：真实优选池可用性远高于随机 CIDR）
  if (dedup.length < (opt.count || 20)) {
    let need = (opt.count || 20) - dedup.length;
    try {
      const pool = await fetchBestcfPool(io);
      for (const p of pool) {
        if (need <= 0) break;
        if (seen.has(p.ip)) continue;
        if (!isCloudflareIP(p.ip)) continue;
        seen.add(p.ip);
        dedup.push({ ip: p.ip, port: opt.port || p.port || 443, name: p.name || '' });
        need--;
      }
    } catch (e) {}
    stats.bestcf = (opt.count || 20) - dedup.length - need;
  }
  if (opt.useCidr !== false && dedup.length < (opt.count || 20)) {
    const need = (opt.count || 20) - dedup.length;
    const pool = randomIPsFromCidrs(CLOUDFLARE_CIDRS, need * 3);
    let filled = 0;
    for (const ip of pool) {
      if (filled >= need) break;
      if (seen.has(ip)) continue;
      seen.add(ip);
      dedup.push({ ip, port: opt.port || 443, name: '' });
      filled++;
    }
    stats.cidr = filled;
  }
  return { candidates: dedup.slice(0,200), stats };
}

// 单个 IP 的 TCP 连接延迟测试
function testOneLatency(ip, port, timeout) {
  return new Promise((resolve) => {
    const start = Date.now();
    let socket, done = false;
    const finish = (ok, latency) => {
      if (done) return; done = true;
      clearTimeout(timer);
      try { if (socket) socket.close(); } catch (e) { /* 忽略 */ }
      resolve({ ip, port, ok, latency });
    };
    const timer = setTimeout(() => finish(false, -1), timeout);
    try {
      socket = connect({ hostname: ip, port });
    } catch (e) { return finish(false, -1); }
    socket.opened.then(() => finish(true, Date.now() - start))
      .catch(() => finish(false, -1));
  });
}

// 并发延迟测试
async function runLatencyTest(candidates, threads, timeout) {
  threads = Math.max(1, Math.min(50, Number(threads) || 5));
  timeout = Math.max(500, Number(timeout) || 5000);
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < candidates.length) {
      const c = candidates[idx++];
      const r = await testOneLatency(c.ip, c.port, timeout);
      results.push(r);
    }
  }
  await Promise.all(Array.from({ length: threads }, worker));
  results.sort((a, b) => (a.latency < 0 ? 1e9 : a.latency) - (b.latency < 0 ? 1e9 : b.latency));
  return results;
}

// ---------------------------------------------------------------------------
// 订阅生成
// ---------------------------------------------------------------------------
// XHTTP Padding（XHTTP Extra）参数：xPadding 混淆参数，客户端与服务端约定一致。
// header/key 两项由 UUID 内部切片派生（slice(1,7) / '_'+slice(25,31)），
// 其余三项为固定混淆策略。V2rayN（extra JSON，camelCase）与 mihomo
// （xhttp-opts，kebab-case）共用同一份派生结果。
function xhttpPadding(cfg) {
  const u = cfg.uuid || '';
  return {
    xPaddingObfsMode: true, xPaddingMethod: 'tokenish', xPaddingPlacement: 'queryInHeader',
    xPaddingHeader: u.slice(1, 7), xPaddingKey: '_' + u.slice(25, 31)
  };
}

// vless/trojan 分享链接 # 后的节点名：非 ASCII（中文等）原样输出、不做 URL 编码，仅转义 URI 特殊字符（% # ? 空格）。
// 原因：v2rayNG/AsteriskNG 对 fragment 的 %XX 按系统编码（GBK）做 URL 解码，UTF-8 编码的中文（%E9%A6...）会被误读成乱码
// （如 香港 → 棣欐腐、台湾 → 鋆版咕）；原样中文走明文 UTF-8，GBK/UTF-8 解码客户端均正常显示。
function uriFragName(name) {
  return String(name).replace(/%/g, '%25').replace(/#/g, '%23').replace(/\?/g, '%3F').replace(/ /g, '%20');
}

function vlessNode(cfg, server, port, name, extra = {}) {
  const host = cfg.host;
  const addr = server.includes(':') && !server.startsWith('[') ? `[${server}]` : server;  // IPv6 需方括号
  const isTls = !HTTP_PORTS.has(Number(port));
  const enc = encodeURIComponent;
  let q = 'encryption=none';
  if (isTls) q += '&security=tls&sni=' + enc(host) + '&fp=chrome';
  else q += '&security=none';   // 80/8080/2052 等明文端口走明文 ws
  q += '&host=' + enc(host);
  if (extra.type === 'xhttp' && isTls) {
    // XHTTP（stream-one）：仅 TLS 端口生效；必须携带 extra（JSON）作为 XHTTP Extra，否则 V2rayN 无法识别完整 xhttp 配置
    // Padding 头/键由 UUID 内部派生（切片），客户端按此发送，服务端按 VLESS 流处理 body
    q += '&type=xhttp&mode=stream-one';
    q += '&extra=' + enc(JSON.stringify(xhttpPadding(cfg)));
  }
  else q += '&type=ws';   // 明文端口与默认路径均走 ws
  q += '&path=' + enc('/' + cfg.path);
  if (cfg.alpn) q += '&alpn=' + enc(cfg.alpn);
  if (cfg.ech) {
    // ECH：输出 "查询域名+DoH"（xray/V2rayN 客户端本地查询 ECH 配置，Worker 端拉取会与用户边缘密钥不匹配导致握手失败）
    q += '&ech=' + enc((cfg.echHost || 'cloudflare-ech.com') + '+' + (cfg.echDns || 'https://223.5.5.5/dns-query'));
  }
  return `vless://${cfg.uuid}@${addr}:${port}?${q}#${uriFragName(name)}`;
}

function trojanNode(cfg, server, port, name) {
  const host = cfg.host;
  const addr = server.includes(':') && !server.startsWith('[') ? `[${server}]` : server;  // IPv6 需方括号
  const enc = encodeURIComponent;
  const isTls = !HTTP_PORTS.has(Number(port));
  // 明文端口（80/8080/8880/2052/2082/2086/2095）：走 security=none 明文 ws（不被 TLS 指纹检测，可用性高）；
  // TLS 端口：security=tls + sni/fp
  let q = isTls
    ? 'security=tls&sni=' + enc(host) + '&fp=chrome&host=' + enc(host) + '&type=ws&path=' + enc('/' + cfg.path)
    : 'security=none&host=' + enc(host) + '&type=ws&path=' + enc('/' + cfg.path);
  if (cfg.alpn && isTls) q += '&alpn=' + enc(cfg.alpn);
  if (cfg.ech && isTls) q += '&ech=' + enc((cfg.echHost || 'cloudflare-ech.com') + '+' + (cfg.echDns || 'https://223.5.5.5/dns-query'));   // ECH：仅 TLS 端口有效
  return `trojan://${cfg.trojanPassword || cfg.uuid}@${addr}:${port}?${q}#${uriFragName(name)}`;
}

// 优选域名 / 优选 API 的 DNS 解析缓存（TTL 10 分钟：域名或 URL → IP 列表）
const DNH_CACHE = new Map();
// 带超时的 fetch（手动 AbortController，兼容所有运行时）
const RESOURCE_LIMITS=Object.freeze({fetches:40,concurrency:4,sourceBytes:1024*1024,bufferBytes:1024*1024,deadlineMs:20000});
function boundedSet(map,key,value,max=128){if(!map.has(key)&&map.size>=max)map.delete(map.keys().next().value);map.set(key,value);}
function createIO(){return {used:0,running:0,waiters:[],deadline:Date.now()+RESOURCE_LIMITS.deadlineMs,cache:new Map(),failures:0};}
async function readBounded(body,maxBytes,deadlineMs=6000){
  if(!body)return new Uint8Array(0);
  const reader=body.getReader(),parts=[];let size=0;const expires=Date.now()+deadlineMs;
  try{while(true){const {done,value}=await withTimeout(reader.read(),Math.max(1,expires-Date.now()),'正文读取超时');if(done)break;size+=value.byteLength;if(size>maxBytes)throw new AppError(413,'响应正文过大');parts.push(value);}}
  catch(e){await reader.cancel().catch(()=>{});throw e;}
  finally{reader.releaseLock();}
  const out=new Uint8Array(size);let off=0;for(const part of parts){out.set(part,off);off+=part.length;}return out;
}
async function readRequestJson(request,max=128*1024){
  try{return JSON.parse(TD.decode(await withTimeout(readBounded(request.body,max),5000,'请求读取超时')));}
  catch(e){if(e instanceof AppError)throw e;throw new AppError(400,'JSON 格式错误');}
}
async function fetchTimeout(url,opts={},ms=6000,io=createIO()){
  const method=opts.method || 'GET';
  const cacheKey=method==='GET' ? String(url)+'|'+JSON.stringify(opts.headers || {}) : null;
  if(cacheKey && io.cache.has(cacheKey)){const hit=await io.cache.get(cacheKey);return hit?.clone() || null;}
  const job=(async()=>{
    if(io.running>=RESOURCE_LIMITS.concurrency)await new Promise(res=>io.waiters.push(res));else io.running++;
    let timer,ctrl=new AbortController();
    try{
      const remaining=Math.min(ms,io.deadline-Date.now());if(remaining<=0)throw new Error('请求预算超时');
      const expires=Date.now()+remaining;timer=setTimeout(()=>ctrl.abort(),remaining);
      let target=new URL(url),response;
      for(let redirects=0;redirects<=3;redirects++){
        if(!['http:','https:'].includes(target.protocol)||target.username||target.password)throw new Error('数据源 URL 无效');
        if(ctrl.signal.aborted || io.used>=RESOURCE_LIMITS.fetches)throw new Error('外部请求预算耗尽');
        io.used++;
        response=await fetch(target.href,{...opts,redirect:'manual',signal:ctrl.signal});
        if([301,302,303,307,308].includes(response.status)){
          await response.body?.cancel();
          if(method!=='GET' || redirects===3)throw new Error('重定向被拒绝');
          const next=new URL(response.headers.get('location'),target);
          if(target.protocol==='https:'&&next.protocol!=='https:')throw new Error('不允许降级重定向');
          target=next;continue;
        }
        const bytes=await withTimeout(readBounded(response.body,RESOURCE_LIMITS.sourceBytes,Math.max(1,expires-Date.now())),Math.max(1,expires-Date.now()),'正文读取超时');
        const headers=new Headers(response.headers);headers.delete('content-length');headers.delete('content-encoding');
        return new Response([204,205,304].includes(response.status)?null:bytes,{status:response.status,headers});
      }
      return null;
    }catch{io.failures++;return null;}
    finally{clearTimeout(timer);ctrl.abort();const next=io.waiters.shift();if(next)next();else io.running--;}
  })();
  if(cacheKey)io.cache.set(cacheKey,job);
  const result=await job;return result?.clone() || null;
}

// 解析优选域名/优选API为 IP：URL 数据源与域名并发拉取（避免串行拖垮订阅墙钟）；按输入顺序均衡截断 maxTotal，保证各地区节点都有
// allowRegionFallback：仅「自定义订阅 + 追加内置及默认节点」开启时允许地区回退生成——
// 地区只从节点备注解析，不由来源 URL 或随机 IP 推定；
// filterCF：仅自定义模式（关闭追加）传 false，输入框内容原样下发（用户自担可用性）；追加/默认模式保持 CF 段过滤保证可达
// v6：默认 IPv4 模式跳过 AAAA 查询（省一半 DNS 子请求）；仅筛选含 IPv6 时传 true
async function resolvePreferredDomains(domainsStr, limitPerDomain = 100, maxTotal = 300, allowRegionFallback = false, filterCF = true, v6 = false, io = createIO()) {
  const list = String(domainsStr || '').split(/[\n,;]+/).map(s => s.trim().replace(/^\*\./, '')).filter(Boolean).slice(0,24);
  const now = Date.now();
  // DoH 降级链：CF 官方 1.1.1.1 优先（Worker 与 1.1.1.1 同机房，内网时延 <5ms 且只计 1 次子请求），失败后优雅降级阿里 DNS
  const dohs = ['https://cloudflare-dns.com/dns-query', 'https://dns.alidns.com/resolve'];
  const qry = async (d,type,filter) => {
    for(const url of dohs){
      const res=await fetchTimeout(url+'?name='+encodeURIComponent(d)+'&type='+type,{headers:{accept:'application/dns-json'}},3000,io);
      if(!res || !res.ok)continue;
      try{const j=await res.json();const arr=(j.Answer||[]).filter(a=>a.type===filter && isValidIp(String(a.data))).map(a=>a.data);if(arr.length)return arr;}catch{}
    }
    return [];
  };
  // 每个条目返回一个有序 IP 数组
  const perItem = await Promise.all(list.map(async (d) => {
    if (d.includes('://')) {
      // CFBox 复刻增强：sub:// 子订阅前缀——后面跟 base64(订阅URL) 或直接 URL
      if (d.startsWith('sub://')) {
        let real = d.slice(6);
        if (/^[A-Za-z0-9+/=]+$/.test(real) && real.length % 4 === 0) {
          try { const dec = atob(real); if (/^https?:\/\//i.test(dec)) real = dec; } catch (e) { /* 保持原样 */ }
        }
        if (!/^https?:\/\//i.test(real)) real = 'https://' + real;
        d = real;
      }
      const ck = 'url:' + d + '|' + [allowRegionFallback,filterCF,v6,limitPerDomain].join('|');
      const cHit = DNH_CACHE.get(ck);
      if (cHit && now - cHit.t < 10 * 60 * 1000) return cHit.ips.slice(0, limitPerDomain);
      try {
        const res = await fetchTimeout(d, {}, 6000, io);
        if (!res || !res.ok) throw new Error('unreachable');
        // edgetunnel 对齐：数组缓冲 + UTF-8/GBK 编码检测（国内优选 API 常返回 GB2312，直接 text() 会乱码）
        const txt = decodeUtf8OrGbk(await res.arrayBuffer());
        // 兼容多种数据源格式：base64 订阅 / CSV 优选表 / HTML 线路表 / vless 订阅行 / 纯 IP 行
        let content = txt;
        // base64 内容检测（子订阅常见输出）：整段可 base64 且长度对齐则解码后再解析；
        // atob 得到的是二进制串，用 decodeUtf8OrGbk 按 UTF-8/GBK 还原，避免 base64 源中文节点名乱码
        if (/^[A-Za-z0-9+/=\s]{40,}$/.test(content.slice(0, 2000)) && content.replace(/\s+/g, '').length % 4 === 0) {
          try {
            const raw = atob(content.replace(/\s+/g, ''));
            content = decodeUtf8OrGbk(Uint8Array.from(raw, c => c.charCodeAt(0)));
          } catch (e) { /* 非 base64，保持原文 */ }
        }
        const seen = new Set();
        const counters = {};
        const rec = [];
        // 已知 bestcf 地区池/天诚源允许非 CF 段中转 IP；识别来源不等于验证节点可达性。
        const relay = isTrustedRegionPool(d);
        // 追加/默认模式强制 CF 段；bestcf 地区优选池（社区中转）放行；仅自定义模式（filterCF=false）原样下发
        const pass = (ip) => !filterCF || isCloudflareIP(ip) || relay;
        // CSV 优选表解析（对齐 edgetunnel 请求优选API）：
        // ① wetest 风格：IP地址,端口,数据中心[,TLS]（TLS 列非 true 跳过，避免明文端口无法转发）
        // ② hostmonit 风格：IP,延迟,下载速度 → 命名「CF优选 {延迟}ms {速度}MB/s」
        const csvLines = content.trim().split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (csvLines.length > 1 && csvLines[0].includes(',')) {
          const headers = csvLines[0].split(',').map(h => h.trim());
          const isWetest = headers.includes('IP地址') && headers.includes('端口');
          const isHostmonit = headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'));
          if (isWetest || isHostmonit) {
            const ipIdx = headers.findIndex(h => h.includes('IP'));
            const portIdx = headers.indexOf('端口');
            const delayIdx = headers.findIndex(h => h.includes('延迟'));
            const speedIdx = headers.findIndex(h => h.includes('下载速度'));
            const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') : headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
            const tlsIdx = headers.indexOf('TLS');
            for (const line of csvLines.slice(1)) {
              if (rec.length >= limitPerDomain) break;
              const cols = line.split(',').map(c => c.trim());
              if (tlsIdx !== -1 && cols[tlsIdx] && cols[tlsIdx].toLowerCase() !== 'true') continue;
              const raw = cols[ipIdx] || '';
              const ipm = raw.match(/(\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3})/);
              if (!ipm) continue;
              const ip = ipm[1].replace(/^\[|\]$/g, '');
              const port = portIdx !== -1 && cols[portIdx] ? parseInt(cols[portIdx]) : 443;
              const key = ip + ':' + port;
              if (seen.has(key)) continue;
              if (!pass(ip)) continue;
              seen.add(key);
              let nm = remarkIdx !== -1 && cols[remarkIdx] ? cols[remarkIdx] : '';
              if (!nm && delayIdx !== -1 && speedIdx !== -1) nm = 'CF优选 ' + (cols[delayIdx] || '') + 'ms ' + (cols[speedIdx] || '') + 'MB/s';
              if (nm) { counters[nm] = (counters[nm] || 0) + 1; rec.push({ ip, port, name: nm + '-' + String(counters[nm]).padStart(2, '0'), ...parseRegionMetadata(nm), ...(relay ? { relay: true } : {}) }); }
              else rec.push({ ip, port, name: '', ...(relay ? { relay: true } : {}) });
            }
            boundedSet(DNH_CACHE,ck,{t:now,ips:rec});
            return rec.slice();
          }
        }
        // HTML 线路表解析（wetest 等页面，对齐 CFBox）：<td data-label="线路名称">…</td><td data-label="优选地址">IP[:端口]</td>…
        if (content.includes('<tr') && content.includes('data-label')) {
          for (const row of content.match(/<tr[\s\S]*?<\/tr>/g) || []) {
            if (rec.length >= limitPerDomain) break;
            const cells = {};
            for (const td of row.match(/<td[^>]*>[\s\S]*?<\/td>/g) || []) {
              const lm = td.match(/data-label="([^"]*)"[^>]*>([\s\S]*?)<\/td>/);
              if (lm) cells[lm[1]] = lm[2].replace(/<[^>]+>/g, '').trim();
            }
            const ipm = (cells['优选地址'] || '').match(/(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/);
            if (!ipm) continue;
            const ip = ipm[1];
            const port = ipm[2] ? parseInt(ipm[2]) : 443;
            const key = ip + ':' + port;
            if (seen.has(key)) continue;
            if (!pass(ip)) continue;
            seen.add(key);
            // 名称保留线路名称/数据中心（含「移动/联通/电信」时面板 isp 筛选生效）
            const nm = (cells['线路名称'] || cells['数据中心'] || '线路').trim();
            if (nm) { counters[nm] = (counters[nm] || 0) + 1; rec.push({ ip, port, name: nm + '-' + String(counters[nm]).padStart(2, '0'), ...parseRegionMetadata(nm), ...(relay ? { relay: true } : {}) }); }
            else rec.push({ ip, port, name: '', ...(relay ? { relay: true } : {}) });
          }
          boundedSet(DNH_CACHE,ck,{t:now,ips:rec});
          return rec.slice();
        }
        // vless/trojan 订阅行提取（子订阅/转换器输出）：vless://uuid@host:port#名称
        for (const line of content.split(/\r?\n/)) {
          if (rec.length >= limitPerDomain) break;
          const vm = line.match(/(?:vless|trojan):\/\/[^@\s/]+@(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?/);
          if (!vm) continue;
          const host = vm[1].replace(/^\[|\]$/g, '');
          const port = vm[2] ? parseInt(vm[2]) : 443;
          const key = host + ':' + port;
          if (seen.has(key)) continue;
          if (!pass(host)) continue;
          seen.add(key);
          let nm = '';
          const hashIdx = line.indexOf('#');
          if (hashIdx >= 0) { try { nm = decodeURIComponent(line.slice(hashIdx + 1).trim()); } catch (e) { nm = line.slice(hashIdx + 1).trim(); } }
          if (nm) { counters[nm] = (counters[nm] || 0) + 1; rec.push({ ip: host, port, name: nm + '-' + String(counters[nm]).padStart(2, '0'), ...parseRegionMetadata(nm), ...(relay ? { relay: true } : {}) }); }
          else rec.push({ ip: host, port, name: '', ...(relay ? { relay: true } : {}) });
        }
        // 纯文本行：IP / IP:端口 / IP:端口#名称（如 bestcf 的 "IP:端口#地区随机 | 香港 HK | HKG | ..."）
        for (const raw of content.split(/\r?\n/)) {
          if (rec.length >= limitPerDomain) break;
          const m = raw.match(/(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?:#([^\r\n]*))?/);
          if (!m) continue;
          const ip = m[1];
          const port = m[2] ? parseInt(m[2]) : 443;
          const key = ip + ':' + port;
          if (seen.has(key)) continue;   // 源内去重（同 IP 同端口只留一条）
          if (!pass(ip)) continue;
          seen.add(key);
          // 结构化备注优先取地区元数据命名；无地区信息时保留原有名称提取规则。
          // 【新增】用户自定义名称（不含中文、不含 |）直接保留原样，例如 JP-A-147 / CF-B-163
          const rawName = (m[3] || '').trim();
          const region = parseRegionMetadata(rawName);
          if (rawName && !/[\u4e00-\u9fa5]/.test(rawName) && !rawName.includes('|')) {
            rec.push({ ip, port, name: rawName, ...region, ...(relay ? { relay: true } : {}) });
            continue;
          }
          // 结构化备注优先使用明确国家码，避免昵称盖过 HK / SG 等字段。
          let nm = rawName.includes('|') && region.cc ? (REGION_CN[region.cc] || REGION_NAMES[region.cc]) : '';
          if (!nm && m[3]) {
            // 优先匹配「中文地区名 + 空格 + 地区码」（如 "澳大利亚 AU"），锚定开头避免 4 字以上地区名被截断（如"澳大利亚"误取"大利亚"）
            const zhCode = m[3].match(/^\s*[\u4e00-\u9fa5]{2,5}\s+[A-Z]{2}/);
            if (zhCode) { const cn = zhCode[0].match(/[\u4e00-\u9fa5]{2,5}/); if (cn) nm = cn[0]; }
            else {
              const segs = m[3].split('|').map(s => s.trim());
              // 优先取「中文名+空格+地区码」段（bestcf 格式 "地区随机 | 香港 HK"），避免把 "地区随机" 前缀当地区名
              const segCode = segs.find(s => /^[\u4e00-\u9fa5]{2,5}\s+[A-Z]{2}$/.test(s));
              if (segCode) { const cn = segCode.match(/[\u4e00-\u9fa5]{2,5}/); if (cn) nm = cn[0]; }
              else {
                // | 分隔的独立中文段（如 "澳大利亚"、"印度尼西亚"），放宽到 2-5 字并排除 bestcf 等前缀词
                const zh = segs.find(s => /^[\u4e00-\u9fa5]{2,5}$/.test(s) && !/^(地区随机|随机优选|官方优选|优选|CF优选)$/.test(s));
                if (zh) nm = zh;
                else { const code = m[3].match(/\b([A-Z]{2})\b/); if (code) nm = REGION_CN[code[1]] || code[1]; }
              }
            }
          }
          if (nm) { counters[nm] = (counters[nm] || 0) + 1; rec.push({ ip, port, name: nm + '-' + String(counters[nm]).padStart(2, '0'), ...region, ...(relay ? { relay: true } : {}) }); }
          else rec.push({ ip, port, name: '', ...region, ...(relay ? { relay: true } : {}) });
        }
        boundedSet(DNH_CACHE,ck,{t:now,ips:rec});
        return rec.slice();   // 返回副本：均衡截断的 shift() 会原地修改数组，直接返回引用会污染缓存
      } catch (e) {
        // SWR 平滑容灾：当次拉取网络异常/超时，沿用上一轮有效缓存兜底，确保外部数据源抖动时订阅永不枯竭
        const stale = DNH_CACHE.get(ck);
        if (stale && now-stale.t<3600000 && stale.ips && stale.ips.length) return stale.ips.slice(0, limitPerDomain);
        return [];   // 无历史缓存才返回空
      }
    }
    // 用户自定义条目（IP / IP:端口 / 域名:端口 / 带#名称）：
    // 修复：原先纯 IP 与带端口/名称的条目不匹配下方域名正则被整体丢弃 → 自定义订阅模式节点全部丢失、名称被忽略
    if (!d.includes('://') && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) {
      const cm = d.match(/^(\[?[0-9a-fA-F:]+\]?|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})(?::(\d{1,5}))?(?:#([^\r\n]*))?$/i);
      if (!cm) return [];
      const host = cm[1].replace(/^\[|\]$/g, '');
      const port = cm[2] ? parseInt(cm[2]) : 443;
      const rawName = (cm[3] || '').trim();
      const isIp = isValidIp(host);
      if (!isIp && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) return [];
      if (filterCF && isIp && !isCloudflareIP(host)) return [];
      if (rawName) return [{ ip: host, port, name: rawName, ...parseRegionMetadata(rawName) }];   // 域名保留让客户端动态解析，自定义名称保留
      if (isIp) return [{ ip: host, port, name: '' }];
      // 无名称的域名：落入下方 DoH 解析分支（与原先一致）
    }
    const dnsKey = d + '|' + [filterCF,v6,limitPerDomain].join('|');
    const hit = DNH_CACHE.get(dnsKey);
    if (hit && now - hit.t < 10 * 60 * 1000) return hit.ips.slice(0, limitPerDomain).map((ip, i) => ({ ip, port: 443, name: d + '-' + (i + 1) }));
    // 按需解析 IPv6：默认仅查 A（IPv4），筛选含 IPv6 时才追加 AAAA 查询，节省 50% DNS 子请求
    const aRec = await qry(d, 'A', 1);
    // 严格自定义模式（filterCF=false）：域名解析结果原样下发，不做 CF 段过滤（用户自担可用性）
    let ips = filterCF ? aRec.filter(isCloudflareIP) : aRec;
    if (v6) {
      const aaaaRec = await qry(d, 'AAAA', 28);
      ips = [...new Set(aRec.concat(aaaaRec))].filter(ip => filterCF ? isCloudflareIP(ip) : true);
    }
    ips = ips.slice(0, limitPerDomain);
    if (!ips.length) {
      // SWR：当次解析失败（死链/超时）但有历史缓存（无论是否过期）→ 沿用旧数据兜底
      if (hit && now-hit.t<3600000 && hit.ips && hit.ips.length) return hit.ips.slice(0, limitPerDomain).map((ip, i) => ({ ip, port: 443, name: d + '-' + (i + 1) }));
      return [];
    }
    boundedSet(DNH_CACHE,dnsKey,{t:now,ips});
    return ips.map((ip, i) => ({ ip, port: 443, name: d + '-' + (i + 1) }));
  }));
  // 按输入顺序均衡截断：轮流取每条目的节点，保证各地区/域名都有且总量受控
  const out = [];
  let got = 0;
  while (got < maxTotal) {
    let any = false;
    for (const arr of perItem) {
      if (got >= maxTotal) break;
      if (arr.length) { out.push(arr.shift()); got++; any = true; }
    }
    if (!any) break;
  }
  return out;
}

function rotateItems(items,seed){
  const score=value=>{let h=2166136261;for(const ch of seed+'|'+value){h^=ch.charCodeAt(0);h=Math.imul(h,16777619);}return h>>>0;};
  return items.slice().sort((a,b)=>score(a.ip+':'+a.port)-score(b.ip+':'+b.port));
}

async function buildNodes(cfg, cap = 800, skipSet = null) {
  const nodes = [];
  // 按地址和端口保留来源地区；国家码不再依赖机房码，同 IP 不同端口互不覆盖。
  cfg._regionByEndpoint = new Map();
  const used = new Set();
  // 订阅模式：random 随机优选（CF CIDR 随机生成指定数量，不经域名解析）
  const mode = (cfg.optimizer && cfg.optimizer.subMode) || '';
  // 筛选含 IPv6 时随机生成/补足混合 v4+v6 段；仅勾选 IPv6 时全走官方 v6 网段（ips-v6 拉取，实测可用）
  const ipT = (cfg.filter && cfg.filter.ipType) || [];
  const wantV6 = ipT.includes('IPv6');
  const onlyV6 = ipT.length === 1 && ipT[0] === 'IPv6';
  const RAND_CIDRS = onlyV6 ? OFFICIAL_V6_CIDRS : (wantV6 ? [...REACHABLE_CIDRS, ...OFFICIAL_V6_CIDRS] : REACHABLE_CIDRS);
  // 仅自定义模式（custom + 关闭追加）：严格按「优选节点」输入框内容下发，放行非 CF 段 IP（用户自担可用性）；
  // 其它模式（默认/追加/随机）入口必须是 CF 段——非 CF IP 无法转发到 Worker（历史 v2rayNG 全 -1 根因）
  const allowNonCF = (mode === 'custom' && !(cfg.optimizer && cfg.optimizer.subIncludeDefault));
  // 节点形态统一按 1.0.6 机制（方案 B）：所有模式端口原样单端口下发（固定 443、不随机 TLS 端口、不追加明文端口变体）
  // 测活剔除范围（方案 A）：默认模式开启测活剔除死节点；自定义订阅 / 随机优选模式不测活
  const probeSkip = (mode === 'custom' || mode === 'random');
  const push = (server, port, name, trusted, colo, cc) => {
    if (nodes.length >= cap) return;   // 生成过程限流：避免多协议膨胀超 Worker CPU
    // 入口 IP 硬性要求：非 CF 段 IP 无法转发到 Worker，直接丢弃；
    // 例外：bestcf 地区优选池的社区中转 IP（trusted 标记）可用作客户端入口（v1.0.5 修复）
    if (isValidIp(server) && !isCloudflareIP(server) && !allowNonCF && !trusted) return;
    const key = server + ':' + port;   // 按 服务器:端口 去重（单端口机制：同 IP 同端口仅下发一次）
    if (used.has(key)) return;
    used.add(key);
    const region = colo || cc ? {colo,cc} : parseRegionMetadata(name);
    if (region.cc || region.colo) cfg._regionByEndpoint.set(key,region);
    const isTls = !HTTP_PORTS.has(Number(port));
    if (cfg.tlsOnly && !isTls) return;   // TLS 控制：仅下发 TLS 端口节点，明文端口跳过
    // 节点端口统一按 1.0.6 机制（方案 B）：端口原样下发（默认/自定义/随机优选均固定源端口，通常是 443），
    // 不做 TLS 端口随机（443 全域可达性最佳），也不追加明文端口变体
    const finalPort = Number(port);
    if (cfg.enableVless) nodes.push(vlessNode(cfg, server, finalPort, name));
    if (cfg.enableTrojan) nodes.push(trojanNode(cfg, server, isTls ? finalPort : Number(port), name));  // Trojan 明文/TLS 端口均下发
    if (cfg.enableXhttp && isTls) nodes.push(vlessNode(cfg, server, finalPort, name, { type: 'xhttp' }));  // XHTTP 仅 TLS 端口
  };
  // 单端口下发（1.0.6 机制，方案 B）：每个地址按源端口（通常 443）单条下发，不追加明文端口变体
  const multiPort = (server, port, name, trusted, colo, cc) => {
    push(server, Number(port) || 443, name, trusted, colo, cc);
  };
  if (mode === 'random') {
    let n = Math.min(Math.max(parseInt(cfg.optimizer.subRandomCount) || 16, 1), Math.min(99, cap));
    // 节点数量控制：开启后以设定数量为准（全局生效，与轮询开/关无关；提升随机优选生成量，使下发达到设定总数）
    if (cfg.nodeLimit) {
      const lim = parseInt(cfg.nodeLimitCount) || 0;
      if (lim > 0) n = Math.min(Math.max(n, lim), cap);
    }
    // 数量 = 下发节点总数（含启用的所有协议），而非 IP 数：每个 IP 生成一条后计数，达 n 即止
    const protoCount = (cfg.enableVless ? 1 : 0) + (cfg.enableTrojan ? 1 : 0) + (cfg.enableXhttp ? 1 : 0) || 1;
    let made = 0;
    // 去重下发：随机模式生成 3 倍数量后过滤已下发 IP；新 IP 排前、已下发 IP 紧随补齐，节点总量恒定
    const randPool = randomIPsFromCidrs(RAND_CIDRS, Math.ceil(n / protoCount) * 3);
    let randIPs = randPool;
    if (skipSet) {
      const unissued = randPool.filter(ip => !skipSet.has(ip));
      const prev = randPool.filter(ip => skipSet.has(ip));
      randIPs = [...unissued, ...prev];
    }
    for (const ip of randIPs) {
      if (made >= n) break;
      // 随机优选模式：按 1.0.6 机制——每个 IP 每协议仅固定 443 单端口下发，不随机 TLS 端口、不追加明文端口变体
      if (cfg.enableVless) { nodes.push(vlessNode(cfg, ip, 443, '随机优选-' + String(made + 1).padStart(2, '0'))); made++; }
      if (made >= n) break;
      if (cfg.enableTrojan) { nodes.push(trojanNode(cfg, ip, 443, '随机优选-' + String(made + 1).padStart(2, '0'))); made++; }
      if (made >= n) break;
      if (cfg.enableXhttp) { nodes.push(vlessNode(cfg, ip, 443, '随机优选-' + String(made + 1).padStart(2, '0'), { type: 'xhttp' })); made++; }
    }
    return nodes;
  }
  const domains = String(cfg.preferredDomains || '').split(/[\n,;]+/).map(s => s.trim()).filter(s => s && !s.includes('://'));  // URL 数据源由 resolvePreferredDomains 解析，不作为服务器地址
  // 兜底名按入口形态区分：域名入口 → “优选域名-XX”，IP 入口 → “优选IP-XX”（原实现对两者一律写“优选IP-XX”，
  // 域名节点名与来源不符：用户在客户端按名字判断来源时会误判）
  let _domIdx = 0, _ipIdx = 0;
  domains.forEach((d) => {
    // 支持 "IP:端口#名称" 格式：剥离 #名称 后再解析地址，名称用于节点命名（无名称时按入口形态兜底）
    const hash = d.indexOf('#');
    const addr = (hash >= 0 ? d.slice(0, hash) : d).trim();
    const nm = (hash >= 0 ? d.slice(hash + 1) : '').trim();
    const p = parseHostPort(addr, 443);
    if (p.host.startsWith('*.')) return;   // 通配符域名无法作为服务器地址，其 IP 由 resolvePreferredDomains 解析下发
    const _fb = isValidIp(p.host)
      ? '优选IP-' + String(++_ipIdx).padStart(2, '0')
      : '优选域名-' + String(++_domIdx).padStart(2, '0');
    multiPort(p.host, p.port, nm || _fb);
  });
  // 双选（IPv4+IPv6）时把 preferredIPs 重排为 v4/v6 交替：各来源 v4 天然排前，
  // 若不做交替，开启「节点数量控制 / 轮询」后 push 限流截断（cap）会先占满 v4，IPv6 被整体挤掉——
  // 交替后按顺序截断天然保持 v4/v6 混合比例（约 1:1），数量控制与轮询开启时同样生效
  let prefIPs = cfg.preferredIPs || [];
  if(cfg._rotationSeed)prefIPs=rotateItems(prefIPs,cfg._rotationSeed);
  if (wantV6 && !onlyV6 && prefIPs.length > 1) {
    const v4l = [], v6l = [];
    for (const x of prefIPs) (String(x.ip).indexOf(':') >= 0 ? v6l : v4l).push(x);
    const mixed = [];
    const mx = Math.max(v4l.length, v6l.length);
    for (let i = 0; i < mx; i++) {
      if (i < v4l.length) mixed.push(v4l[i]);
      if (i < v6l.length) mixed.push(v6l[i]);
    }
    prefIPs = mixed;
  }
  prefIPs.forEach((x, i) => {
    multiPort(x.ip, x.port || 443, x.name || '优选IP-' + String(i + 1).padStart(2, '0'), x.relay === true, x.colo, x.cc);
  });
  // 自定义订阅模式：仅下发用户设置节点，不兜底内置池、不做 CF 随机补足；
  // 但开启「追加内置及默认节点」(subIncludeDefault) 后需要完整下发自定义+默认+补足，因此继续走补足逻辑
  if (mode === 'custom' && !(cfg.optimizer && cfg.optimizer.subIncludeDefault)) return nodes;
  if (!domains.length && !(cfg.preferredIPs || []).length) {
    // 无任何优选：内置优选 IP 池（开箱即用）+ 官方域名兜底（无明确地区，直接使用“优选IP-XX”名称）
    parseIPList(BUILTIN_PREFERRED_IPS.join('\n')).forEach(x => multiPort(x.ip, x.port || 443, x.name || '0'));
    BUILTIN_OFFICIAL_DOMAINS.forEach((d, i) => multiPort(d, 443, '优选域名-' + String(i + 1).padStart(2, '0')));
  }
  // CF CIDR 随机补足：节点数不足 fillCount（封顶 cap）时随机生成补齐（大量下发，客户端自动择优；对齐 1.0.6/2.0 第一版）
  // 补足候选做小范围 TCP 测活（可达排前，不足由未测活补齐），保证节点数量充足
  const fillCount = Math.min(Math.max(parseInt((cfg.optimizer && cfg.optimizer.fillCount) || 0) || 0, 0), 5000);
  const need = Math.min(fillCount, cap) - used.size;   // 按唯一 IP 数补足，而非节点数（多协议节点会膨胀 nodes.length）
  if (need > 0) {
    // 优先用实测高存活率大站任播轮换补足（随机 CIDR 生成的任播 IP 大量不可达、客户端测速 -1）；
    // 轮换仍带已下发去重，超出 STABLE 数量后回退随机 CIDR（保证海量下发数量）；
    // 候选再做 TCP 测活（1.5s 超时，网络等待不计 CPU），可达排前，不足由未测活补齐
    const freshStable = skipSet ? BUILTIN_STABLE_IPS.filter(ip => !skipSet.has(ip)) : BUILTIN_STABLE_IPS.slice();
    const fillPool = randomIPsFromCidrs(RAND_CIDRS, need * 3);
    const freshRand = skipSet ? fillPool.filter(ip => !skipSet.has(ip)) : fillPool;
    let fillIPs = [...freshStable, ...freshRand];
    if (fillIPs.length < need) fillIPs = [...BUILTIN_STABLE_IPS, ...fillPool];
    if (fillIPs.length > 0) {
      const probeCount = Math.min(fillIPs.length, Math.max(need, 20), 60);
      const probeShot = fillIPs.slice(0, probeCount);
      // 自定义订阅 / 随机优选模式不进行测活（节点原样下发）；默认模式保持测活剔除死节点
      // 并发受限（≤4）：排队不再计入超时，避免假死
      const probeOk = probeSkip ? probeShot.map(() => true) : await probeAll(probeShot, (ip) => testProxyAlive(ip,443,1500,cfg.probeAlive));
      const alive = probeShot.filter((ip, i) => probeOk[i]);
      const rest = fillIPs.slice(probeCount);
      fillIPs = [...alive, ...rest].slice(0, need);
    }
    let fi = 0;
    for (const ip of fillIPs) {
      if (nodes.length >= cap) break;   // 补足同样受 cap 限流（与 push 一致）
      fi++;
      multiPort(ip, 443, '随机补足-' + String(fi).padStart(3, '0'));
    }
  }
  return nodes;
}

// 从节点链接提取服务器地址与端口（URL API 对 vless:// 等非标准 scheme 不解析 port/IPv6，需手动处理）
function parseNodeServer(n) {
  const at = n.indexOf('@');
  const q = n.indexOf('?', at);
  const auth = (q > at && at >= 0) ? n.slice(at + 1, q) : n.slice(at + 1);
  if (auth.startsWith('[')) {
    const end = auth.indexOf(']');
    const host = end > 0 ? auth.slice(1, end) : auth;
    const rest = auth.slice(end + 1);
    const port = rest.startsWith(':') ? parseInt(rest.slice(1)) : 443;
    return { host, port: isNaN(port) ? 443 : port };
  }
  const idx = auth.lastIndexOf(':');
  if (idx > 0) {
    const port = parseInt(auth.slice(idx + 1));
    return { host: auth.slice(0, idx), port: isNaN(port) ? 443 : port };
  }
  return { host: auth, port: 443 };
}

// 轻量查询参数提取：从分享链接字符串提取指定参数（替代 new URL().searchParams，避免 URL 对象开销与 GC 压力）
function getParam(n, key) {
  const q = n.indexOf('?');
  if (q < 0) return null;
  const hash = n.indexOf('#', q);
  const seg = (hash > q ? n.slice(q + 1, hash) : n.slice(q + 1));
  for (const pair of seg.split('&')) {
    const eq = pair.indexOf('=');
    const k = eq > 0 ? pair.slice(0, eq) : pair;
    if (k === key) return eq > 0 ? decodeURIComponent(pair.slice(eq + 1)) : '';
  }
  return null;
}

// 解析分享链接为统一节点信息（五个客户端生成器共用；纯字符串解析，无 new URL 对象开销）
function parseShareNode(n, i) {
  const { host: srvRaw, port: prt } = parseNodeServer(n);
  // IPv6 以裸地址传递：Clash/Sing-box/Surge/Loon 的 server 字段端口均为独立字段/逗号分隔，要求裸 IPv6；
  // 仅 vless URI（生成处单独加方括号）与 QuanX（ip:port 格式，生成处补方括号）需要 [ip] 形式
  const srv = srvRaw;
  const hashIdx = n.indexOf('#');
  let name = `节点${i + 1}`;
  if (hashIdx >= 0) { try { name = decodeURIComponent(n.slice(hashIdx + 1)) || name; } catch (e) { /* 忽略非法编码 */ } }
  const at = n.indexOf('@');
  let user = '';
  if (at >= 0) {
    const proto = n.indexOf('://');
    const start = proto >= 0 ? proto + 3 : 0;
    try { user = decodeURIComponent(n.slice(start, at)); } catch (e) { user = n.slice(start, at); }
  }
  const isTrojan = n.startsWith('trojan://');
  const tls = isTrojan || (getParam(n, 'security') || 'tls') === 'tls';
  return { srv, prt, name, user, isTrojan, tls };
}

// 运营商标签仍按名称匹配；地区使用解析后的国家/地区码。
const ISP_TAGS = { 移动: ['移动', 'CM', 'CHINAMOBILE'], 联通: ['联通', 'CU', 'UNICOM'], 电信: ['电信', 'CT', 'CHINATELECOM'] };
const FILTER_ISPS = ['移动', '联通', '电信'];
const FILTER_IPTYPES = ['IPv4', 'IPv6'];

// 按面板筛选配置过滤节点（region 优先用来源元数据，ipType 按地址类型，isp 按名称标记）
// 任何维度筛选后为空时逐级放宽（isp → ipType → region），保证订阅永不为空（避免客户端「无效订阅」）
function filterNodes(nodes, filter, regionByEndpoint) {
  if (!filter || !filter.region && !filter.ipType && !filter.isp) return nodes;
  const region = filter.region || 'all';
  const ipType = filter.ipType || FILTER_IPTYPES;
  const isp = filter.isp || FILTER_ISPS;
  // 预解析节点（名称解析一次，供各轮过滤与池标记检查复用）
  const meta = nodes.map(n => {
    const { host, port } = parseNodeServer(n);
    let name = '';
    try {
      const h = n.indexOf('#');
      if (h >= 0) name = decodeURIComponent(n.slice(h + 1) || '');
    } catch (e) { name = ''; }
    const sourceRegion = regionByEndpoint?.get(host+':'+port) || parseRegionMetadata(name);
    return { host, name, up: name.toUpperCase(), cc: sourceRegion.cc || countryCodeForColo(sourceRegion.colo) };
  });
  // 池内无任何运营商标记时 ISP 筛选不生效（默认数据源节点名仅含地区，按运营商过滤会清空节点池）
  const poolHasIsp = meta.some(m => m.up && Object.keys(ISP_TAGS).some(k => (ISP_TAGS[k] || [k]).some(t => m.up.includes(t.toUpperCase()))));
  const apply = (rg, t, s) => {
    // rg 兼容字符串（旧配置 'all'/'HK'）与数组（面板多选地区 ['HK','SG']）；数组含 'all' 或空 = 全部地区
    const regions = (Array.isArray(rg) ? rg : [rg]).map(r => String(r).toUpperCase());
    const selected = !regions.length || regions.includes('ALL') ? null : regions;
    const partial = s.length > 0 && s.length < FILTER_ISPS.length;
    return nodes.filter((n, i) => {
      const m = meta[i];
      const isV6 = m.host.indexOf(':') >= 0;
      if (!m.name) return false;  // 跳过无法解析的非法节点
      if (selected && m.cc && !selected.includes(m.cc)) return false;
      if (selected && !m.cc) {
        // 无地区标记的通用节点（优选IP-XX / 优选IP-SXX / 优选域名-XX / 域名-XX / 随机补足-XXX / 随机优选-XX /
        // 原生地址 / 内置·保底-XX）是 CF 通用入口，任意地区可用，不参与地区过滤；地区过滤仅剔除明确标记为
        // 其它地区的节点，避免指定地区后节点数量骤减
        // ★ 白名单必须与各处命名兜底同步：漏一个前缀，用户勾选地区后该批节点会被整批剔除（静默少节点）
        if (!/^(优选IP(-S)?|优选域名|域名|随机补足|随机优选|内置·保底)-?\d+/.test(m.name)
            && m.name !== '原生地址') return false;
      }
      if (t.length === 1) {
        if (t[0] === 'IPv4' && isV6) return false;
        if (t[0] === 'IPv6' && !isV6) return false;
      }
      if (partial && poolHasIsp && !s.some(k => (ISP_TAGS[k] || [k]).some(t2 => m.up.includes(t2.toUpperCase())))) return false;
      return true;
    });
  };
  let out = apply(region, ipType, isp);
  if (!out.length) out = apply(region, ipType, FILTER_ISPS);          // 放宽 isp
  if (!out.length) out = apply(region, FILTER_IPTYPES, FILTER_ISPS);  // 放宽 ipType
  if (!out.length) out = apply('all', FILTER_IPTYPES, FILTER_ISPS);   // 放宽 region
  return out;
}

// ---------- Clash YAML ----------
// YAML 标量值序列化（裸值或 JSON 字符串，避免特殊字符破坏 YAML）
function yamlVal(v) {
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  const s = String(v);
  return /^[\w.\-/\u4e00-\u9fa5]+$/.test(s) ? s : JSON.stringify(s);
}
// 单个 Clash 代理块模板化生成（固定结构，800 节点级订阅生成耗时降低一个数量级）
function clashProxyYaml(p) {
  const L = [];
  L.push('  - name: ' + yamlVal(p.name));
  L.push('    type: ' + p.type);
  L.push('    server: ' + yamlVal(p.server));
  L.push('    port: ' + p.port);
  if (p.type === 'vless') L.push('    uuid: ' + yamlVal(p.uuid));
  else L.push('    password: ' + yamlVal(p.password));
  L.push('    network: ' + p.network);
  L.push('    udp: true');
  if (p.tls) {
    L.push('    tls: true');
    L.push('    skip-cert-verify: false');   // 使用部署域名作为 SNI 并验证证书
    // ALPN：ws/trojan 强制 HTTP/1.1（CF Worker 的 WebSocket 仅支持 HTTP/1.1 升级，mihomo utls(chrome) 默认 ALPN 含 h2 → WS 升级失败）；
    // xhttp 必须 h2（stream-one 依赖 HTTP/2 双向流，h1.1 请求体未发完 CF 边缘无法回传响应 → Clash Verge 节点全部超时）
    L.push(p.network === 'xhttp' ? '    alpn: [h2]' : '    alpn: [http/1.1]');
    L.push('    servername: ' + yamlVal(p.servername));
    if (p.type === 'trojan') L.push('    sni: ' + yamlVal(p.servername));   // mihomo trojan 只认 sni 字段（servername 被忽略）：CF 优选 IP 下缺 sni 时 TLS SNI 回落为 server(IP)，Go/utls 对 IP 型 ServerName 不发送 SNI 扩展 → CF 边缘无法路由 → 403 → Clash Verge 全 Error
    L.push('    client-fingerprint: chrome');
    if (p['ech-opts']) {
      L.push('    ech-opts:');
      L.push('      enable: ' + yamlVal(p['ech-opts'].enable));
      L.push('      query-server-name: ' + yamlVal(p['ech-opts']['query-server-name']));
    }
  }
  if (p.network === 'ws') {
    L.push('    ws-opts:');
    L.push('      path: ' + yamlVal(p['ws-opts'].path));
    L.push('      headers:');
    L.push('        Host: ' + yamlVal(p['ws-opts'].headers.Host));
  } else if (p.network === 'xhttp') {
    const xo = p['xhttp-opts'];
    L.push('    xhttp-opts:');
    L.push('      path: ' + yamlVal(xo.path));
    L.push('      mode: ' + yamlVal(xo.mode));
    // 修复：mihomo 规范中 XHTTP 请求主机字段名为 host（headers.Host 是错误写法，
    // 会导致 Nekobox 等客户端把 'Host: 域名' 整行误导入 XHTTP 标头导致节点报错）
    L.push('      host: ' + yamlVal(xo.host));
    L.push('      x-padding-obfs-mode: ' + yamlVal(xo['x-padding-obfs-mode']));
    L.push('      x-padding-method: ' + yamlVal(xo['x-padding-method']));
    L.push('      x-padding-placement: ' + yamlVal(xo['x-padding-placement']));
    L.push('      x-padding-header: ' + yamlVal(xo['x-padding-header']));
    L.push('      x-padding-key: ' + yamlVal(xo['x-padding-key']));
  }
  return L.join('\n');
}
function generateClash(cfg, nodes) {
  const host = cfg.host;
  const path = '/' + cfg.path;
  const seen = new Set();
  // XHTTP 节点按 mihomo xhttp-opts 规范输出（含 x-padding 混淆参数），与 WS/Trojan 一并下发
  const proxies = nodes.map((n) => {
    const { user, srv, prt, name: baseName, isTrojan, tls } = parseShareNode(n, 0);
    let name = baseName;
    const xType = getParam(n, 'type') || 'ws';
    // 同名去重：同一名称（同一 IP 多协议节点或不同 IP 同名优选池）追加协议后缀并保证全局唯一——
    // 若后缀仍被占用（多个同名 IP 的 Trojan/XHTTP 节点），继续递增序号，避免 mihomo「duplicate name」校验失败
    if (seen.has(name)) {
      const suff = isTrojan ? 'T' : (xType === 'xhttp' ? 'X' : 'W');
      let cand = name + '·' + suff;
      let k = 2;
      while (seen.has(cand)) { cand = name + '·' + suff + k; k++; }
      name = cand;
    }
    seen.add(name);
    const base = {
      name, server: srv, port: prt, udp: true,
      ...(tls ? { tls: true, 'skip-cert-verify': false, servername: host, 'client-fingerprint': 'chrome', alpn: ['http/1.1'] } : {}),
      ...(cfg.ech && tls ? { 'ech-opts': { enable: true, 'query-server-name': cfg.echHost || 'cloudflare-ech.com' } } : {})   // 修复 #6：mihomo ECH 官方格式为顶层 ech-opts（enable + query-server-name），旧 tls-opts.ech 不被识别导致 ECH 未生效
    };
    if (isTrojan) {
      return { ...base, type: 'trojan', password: user, network: 'ws', 'ws-opts': { path, headers: { Host: host } } };
    }
    if (xType === 'xhttp') {
      // 从节点链接的 extra 参数恢复 x-padding 混淆配置（由 UUID 派生，与服务端一致）
      let xo = {};
      try { xo = JSON.parse(getParam(n, 'extra') || '{}'); } catch (e) { /* extra 解析失败则用空 */ }
      return {
        ...base, type: 'vless', uuid: user, network: 'xhttp',
        alpn: ['h2'],   // 修复：xhttp stream-one 依赖 HTTP/2 双向流必须 h2（ws 节点才用 http/1.1）
        'xhttp-opts': {
          path,
          mode: 'stream-one',
          // 修复：mihomo 规范 XHTTP 主机字段为 host（headers.Host 会被 Nekobox 误读为标头）
          host,
          'x-padding-obfs-mode': xo.xPaddingObfsMode !== undefined ? xo.xPaddingObfsMode : true,
          'x-padding-method': xo.xPaddingMethod || 'tokenish',
          'x-padding-placement': xo.xPaddingPlacement || 'queryInHeader',
          'x-padding-header': xo.xPaddingHeader || '',
          'x-padding-key': xo.xPaddingKey || ''
        }
      };
    }
    return { ...base, type: 'vless', uuid: user, network: 'ws', 'ws-opts': { path, headers: { Host: host } } };
  });
  // 节点排序：443端口优先（非标准端口如8443在mihomo下HTTPS握手易被GFW干扰，放后面避免默认选中）
  proxies.sort((a, b) => (a.port === 443 ? 0 : 1) - (b.port === 443 ? 0 : 1));
  const yaml = `# CFNext 订阅
test-url: 'http://www.gstatic.com/generate_204'
proxies:
${proxies.map(p => clashProxyYaml(p)).join('\n')}
${CLASH_TEMPLATE}
`;
  return yaml;
}

// Surfboard（Surge 兼容格式，不支持 VLESS/XHTTP，Trojan 必须 TLS）：
// 将 VLESS TLS 节点转换为 Trojan（密码=UUID，TLS/WS 参数一致），XHTTP 与明文端口节点过滤，
// 输出 Surge 风格配置（[General]/[Proxy]/[Proxy Group]/[Rule]），Surfboard 直接导入
function generateSurfboard(cfg, nodes) {
  const host = cfg.host, path = '/' + cfg.path;
  if (!cfg.enableTrojan) throw new AppError(400, 'Surfboard 需要先启用 Trojan');
  const sb = [];
  for (const n of nodes) {
    if (n.startsWith('trojan://') && n.indexOf('security=none') < 0) sb.push(n);
    else if (n.startsWith('vless://') && n.indexOf('type=xhttp') < 0 && n.indexOf('security=none') < 0)
      sb.push(n.replace(/^vless:\/\/[^@]+@/, 'trojan://' + encodeURIComponent(cfg.trojanPassword || cfg.uuid) + '@').replace('encryption=none&', ''));
  }
  const lines = sb.map((n, i) => {
    const { user, srv, prt, name } = parseShareNode(n, i);
    return `${name} = trojan, ${srv}, ${prt}, password=${user}, ws=true, ws-path=${path}, ws-headers=Host:${host}, tls=true, skip-cert-verify=false, sni=${host}`;
  });
  return `#!MANAGED-CONFIG
[General]
loglevel = notify
dns-server = 223.5.5.5, 119.29.29.29

[Proxy]
${lines.join('\n')}

[Proxy Group]
🚀 节点选择 = select, ${lines.map(l => l.split(' = ')[0]).join(', ')}
🌐 全球直连 = select, DIRECT
🐟 漏网之鱼 = select, 🚀 节点选择

[Rule]
GEOIP,CN,DIRECT
FINAL,🐟 漏网之鱼
`;
}

// ---------- Sing-box JSON ----------
function generateSingbox(cfg, nodes) {
  const host = cfg.host;
  const path = '/' + cfg.path;
  const outbounds = nodes.map((n, i) => {
    const { user, srv, prt, name, isTrojan, tls } = parseShareNode(n, i);
    const type = getParam(n, 'type') || 'ws';
    // XHTTP 在 sing-box 中不支持 uTLS（官方限制，xhttp+utls 会导致 outbound 异常/流量不通），xhttp 模式禁用 utls
    // 使用部署域名 server_name 验证证书；
    // 强制 HTTP/1.1 ALPN 避免 CF 边缘协商 h2 导致 WS 升级失败（v1.0.5 修复）
    // xhttp stream-one 依赖 HTTP/2 双向流，ALPN 必须 h2（h1.1 经 CF 边缘请求体未发完响应无法回传 → 超时）；ws 才用 http/1.1
    const tlsObj = tls ? (type === 'xhttp'
      ? { enabled: true, server_name: host, insecure: false, alpn: ['h2'] }
      : { enabled: true, server_name: host, insecure: false, alpn: ['http/1.1'], utls: { enabled: true, fingerprint: 'chrome' } })
      : { enabled: false };
    // early data：TLS 下的 ws 走 2048 字节 early data（ed=2048），
    // 减少首包往返；明文 ws 与 xhttp 不启用
    const transport = type === 'xhttp' ? { type: 'xhttp', mode: 'stream-one', path } :
      (tls ? {
        type: 'ws', path, headers: { Host: host },
        max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol'
      } : { type: 'ws', path, headers: { Host: host } });
    if (isTrojan) {
      return {
        type: 'trojan', tag: name, server: srv, server_port: prt,
        password: user, tls: tlsObj,
        transport
      };
    }
    return {
      type: 'vless', tag: name, server: srv, server_port: prt,
      uuid: user, packet_encoding: 'xudp',
      tls: tlsObj,
      transport
    };
  });
  const tags = outbounds.map(o => o.tag);
  // rule_set 分流（参考 CFNext sing-box 生成）：远程规则集（MetaCubeX .list 文本格式）+ 主流分流域名
  const RULE_SETS = [
    ['geosite-cn', '🎯 全球直连'], ['geosite-google', '🌐 谷歌服务'], ['geosite-apple', '🍎 苹果服务'],
    ['geosite-microsoft', 'Ⓜ️ 微软服务'], ['geosite-openai', '🤖 OpenAI'], ['geosite-spotify', '🌍 国外媒体'],
    ['geosite-youtube', '🌍 国外媒体'], ['geosite-netflix', '🌍 国外媒体'], ['geosite-disney', '🌍 国外媒体'],
    ['geosite-twitter', '🌍 国外媒体'], ['geosite-telegram', '🌍 国外媒体'], ['geosite-github', '🌍 国外媒体'],
    ['geosite-category-ads-all', 'block']
  ];
  const config = {
    log: { level: 'info' },
    // 完整 DNS + fakeip：远程 DoH 解析（走代理）+ 本地直连 DNS 兜底；fakeip 加速分流
    dns: {
      servers: [
        { tag: 'dns-remote', address: 'https://1.1.1.1/dns-query' },
        { tag: 'dns-direct', address: 'udp://223.5.5.5' }
      ],
      strategy: 'ipv4_only',
      independent_cache: true,
      fakeip: { enabled: true, inet4_range: '198.18.0.0/15', store_fakeip: true }
    },
    inbounds: [
      {
        type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080,
        sniff: true, sniff_override_destination: true
      },
      {
        type: 'tun', tag: 'tun-in', interface_name: 'tun0',
        inet4_address: ['172.19.0.1/30'], mtu: 9000,
        auto_route: true, strict_route: true, stack: 'mixed',
        sniff: true, sniff_override_destination: true
      }
    ],
    outbounds: [
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
      { type: 'dns', tag: 'dns-out' },
      { type: 'selector', tag: '🚀 节点选择', outbounds: tags },
      { type: 'selector', tag: '🎯 全球直连', outbounds: ['direct'] },
      { type: 'selector', tag: '🐟 漏网之鱼', outbounds: ['🚀 节点选择', '🎯 全球直连'] },
      { type: 'selector', tag: '🌍 国外媒体', outbounds: ['🚀 节点选择'] },
      { type: 'selector', tag: '🌐 谷歌服务', outbounds: ['🚀 节点选择'] },
      { type: 'selector', tag: '🤖 OpenAI', outbounds: ['🚀 节点选择'] },
      { type: 'selector', tag: '🍎 苹果服务', outbounds: ['🎯 全球直连'] },
      { type: 'selector', tag: 'Ⓜ️ 微软服务', outbounds: ['🎯 全球直连'] }
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { ip_is_private: true, outbound: 'direct' },
        ...RULE_SETS.map(([rs, out]) => ({ rule_set: [rs], outbound: out })),
        { geoip: ['cn'], outbound: 'direct' },   // 大陆 IP 兜底直连（覆盖未收录域名 / 纯 IP 连接的大陆应用）
        { ip_is_private: true, outbound: 'block' }
      ],
      rule_set: RULE_SETS.map(([rs]) => ({
        type: 'remote', tag: rs, format: 'source',
        url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/' + rs + '.list'
      })),
      final: '🐟 漏网之鱼',
      auto_detect_interface: true,
      default_domain_resolver: { server: 'dns-remote' }
    },
    experimental: {
      clash_api: { external_controller: '127.0.0.1:9090' }
    }
  };
  return JSON.stringify(config, null, 2);
}

// ---------- Surge ----------
function generateSurge(cfg, nodes) {
  const host = cfg.host, path = '/' + cfg.path;
  const proxies = nodes.map((n, i) => {
    const { user, srv, prt, name, isTrojan, tls } = parseShareNode(n, i);
    const tlsPart = tls ? ', tls=true, skip-cert-verify=false, sni=' + host : ', tls=false';
    return isTrojan
      ? `${name} = trojan, ${srv}, ${prt}, password=${user}, ws=true, ws-path=${path}, ws-headers=Host:${host}${tlsPart}`
      : `${name} = vless, ${srv}, ${prt}, username=${user}, ws=true, ws-path=${path}, ws-headers=Host:${host}${tlsPart}`;
  });
  return `#!MANAGED-CONFIG
[General]
loglevel = notify
dns-server = 223.5.5.5, 119.29.29.29

[Proxy]
${proxies.join('\n')}

[Proxy Group]
🚀 节点选择 = select, ${proxies.map(p => p.split(' = ')[0]).join(', ')}
🌐 全球直连 = select, DIRECT
🐟 漏网之鱼 = select, 🚀 节点选择

[Rule]
GEOIP,CN,DIRECT
FINAL,🐟 漏网之鱼
`;
}

// ---------- Loon ----------
function generateLoon(cfg, nodes) {
  const host = cfg.host, path = '/' + cfg.path;
  const proxies = nodes.map((n, i) => {
    const { user, srv, prt, name, isTrojan, tls } = parseShareNode(n, i);
    const tlsPart = tls ? ', tls=true, skip-cert-verify=false, sni=' + host : ', tls=false';
    return isTrojan
      ? `${name} = trojan, ${srv}, ${prt}, password=${user}, ws=true, ws-path=${path}, ws-headers=Host:${host}${tlsPart}`
      : `${name} = vless, ${srv}, ${prt}, username=${user}, ws=true, ws-path=${path}, ws-headers=Host:${host}${tlsPart}`;
  });
  const names = proxies.map(p => p.split(' = ')[0]).join(', ');
  return `[General]
dns-server = 223.5.5.5, 119.29.29.29

[Proxy]
${proxies.join('\n')}

[Proxy Group]
🚀 节点选择 = select, ${names}
🌐 全球直连 = select, DIRECT
🐟 漏网之鱼 = select, ${names}

[Rule]
GEOIP,CN,DIRECT
FINAL,🐟 漏网之鱼
`;
}

// ---------- Quantumult X ----------
function generateQuanX(cfg, nodes) {
  const host = cfg.host, path = '/' + cfg.path;
  // QuanX 的 ip:port 格式中 IPv6 必须带方括号（裸 v6 与端口冒号歧义）
  const qxHost = (srv) => srv.indexOf(':') >= 0 ? '[' + srv + ']' : srv;
  const servers = nodes.map((n, i) => {
    const { user, srv, prt, name } = parseShareNode(n, i);
    if (n.startsWith('trojan://')) {
      return `trojan=${qxHost(srv)}:${prt}, password=${user}, over-tls=true, tls-host=${host}, obfs=wss, obfs-host=${host}, obfs-uri=${path}, tls-verification=true, tag=${name}`;
    }
    const tls = (getParam(n, 'security') || 'tls') === 'tls';
    return `vless=${qxHost(srv)}:${prt}, method=none, password=${user}, obfs=${tls ? 'wss' : 'ws'}, obfs-host=${host}, obfs-uri=${path}${tls ? ', tls-verification=true, tls13=true' : ''}, tag=${name}`;
  });
  const names = nodes.map((n, i) => {
    const h = n.indexOf('#');
    if (h < 0) return `节点${i + 1}`;
    try { return decodeURIComponent(n.slice(h + 1)) || `节点${i + 1}`; } catch (e) { return `节点${i + 1}`; }
  }).join(', ');
  return `[general]
network_check_url=http://www.gstatic.com/generate_204
server_check_url=http://www.gstatic.com/generate_204
dns_exclusion_list=*.cmpassport.com, *.qq.com, *.weibo.com, *.icloud.com
[dns]
server=223.5.5.5
server=119.29.29.29
[server_local]
${servers.join('\n')}
[policy]
static=🚀 节点选择, ${names}, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png
static=🌐 全球直连, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png
static=🐟 漏网之鱼, 🚀 节点选择, direct, img-url=https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Final.png
[filter_local]
geoip, cn, 🌐 全球直连
final, 🐟 漏网之鱼
`;
}

// ★ 测活总开关（见 DEFAULT_CONFIG.probeAlive / 面板「节点测活」）：关闭时所有测活函数直接返回 true（不剔除任何节点）
// 注意：由于 Cloudflare 运行时禁止 connect() 到 CF IP 段，对 CF 段 IP 的探测恒失败（抛
// "proxy request failed, cannot connect to the specified address"），故测活仅在「第三方中转（非 CF 段）」
// 场景有真实信息量；对 CF 段 IP 关闭测活 = 避免把最优来源整体判死。
async function probeAll(items,fn){
  const out=[];let idx=0;
  await Promise.all(Array.from({length:Math.min(4,items.length)},async()=>{while(idx<items.length){const i=idx++;try{out[i]=await fn(items[i],i);}catch{out[i]=false;}}}));
  return out;
}

// ProxyIP 可用性检测：TCP 连通测试（参考 TunnelBoard 测活思路，独立实现），2 秒超时
async function testProxyAlive(server,port,timeoutMs,enabled=false){
  if(!enabled || isCloudflareIP(server))return true;
  let conn;try{conn=await connectWithTimeout(server,port,timeoutMs||2000);return true;}catch{return false;}finally{closeSocket(conn);}
}
async function testRelayAlive(server,port,timeoutMs,enabled=false){return testProxyAlive(server,port,timeoutMs,enabled);}


// 域名可用性预检：DoH 解析首个 CF IP → TCP 测活，剔除死域名（NXDOMAIN / 解析到死 IP，客户端测速 -1 主因）。
// 活域名仍按域名形式下发（保留客户端动态 DNS 解析拿最优边缘的优势）；结果 10 分钟缓存，避免每次订阅重测
async function dohFirstCF(domain,io) {
  try {
    const res = await fetchTimeout('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=A', { headers: { accept: 'application/dns-json' } }, 4000, io);
    if (!res || !res.ok) return null;
    const j = await res.json();
    const ips = (j.Answer || []).filter(a => a.type === 1 && /^\d+\.\d+\.\d+\.\d+$/.test(a.data)).map(a => a.data);
    return ips.filter(isCloudflareIP)[0] || null;
  } catch (e) { return null; }
}
const DOMAIN_ALIVE_CACHE = { t: 0, list: null };
async function filterAliveDomains(domainText,cfg) {
  // 测活关闭：域名预检直接跳过，返回原文（原样下发，不剔除任何域名）
  if (!cfg.probeAlive) return String(domainText || '').split(/[\n,;]+/).map(s => s.trim().replace(/^\*\./, '')).filter(Boolean).join('\n');
  if (Date.now() - DOMAIN_ALIVE_CACHE.t < 10 * 60 * 1000 && DOMAIN_ALIVE_CACHE.list !== null && DOMAIN_ALIVE_CACHE.key===domainText) return DOMAIN_ALIVE_CACHE.list;
  const domains = String(domainText || '').split(/[\n,;]+/).map(s => s.trim().replace(/^\*\./, '')).filter(Boolean);
  // DoH 解析 + TCP 测活双重预检（10 分钟缓存）：解析不出 CF IP 或解析到非 CF 段的域名（源站已搬走）直接判死；
  // 解析出 CF IP 再做 TCP 测活，连接超时的死域名剔除——客户端测速 -1 主因
  // 并发受限（≤4）：DoH fetch + TCP 探测都算出网，避免撞 6 连接上限；排队不计入超时
  const checked = await probeAll(domains, async (d) => {
    const ip = await dohFirstCF(d,cfg._io);
    if (!ip || !isCloudflareIP(ip)) return { d, ok: false };
    return { d, ok: await testProxyAlive(ip,443,2000,cfg.probeAlive) };
  });
  const alive = checked.map((c, i) => (c && c.ok ? domains[i] : null)).filter(Boolean);
  DOMAIN_ALIVE_CACHE.t = Date.now();DOMAIN_ALIVE_CACHE.key=domainText;
  DOMAIN_ALIVE_CACHE.list = alive.join('\n');
  return DOMAIN_ALIVE_CACHE.list;
}

// bestcf 区域优选池拉取（内存缓存 10 分钟；并发拉 5 区域，解析 "IP:端口" 行）
const bestcfCache = { list: null, at: 0 };
async function fetchBestcfPool(io) {
  if (bestcfCache.list && Date.now() - bestcfCache.at < 10 * 60 * 1000) return bestcfCache.list;
  const out = [];
  const jobs = BESTCF_REGION_URLS.map(async (rp) => {
    try {
      const res = await fetchTimeout(rp.url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, 6000, io);
      if (!res || !res.ok) return;
      const text = await res.text();
      const got = [];
      for (const line of text.split(/[\r\n]+/)) {
        const m = line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?$/);
        if (m && got.length < rp.count) got.push({ ip: m[1], port: m[2] ? parseInt(m[2], 10) : 443, name: rp.label + '-' + String(got.length + 1).padStart(2, '0') });
      }
      got.forEach(g => out.push(g));
    } catch (e) {}
  });
  await Promise.all(jobs);
  bestcfCache.list = out;
  bestcfCache.at = Date.now();
  return out;
}

// 内置保底节点：CF 官方任播段 IP（实测 443 全部可达），固定 443 追加下发，
// 无论任何订阅模式都保证订阅内存在稳定可用节点（参考 TunnelBoard 内置优选思路）
function appendStableNodes(nodes, rc, cap) {
  if (nodes.length >= cap) return;
  const used = new Set();
  for (const n of nodes) {
    try { used.add(parseNodeServer(n).host); } catch (e) { /* 忽略 */ }
  }
  let si = 0;
  for (const ip of BUILTIN_STABLE_IPS) {
    if (nodes.length >= cap) break;
    if (used.has(ip)) continue;
    used.add(ip);
    si++;
    const nm = '内置·保底-' + String(si).padStart(2, '0');
    if (rc.enableVless) nodes.push(vlessNode(rc, ip, 443, nm));
    if (nodes.length >= cap) break;
    if (rc.enableTrojan) nodes.push(trojanNode(rc, ip, 443, nm));
    if (nodes.length >= cap) break;
    if (rc.enableXhttp) nodes.push(vlessNode(rc, ip, 443, nm, { type: 'xhttp' }));
  }
}

// 兜底入口节点（代码独立实现）：
// 兜底入口节点（代码独立实现）：
// 原生地址（当前访问域名）仅在面板「原生地址」开关（src.native）开启后追加——默认关闭不追加，
// 与「地址来源」面板控制保持一致；
// 内置地区反代（proxyip.*.cmliussss.net）不再自动下发为订阅节点
// （需要反代时请通过「出站代理」或「反代/落地 IP」填写自己的中继服务）
function appendFallbackNodes(nodes, rc, cap, colo) {
  if (nodes.length >= cap) return;
  const used = new Set();
  for (const n of nodes) {
    try { used.add(parseNodeServer(n).host); } catch (e) { /* 忽略 */ }
  }
  const pushNode = (server, name) => {
    if (nodes.length >= cap) return;
    if (used.has(server)) return;
    used.add(server);
    if (rc.enableVless) nodes.push(vlessNode(rc, server, 443, name));
    if (rc.enableTrojan) nodes.push(trojanNode(rc, server, 443, name));
    if (rc.enableXhttp) nodes.push(vlessNode(rc, server, 443, name, { type: 'xhttp' }));
  };
  // 原生地址：仅面板「原生地址」开关（src.native）开启时下发；默认关闭不下发
  if (rc.src && rc.src.native === true) {
    pushNode(rc.host, '原生地址');
  }
  // 内置地区反代（proxyip.*.cmliussss.net）不再自动下发（用户要求订阅中不出现内置反代节点）
}

// 根据 UA 或指定格式生成订阅
async function generateSubscription(cfg, requestUrl, format, ua, colo, env) {
  // 兜底：path 为空或为 "/" 时一律回退 UUID（兼容 KV 残留旧值；Worker WS/xhttp 代理仅在 panelPath=cfg.path 处理）
  if (!cfg.path || cfg.path === '/' || cfg.path === '') cfg.path = cfg.uuid;
  // 筛选含 IPv6 时刷新官方 v6 网段（ips-v6，6 小时缓存节流；失败沿用内置/上次成功段）
  const _ipT0 = (cfg.filter && cfg.filter.ipType) || [];
  if (_ipT0.includes('IPv6')) await refreshOfficialV6CIDRs(cfg._io);
  // 自定义域名部署（非 *.workers.dev）：Cloudflare 边缘实测明文 HTTP 端口（80/8080/8880/2052/2082/2086/2095）全部拒绝，
  // 自动禁用明文端口节点（等效 tlsOnly）；节点端口统一固定为源端口（通常 443）单端口下发（1.0.6 机制）。
  const hostOnly443 = !/\.workers\.dev$/i.test(new URL(requestUrl).hostname);
  const rc = Object.assign({}, cfg, { host: cfg.host || new URL(requestUrl).hostname });
  if (hostOnly443) { rc.tlsOnly = true; }
  const mode = (cfg.optimizer && cfg.optimizer.subMode) || '';
  // 订阅模式决定节点来源：
  //   ''（关闭，默认）→ 仅用内置默认优选池限量下发（不解析自定义订阅的优选节点）
  //   custom          → 使用「优选节点」框内地址（支持汇聚，可增删）
  //   random          → 由 buildNodes 直接随机生成，此处不解析
  let resolved = [];
  // 筛选含 IPv6 时查询 AAAA 记录并生成 IPv6 节点（默认双选 IPv4+IPv6 同样生效）；
  // 仅勾选 IPv6（单选）时随机生成/补足全部走 IPv6 专用段（参考 CFNext v1.0.5 可达性原则）
  const ipT = (cfg.filter && cfg.filter.ipType) || [];
  const wantV6 = ipT.includes('IPv6');
  const onlyV6 = ipT.length === 1 && ipT[0] === 'IPv6';
  const RAND_CIDRS = onlyV6 ? OFFICIAL_V6_CIDRS : (wantV6 ? [...REACHABLE_CIDRS, ...OFFICIAL_V6_CIDRS] : REACHABLE_CIDRS);
  // 内置 Cloudflare 优选 IP（实测可达的 Anycast 兜底池，始终随订阅下发；无明确地区，名称统一“优选IP-XX”）
  const builtinIPs = parseIPList(BUILTIN_PREFERRED_IPS.join('\n')).map(x => ({ ip: x.ip, port: x.port || 443, name: x.name || ('优选IP-' + String(BUILTIN_PREFERRED_IPS.indexOf(x) + 1).padStart(2, '0')) }));
  if (mode === 'custom') {
    // 自定义订阅（支持汇聚）：默认仅下发「优选节点」框内设置的节点（严格模式，不生成任何额外节点）；
    // 开启 subIncludeDefault 后追加内置优选 IP 池 + 默认 6 条地区源节点（含地区回退生成 + CF CIDR 补足），自定义与默认节点合并下发
    const incDefault = !!(cfg.optimizer && cfg.optimizer.subIncludeDefault);
    // 仅自定义模式（关闭追加）：输入框内容（域名/优选API/IP）原样下发，不做 CF 段过滤（用户自担可用性）；
    // 追加模式：CF 段过滤 + 地区回退生成，自定义与默认节点合并下发
    // 严格模式（仅自定义节点）：放大每源解析上限与总量上限（用户汇聚多源 100/源 时不被 40/源、300 总量截断，数量与填入地址对等）
    const strictMode = !incDefault;
    resolved = await resolvePreferredDomains(cfg.preferredDomains || '', strictMode ? 200 : 40, strictMode ? 2000 : 300, incDefault, incDefault, wantV6, cfg._io);
    if (incDefault) {
      // 默认域名池优先（CNAME 域名解析出可用 CF 优选 IP，保证可达性），自定义节点追加在后并去重
      const def = await resolvePreferredDomains(DEFAULT_PREFERRED_DOMAINS, 40, 240, false, true, wantV6, cfg._io);
      const seen = new Set(def.map(x => x.ip));
      resolved = [...def, ...resolved.filter(x => !seen.has(x.ip))];
      rc.preferredIPs = [...(rc.preferredIPs || []), ...builtinIPs];
      if (!rc.optimizer) rc.optimizer = {};
      // 追加模式下按接近上限的数量补足（fillCount 决定 buildNodes 的 CF CIDR 随机补足 IP 数，默认 0 时强制大量补足），满足"下发全部节点"预期
      rc.optimizer.fillCount = Math.min(parseInt(rc.optimizer.fillCount) || 0,800);
    }
  } else if (mode === '') {
    // 关闭（使用面板默认）：
    // 1) 原生地址（src.native）：工作器域名直接作为节点 server 下发（默认关闭）；
    // 2) 第三方优选域名直接作为节点 server 下发（客户端连接时动态 DNS 解析，拿到当前最优 CF 边缘 IP，可用性远高于静态 IP 快照）；
    // 3) 订阅时自动拉取最新优选 IP（HostMonit 仓库，10 分钟缓存）作为 IP 节点，失败回退内置池；
    // 4) CF CIDR 随机补足保证海量下发。
    // 地区筛选开启时仍按地区源解析成 IP（地区节点需确定地区标记；域名节点无地区标记不参与地区过滤）。
    const src = cfg.src || {};
    const useNative = src.native === true;            // 启用原生地址（工作器域名）
    const useDomain = src.prefDomain !== false;       // 启用优选域名（默认开）
    const useIp = src.prefIp !== false;               // 启用优选 IP（内置池 + 实时拉取，默认开）
    const useCustom = src.customPref === true;        // 启用自定义优选（面板「优选配置」列表，默认关闭）
    // 原生地址（工作器域名，IPv4 入口）：仅勾选 IPv6 时跳过，避免 v4 域名混入
    if (useNative && !onlyV6) {
      rc.preferredDomains = (rc.preferredDomains ? rc.preferredDomains + '\n' : '') + rc.host + '#原生地址';
    }
    if (!useCustom) rc.preferredIPs = [];
    const fl2 = cfg.filter || {};
    const regionSel = fl2.region;
    // 兼容字符串（旧配置）与数组（面板多选）：空 / 'all' / ['all'] 视为全部地区
    const regionAll = Array.isArray(regionSel) ? (regionSel.length === 0 || regionSel.includes('all')) : (!regionSel || regionSel === 'all');
    if (regionAll) {
      resolved = [];
      // 仅勾选 IPv6 时跳过 v4 优选域名（域名节点为 IPv4 入口，混入会占满 cap 并被 filterNodes 剔除，导致数量控制下发不足）
      if (useDomain && !onlyV6) {
        // 域名可用性预检：DoH 解析 + TCP 测活，死域名（NXDOMAIN/死 IP）不下发——客户端测速 -1 主因；
        // 活域名仍按域名形式下发，保留客户端动态 DNS 解析拿当前最优 CF 边缘的优势
        const aliveDomains = await filterAliveDomains(DEFAULT_PREFERRED_DOMAINS,cfg);
        if (aliveDomains) rc.preferredDomains = (rc.preferredDomains ? rc.preferredDomains + '\n' : '') + aliveDomains;
      }
      // 仅勾选 IPv6 时跳过 IPv4 来源（fresh/地区池/内置池均为 v4，筛选后会被剔除，避免无谓解析与 CPU 开销）
      if (useIp && !onlyV6) {
        const fresh = await fetchLatestPreferredIPs(150,cfg._io);
        if (fresh && fresh.length) rc.preferredIPs = [...(rc.preferredIPs || []), ...fresh];
        // v1.0.5 修复：并入 bestcf 地区优选池（社区维护的可达中转 IP，可用率高，trusted 标记放行）作为默认优选 IP 来源之一
        try {
          const regionPool = await resolvePreferredDomains(DEFAULT_REGION_POOLS, 100, 600, true, true, false, cfg._io);
          if (regionPool && regionPool.length) rc.preferredIPs = [...(rc.preferredIPs || []), ...regionPool];
        } catch (e) { /* bestcf 池拉取失败不影响其它来源 */ }
      }
      // IPv6 节点来源：筛选含 IPv6 时解析默认域名池 AAAA 记录生成 v6 IP 节点（仅追加，不影响 v4 链路）；
      // 仅勾选 IPv6 时并入官方域名 AAAA（增加真实可达 v6 数量），并关闭 CIDR 随机补足——
      // 随机生成的任播段 v6 地址并非 CF 实际部署 IP，实测全部 -1，宁可少而真实
      if (wantV6 && useDomain) {
        try {
          const v6src = DEFAULT_PREFERRED_DOMAINS + (onlyV6 ? '\n' + BUILTIN_OFFICIAL_DOMAINS.join('\n') : '');
          const v6dom = await resolvePreferredDomains(v6src, 40, onlyV6 ? 800 : 240, false, true, true, cfg._io);
          if (v6dom && v6dom.length) rc.preferredIPs = [...(rc.preferredIPs || []), ...v6dom];
        } catch (e) { /* AAAA 解析失败不影响其它来源 */ }
      }
    } else if (useDomain) {
      resolved = await resolvePreferredDomains(DEFAULT_PREFERRED_DOMAINS, 100, 300, false, true, wantV6, cfg._io);
    }
    // 内置实测池（IPv4）：单选 IPv6 时全量转 IPv4-embedded IPv6（2606:4700::<hex>，与对应 IPv4 路由到同一 CF 边缘，下发即用）；
    // 混合（IPv4+IPv6 同选）时全局下发——内置池全量保持 IPv4 且全量转 embedded IPv6，两侧都不削减
    if (useIp) {
      if (onlyV6) {
        const embedded = builtinIPs.map(b => ({ ip: ipv4ToEmbeddedV6(b.ip), port: b.port || 443, name: b.name })).filter(b => b.ip);
        rc.preferredIPs = [...(rc.preferredIPs || []), ...embedded];
      } else if (wantV6) {
        const embedded = builtinIPs.map(b => ({ ip: ipv4ToEmbeddedV6(b.ip), port: b.port || 443, name: b.name })).filter(b => b.ip);
        // 【优化 2026-09-25】同 IPv4 分支：内置 CF 实测池提到第三方中转池（relay 标记）之前占位
        const _tail6 = (rc.preferredIPs || []).filter(x => x && x.relay === true);
        const _head6 = (rc.preferredIPs || []).filter(x => !(x && x.relay === true));
        rc.preferredIPs = [..._head6, ...builtinIPs, ...embedded, ..._tail6];
      } else {
        // 【优化 2026-09-25】内置 CF 实测池提到第三方中转池之前占位。
        // 依据：cap 是先到先占（buildNodes 的 push 按插入顺序截断）。原顺序把 builtinIPs 追加在
        // bestcf 地区中转池（relay 标记）之后 → 中转池先把名额吃满，内置池常被挤出 cap 之外。
        // 实测（客户端侧 TCP+TLS 握手）：内置池 283/300 = 94%（前 20 条 100%），中转池仅约 70%。
        const _tail = (rc.preferredIPs || []).filter(x => x && x.relay === true);
        const _head = (rc.preferredIPs || []).filter(x => !(x && x.relay === true));
        rc.preferredIPs = [..._head, ...builtinIPs, ..._tail];
      }
    }
    // 地址来源全部关闭时兜底内置优选池，保证订阅永不为空（客户端不会收到「无效订阅」）；单选 IPv6 时同样转 embedded
    if (!useNative && !useDomain && !useIp && !useCustom) {
      if (onlyV6) {
        const embedded = builtinIPs.map(b => ({ ip: ipv4ToEmbeddedV6(b.ip), port: b.port || 443, name: b.name })).filter(b => b.ip);
        rc.preferredIPs = [...(rc.preferredIPs || []), ...embedded];
      } else {
        rc.preferredIPs = [...(rc.preferredIPs || []), ...builtinIPs];
      }
    }
    // 仅勾选 IPv6（单选）时清掉各来源混入的 IPv4（域名 AAAA 解析的 v4 与用户自定义列表中的 v4 一并剔除，
    // 避免 filterNodes 过滤空集后放宽回退全 v4；参考 CFNext v1.0.5 同款处理）
    if (onlyV6 && rc.preferredIPs) rc.preferredIPs = rc.preferredIPs.filter(x => String(x.ip).indexOf(':') >= 0);
    if (!rc.optimizer) rc.optimizer = {};
    // 单选 IPv6 时内置实测池已全量转 embedded IPv6（真实可达），无需 CIDR 随机补足（随机 v6 不可达会拖低可用率）；
    // 纯 IPv4 / 混合保留少量随机补足供海量下发
    rc.optimizer = {...rc.optimizer,fillCount:onlyV6 ? 0 : Math.min(parseInt(rc.optimizer.fillCount)||0,800)};
    // 连通率提升（纯排序，不删节点）：实测存活率最高的 20 条大站任播 IP（BUILTIN_STABLE_IPS）排到优选池最前——
    // 客户端默认选第一个可用节点，头部放最稳 IP = 用户优先踩到高存活率节点；其它来源顺序与数量不变（appendStableNodes 自带 used 去重不会重复）
    if (rc.preferredIPs && rc.preferredIPs.length) {
      const stableNodes = BUILTIN_STABLE_IPS.map((ip, i) => ({ ip, port: 443, name: '优选IP-S' + String(i + 1).padStart(2, '0') }));
      const stableSet = new Set(stableNodes.map(n => n.ip));
      rc.preferredIPs = [...stableNodes, ...rc.preferredIPs.filter(x => !stableSet.has(x.ip))];
    }
  }
  // 去重下发：读取上次已下发 IP（KV issued），所有模式均生效（随机补足 / 随机优选 / 自定义解析）
  const skipSet = (cfg._skipIssued && cfg._skipIssued.size) ? cfg._skipIssued : null;
  if (resolved.length) {
    // 新 IP 优先排前（供客户端优先连接），已下发过的 IP 紧随其后作为数量补齐——
    // 采用 [...unissued, ...previouslyIssued] 策略，节点总量恒定，不再因去重塌陷
    let fresh = resolved;
    if (skipSet) {
      const unissued = resolved.filter(x => !skipSet.has(x.ip));
      const previouslyIssued = resolved.filter(x => skipSet.has(x.ip));
      fresh = [...unissued, ...previouslyIssued];
    }
    // 统一名称：域名池/数据源自动解析且无法确定地区的节点（"域名.xx-NN" 格式）改为“优选域名-XX”，避免长域名占据节点名；
    // 能确定地区的（如优选 API 源 /HK/ → “香港-XX”）、用户自定义名称（如 JP-A-147）与面板手动填写的名称保留不变
    const nameBase = (rc.preferredIPs || []).length;
    fresh = fresh.map((x, i) => (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}-\d+$/.test(x.name || '')) ? Object.assign({}, x, { name: '优选域名-' + String(nameBase + i + 1).padStart(2, '0') }) : x);
    rc.preferredIPs = [...(rc.preferredIPs || []), ...fresh];
  }
  // 仅勾选 IPv6 时：resolved（地区筛选解析）在首次过滤之后才并入，此处二次过滤保证纯 v6（数量控制下不被 v4 挤占）
  if (onlyV6 && rc.preferredIPs) rc.preferredIPs = rc.preferredIPs.filter(x => String(x.ip).indexOf(':') >= 0);
  ua = (ua || '').toLowerCase();
  const forced = (format || '').toLowerCase();
  // 节点数上限（按 Workers / Pages 免费额度 10ms CPU 硬限调整）：
  //   - 纯行格式（v2ray 通用链接）拼接近乎零成本 → 800 上限，满足大量择优；
  //   - 结构化格式（Clash/Singbox/Surge/Loon/QuanX）模板生成成本较高，
  //     为保免费版稳定（含网络/KV/解析开销）收紧到 300，避免 CPU 超限导致订阅 5xx；
  //   - 自定义订阅开启「追加内置及默认节点」时：轻量格式放宽到 800，结构化格式放宽到 300。
  const isHeavy = ['clash', 'singbox', 'sing-box', 'surge', 'surfboard', 'loon', 'quanx', 'quantumultx'].includes(forced) || /clash|singbox|sing-box|surge|surfboard|loon|quantumult/.test(ua);
  let cap = isHeavy ? 300 : 800;
  if(cfg.nodeLimit)cap=Math.min(cap,cfg.nodeLimitCount || 300);
  // 配额安全自动调节：当日用量偏高时由路由层注入 _quotaCap，此处做最终收紧（永远不放大）
  if (cfg._quotaCap) cap = Math.min(cap, cfg._quotaCap);
  // 随机优选节点无地区标记，随机模式下忽略地区筛选（ipType/isp 仍生效）
  const fl = (mode === 'random') ? Object.assign({}, cfg.filter, { region: 'all' }) : cfg.filter;
  // 连通率优化：仅默认模式（mode===''）对最终优选 IP 池（内置静态池 + HostMonit 实时池 + bestcf 中转池）做 TCP 测活（10 分钟缓存），
  // 剔除不可达 IP（静态快照与中转池中大量 IP 已失效，客户端测速 -1 主因）；
  // 自定义模式（严格/追加）节点由用户自定（自建落地端口往往非 443，TCP 测活会误删），整体跳过测活剔除；
  // 默认模式剔除数量由 fillCount 自动补足（补足路径同样已测活），下发总量保持不变
  // 二次测活移除（对齐 1.0.6）：默认模式不再对优选 IP 池做 TCP 测活剔除——Worker 边缘连通性 ≠ 客户端连通性，
  // 测活误杀导致可用节点少、订阅生成慢；全量下发由客户端自行择优（fillCount 补足块内的小范围测活仍保留）
  let nodes = filterNodes(await buildNodes(rc, cap, skipSet), fl, rc._regionByEndpoint);
  // 兜底入口节点：自定义订阅严格模式（仅下发框内节点）不追加，其余模式追加原生地址与地区反代入口；
  // 仅勾选 IPv6 时跳过（原生地址/反代均为 IPv4 域名，混入会破坏「只下发 IPv6」语义）
  const strictCustom = (mode === 'custom' && !(cfg.optimizer && cfg.optimizer.subIncludeDefault));
  if (!strictCustom && !onlyV6) appendFallbackNodes(nodes, rc, cap, colo);
  // 内置保底节点：无论任何模式（含自定义订阅严格模式）始终追加 20 个实测可用的 CF 官方任播段 IP（443），
  // 保证订阅内始终有稳定可用节点（参考 TunnelBoard 内置优选思路）；仅勾选 IPv6 时跳过（保底池为 IPv4）
  // 内置保底节点：严格自定义模式（仅自定义节点）且已有自定义节点时跳过——用户自担可用性，不混入「内置·保底-X」；
  // 严格模式解析结果为空时仍追加保底，保证订阅永不为空（客户端不会收到「无效订阅」）
  if (!onlyV6 && !(strictCustom && nodes.length > 0)) appendStableNodes(nodes, rc, cap);
  // 下发控制开启时按 cap 补足（全局生效，与轮询状态无关）：优先用 bestcf 区域优选池（实时测速过的优质 IP）补齐，
  // 不足再用 ProxyIP 域名兜底（TCP 测活通过才下发），最后才回退 CF CIDR 随机生成——
  // 避免下发大量「延迟 -1」的随机 IP 死节点（参考 TunnelBoard：订阅场景不生成随机 IP）
  // 节点数量控制补足：严格自定义模式（仅自定义节点）跳过——不追加 bestcf 池 / ProxyIP 反代 / CIDR 随机 IP 等任何内置节点；
  // 内置节点仅在「追加内置优选池与默认地区源」开启时作为追加下发
  if (cfg.nodeLimit && mode && !strictCustom && nodes.length < cap) {
    const need = cap - nodes.length;
    // 该补足块仅服务「自定义订阅（追加内置）/ 随机优选」两种模式：
    // 优先用 bestcf 区域优选池（实时测速过的优质 IP）补齐，不足再回退 CF CIDR 随机补足——
    // 避免纯随机 CIDR 灌入大量「延迟 -1」死节点；两模式均不进行测活（按 1.0.6 机制）
    const seen = new Set();
    for (const n of nodes) { try { seen.add(parseNodeServer(n).host); } catch (e) {} }
    const pushFill = (ip, port, name) => {
      if (nodes.length >= cap) return;
      if (seen.has(ip)) return;
      seen.add(ip);
      if (rc.enableVless) nodes.push(vlessNode(rc, ip, port || 443, name));
      if (rc.enableTrojan && nodes.length < cap) nodes.push(trojanNode(rc, ip, port || 443, name));
      if (rc.enableXhttp && nodes.length < cap) nodes.push(vlessNode(rc, ip, port || 443, name, {type:'xhttp'}));
    };
    let fi = 0;
    try {
      const pool = await fetchBestcfPool(cfg._io);
      const fresh = skipSet ? pool.filter(p => !skipSet.has(p.ip)) : pool;
      const ordered = fresh.length >= need ? fresh : pool;
      for (const p of ordered) { pushFill(p.ip, p.port, p.name || ('优选IP-' + String(p.port))); if (nodes.length >= cap) break; }
    } catch (e) {}
    if (nodes.length < cap) {
      const left = cap - nodes.length;
      const v6c = OFFICIAL_V6_CIDRS;
      const fillCidrs = onlyV6 ? v6c : (wantV6 ? [...REACHABLE_CIDRS, ...v6c] : REACHABLE_CIDRS);
      const pool = randomIPsFromCidrs(fillCidrs, left * 3);
      const freshP = skipSet ? pool.filter(ip => !skipSet.has(ip)) : pool;
      const fillIPs = (freshP.length >= left) ? freshP : pool;
      for (const ip of fillIPs) {
        if (nodes.length >= cap) break;
        fi++;
        pushFill(ip, 443, '随机补足-' + String(fi).padStart(3, '0'));
      }
    }
  }
  // 严格封顶：多协议膨胀可能越过 cap 一个 IP（3 条），统一截断到上限；节点数量控制开启时同样按设定值精确截断
  if (nodes.length > cap) nodes.length = cap;
  // 节点命名：按来源国家码/机房码追加地点后缀；只有国家码时不显示城市。
  // 放在所有追加/截断之后，避免影响 filterNodes 的地区标记判定（它跑在改名之前）。
  // 关闭开关：环境变量 RELAY_EXIT_PROBE=0（沿用旧开关名，现在表示「不写地点后缀」）。
  if (!cfg._noExitProbe) {
    const _regionMap = rc._regionByEndpoint;
    if (_regionMap && _regionMap.size) {
      for (let i = 0; i < nodes.length; i++) {
        if (nodes[i].indexOf('#') <= 0) continue;
        let _endpoint;
        try { _endpoint = parseNodeServer(nodes[i]); } catch (e) { continue; }
        const _meta = _regionMap.get(_endpoint.host+':'+_endpoint.port);
        if (!_meta) continue;
        const _sfx = geoNameSuffix(_meta.colo, _meta.cc);
        if (_sfx) nodes[i] += uriFragName(_sfx);
      }
    }
  }
  nodes=nodes.slice(0,cap);
  let type, body;
  if (forced === 'clash') { type = 'text/yaml'; body = generateClash(rc, nodes); }
  else if (forced === 'singbox' || forced === 'sing-box') { type = 'application/json'; body = generateSingbox(rc, nodes); }
  else if (forced === 'surge') { type = 'text/plain'; body = generateSurge(rc, nodes); }
  else if (forced === 'surfboard') { type = 'text/plain'; body = generateSurfboard(rc, nodes); }
  else if (forced === 'loon') { type = 'text/plain'; body = generateLoon(rc, nodes); }
  else if (forced === 'quanx' || forced === 'quantumultx') { type = 'text/plain'; body = generateQuanX(rc, nodes); }
  else if (forced === 'plain' || forced === 'raw') { type = 'text/plain'; body = nodes.join('\n'); }
  else if (forced === 'v2ray' || forced === 'v2rayn' || forced === 'shadowrocket' || forced === 'nekoray' || forced === 'stash') {
    // 明文下发（与 1.0.6 一致）：base64 订阅在 AsteriskNG / v2rayNG 中按系统编码（GBK）解码，
    // 中文节点名（UTF-8）会被误读成乱码（如 美国 → 缇庡浗）；明文按响应 charset=utf-8 读取则正常
    type = 'text/plain'; body = nodes.join('\n');
  }
  // UA 自动识别
  else if (ua.includes('clash') || ua.includes('stash')) { type = 'text/yaml'; body = generateClash(rc, nodes); }
  else if (ua.includes('sing-box')) { type = 'application/json'; body = generateSingbox(rc, nodes); }
  else if (ua.includes('surge')) { type = 'text/plain'; body = generateSurge(rc, nodes); }
  else if (ua.includes('surfboard')) { type = 'text/plain'; body = generateSurfboard(rc, nodes); }
  else if (ua.includes('loon')) { type = 'text/plain'; body = generateLoon(rc, nodes); }
  else if (ua.includes('quantumult')) { type = 'text/plain'; body = generateQuanX(rc, nodes); }
  // 默认（v2rayN / Shadowrocket / 未知客户端）：返回 base64 编码订阅（V2rayN 标准格式）
  else { type = 'text/plain'; body = nodes.join('\n'); }   // 明文（同 1.0.6，避免客户端按 GBK 解码 base64 导致中文名称乱码）
  return { type, body };
}

// ---------------------------------------------------------------------------
// 管理面板 HTML（单页应用）
// ---------------------------------------------------------------------------
// 两个页面共用主题控制器：首次渲染前读取偏好，未选择时跟随系统。
const THEME_SCRIPT = String.raw`<script>
(function(){
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  var mode = 'auto';
  function readMode(){
    var saved;
    try { saved = localStorage.getItem('tp_theme'); } catch(e) {}
    return saved === 'light' || saved === 'dark' ? saved : 'auto';
  }
  function apply(){
    var resolved = mode === 'auto' ? (media && media.matches ? 'dark' : 'light') : mode;
    document.documentElement.setAttribute('data-theme', resolved);
    document.documentElement.style.colorScheme = resolved;
    window.dispatchEvent(new Event('cf-theme-change'));
  }
  mode = readMode();
  window.cfTheme = {
    get: function(){ return mode; },
    apply: apply,
    set: function(value){
      mode = value === 'light' || value === 'dark' ? value : 'auto';
      try { localStorage.setItem('tp_theme', mode); } catch(e) {}
      apply();
    }
  };
  if (media) {
    var onSystemChange = function(){ if (mode === 'auto') apply(); };
    if (media.addEventListener) media.addEventListener('change', onSystemChange);
    else if (media.addListener) media.addListener(onSystemChange);
  }
  window.addEventListener('storage', function(event){
    if (event.key === 'tp_theme' || event.key === null) { mode = readMode(); apply(); }
  });
  apply();
})();
</script>`;

const PANEL_HTML = String.raw`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${THEME_SCRIPT}
<title>CFNext · Cloudflare 隧道面板</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect x='3' y='3' width='18' height='18' rx='5' fill='%23f6821f'/%3E%3Cpath d='M8 15V9l8 6V9' stroke='%230d131b' stroke-width='2' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0f14;--bg2:#0f141b;--card:#131a23;--card2:#182130;--border:#243041;
  --text:#e8eef6;--dim:#8fa3ba;--faint:#5c6f86;
  --accent:#f6821f;--accent2:#ff9a3d;--accent-dim:rgba(246,130,31,.14);
  --ok:#34c98e;--ok-dim:rgba(52,201,142,.13);--err:#ff5c5c;--err-dim:rgba(255,92,92,.13);--warn:#ffb454;
  --sb-bg:#0d131b;--sb-text:#9fb0c5;--sb-dim:#5c6f86;--sb-border:#1c2737;
  --sb-active-bg:rgba(246,130,31,.13);--sb-active-text:#ffa14d;--sb-active-bar:#f6821f;
  --shadow:0 10px 30px rgba(0,0,0,.28);
}
[data-theme="light"]{
  --bg:#f3f5f9;--bg2:#e9edf3;--card:#ffffff;--card2:#f6f8fb;--border:#dde4ee;
  --text:#1b2634;--dim:#5d6b7d;--faint:#93a1b3;
  --accent:#e8720e;--accent2:#f6821f;--accent-dim:rgba(232,114,14,.10);
  --ok:#1f9d6a;--ok-dim:rgba(31,157,106,.12);--err:#d94848;--err-dim:rgba(217,72,72,.10);--warn:#c07c1e;
  --sb-bg:#ffffff;--sb-text:#5d6b7d;--sb-dim:#a2aec0;--sb-border:#e7ebf2;
  --sb-active-bg:rgba(232,114,14,.09);--sb-active-text:#c96408;--sb-active-bar:#e8720e;
  --shadow:0 10px 28px rgba(30,45,70,.10);
}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:"PingFang SC","Microsoft YaHei","Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.55}
.app{display:flex;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* ===== 侧边栏 ===== */
.sidebar{width:236px;flex:0 0 236px;background:var(--sb-bg);border-right:1px solid var(--sb-border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;z-index:50;transition:background .25s,border-color .25s}
.brand{display:flex;align-items:center;gap:10px;padding:18px 18px 14px}
.mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;flex:0 0 34px;box-shadow:0 4px 12px var(--accent-dim)}
.mark svg{width:18px;height:18px}
.mark path{stroke:#0d131b}
.brand .bt{display:flex;flex-direction:column;line-height:1.2}
.brand .bt b{font-size:15px;letter-spacing:.3px;color:var(--text)}
.brand .bt span{font-size:11px;color:var(--sb-dim)}
.nav{flex:1;padding:6px 10px 12px;overflow-y:auto}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:2px 0;border-radius:8px;color:var(--sb-text);cursor:pointer;border:none;background:transparent;width:100%;text-align:left;font-size:13.5px;position:relative;transition:background .15s,color .15s}
.nav-item svg{width:17px;height:17px;flex:0 0 17px;stroke:currentColor}
.nav-item:hover{background:var(--sb-active-bg);color:var(--sb-active-text)}
.nav-item.on{background:var(--sb-active-bg);color:var(--sb-active-text);font-weight:600}
.nav-item.on::before{content:"";position:absolute;left:-10px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--sb-active-bar)}
.side-foot{padding:12px 18px;border-top:1px solid var(--sb-border);display:flex;align-items:center;justify-content:space-between;font-size:11.5px;color:var(--sb-dim)}
.ver-chip{font-family:ui-monospace,Consolas,monospace;background:var(--accent-dim);color:var(--sb-active-text);padding:2px 8px;border-radius:6px;font-size:11px;border:1px solid transparent;cursor:pointer;transition:border-color .15s,color .15s,background .15s}
.ver-chip:hover{color:var(--accent);border-color:var(--accent)}
.ver-chip.has-update{color:var(--accent);background:var(--accent-dim);border-color:var(--accent)}
.ver-chip.checking{opacity:.7;pointer-events:none}

/* ===== 主区 ===== */
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:14px;padding:14px 26px;border-bottom:1px solid var(--border);background:var(--bg);position:sticky;top:0;z-index:40}
.topbar h1{font-size:17px;font-weight:600;flex:1;min-width:0}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;padding:4px 10px;border-radius:20px;background:var(--ok-dim);color:var(--ok);white-space:nowrap}
.pill.off{background:var(--err-dim);color:var(--err)}
.pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.icon-btn{width:34px;height:34px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);cursor:pointer;display:flex;align-items:center;justify-content:center;flex:0 0 34px}
.icon-btn:hover{border-color:var(--accent);color:var(--accent)}
.icon-btn svg{width:16px;height:16px;stroke:currentColor}
.hamb{display:none}
.wdwarn{display:none;background:rgba(59,130,246,.10);border-bottom:1px solid rgba(59,130,246,.35);color:var(--accent2);padding:9px 26px;font-size:12.5px;line-height:1.6;text-align:center}
[data-theme="light"] .wdwarn{color:var(--accent);background:rgba(29,95,168,.06);border-bottom-color:rgba(29,95,168,.35)}

.content{padding:22px 26px 96px;max-width:1180px;width:100%;margin:0 auto}
.view{display:none}
.view.on{display:block;animation:fade .18s ease}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.view-head{margin-bottom:16px}
.view-head h2{font-size:20px;font-weight:700}
.view-head p{color:var(--dim);font-size:13px;margin-top:4px}

/* ===== 卡片 ===== */
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.filter-region{display:flex;align-items:center;gap:14px;padding:2px 0 14px;border-bottom:1px solid var(--border);margin-bottom:14px;flex-wrap:wrap}
.filter-region-label{font-size:13px;font-weight:600;white-space:nowrap}
.filter-row{display:flex;flex-wrap:wrap}
.filter-group{flex:0 1 auto;min-width:180px;padding:0 14px;border-left:1px solid var(--border)}
.filter-group:first-child{border-left:none;padding-left:0}
.filter-group-title{font-size:12px;font-weight:600;color:var(--dim);margin-bottom:9px;letter-spacing:.3px}
.pills{display:flex;flex-wrap:wrap;gap:8px}
.pills.nowrap{flex-wrap:nowrap;white-space:nowrap}
.pills.nowrap .spill span{padding:5px 10px;font-size:12px}
.spill input{position:absolute;opacity:0;pointer-events:none}
.spill span{display:inline-block;padding:5px 14px;border:1px solid var(--border);border-radius:999px;font-size:12.5px;color:var(--dim);cursor:pointer;background:var(--card);transition:border-color .15s,color .15s,background .15s;user-select:none;line-height:1.5}
.spill:hover span{border-color:var(--accent);color:var(--accent)}
.spill input:checked + span{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;border-radius:999px}.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:16px}
.card h3{font-size:14px;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card h3 .tick{width:3px;height:14px;border-radius:2px;background:var(--accent)}
.card .sub{font-size:12px;color:var(--dim);font-weight:400;margin-left:auto}
.kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px dashed var(--border);font-size:13px}
.kv:last-child{border-bottom:none}
.kv .k{color:var(--dim);white-space:nowrap}
.kv .v{text-align:right;word-break:break-all;font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.kv .v.ok{color:var(--ok)}.kv .v.bad{color:var(--err)}.kv .v.warn{color:var(--warn)}

/* ===== 表单 ===== */
.field{margin-bottom:12px}
.field>label{display:block;font-size:12.5px;color:var(--dim);margin-bottom:6px;font-weight:500}
input[type=text],input[type=password],input[type=number],select,textarea{
  width:100%;background:var(--card2);border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:8px 11px;font-size:13.5px;outline:none;transition:border-color .15s,box-shadow .15s;
  font-family:inherit;
}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
textarea{resize:vertical;line-height:1.5;font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
select{cursor:pointer;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%238fa3ba' stroke-width='1.6' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:30px}
[data-theme="light"] select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%235d6b7d' stroke-width='1.6' fill='none' stroke-linecap='round'/%3E%3C/svg%3E")}
input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;cursor:pointer}
.hint{font-size:12px;color:var(--dim);margin-top:6px;line-height:1.6}
.inrow{display:flex;gap:8px;align-items:flex-start}
.inrow>div{flex:1}
.inrow .btn{margin-top:1px;white-space:nowrap}
.checkline{display:flex;align-items:center;gap:20px;padding:5px 0;font-size:13px;cursor:pointer}
.checkline input{margin:0;flex:0 0 auto;vertical-align:middle}
.checkline span{line-height:1.5}
.proto-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13.5px}
.proto-row:last-child{border-bottom:none}

/* 开关 */
.switch{position:relative;display:inline-block;width:40px;height:22px;flex:0 0 40px}
.switch input{opacity:0;width:0;height:0}
.sl{position:absolute;inset:0;background:var(--border);border-radius:22px;cursor:pointer;transition:background .18s}
.sl::before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .18s}
.switch input:checked+.sl{background:var(--accent)}
.switch input:checked+.sl::before{transform:translateX(18px)}

/* 按钮 */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--border);background:var(--card2);color:var(--text);border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer;transition:border-color .15s,background .15s,transform .05s;font-family:inherit;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.55;cursor:not-allowed}
.btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#201308;font-weight:600}
.btn.primary:hover{filter:brightness(1.06);color:#201308}
.btn.danger{background:var(--err-dim);border-color:transparent;color:var(--err)}
.btn.danger:hover{border-color:var(--err)}
.btn.sm{padding:4px 10px;font-size:12px;border-radius:6px}
.btn .dirty-dot{display:none;width:6px;height:6px;border-radius:50%;background:var(--warn)}
.btn.dirty .dirty-dot{display:inline-block}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.row .grow{flex:1;min-width:140px}

/* 表格 */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{text-align:left;padding:9px 10px;font-size:13px;border-bottom:1px solid var(--border);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
th{color:var(--dim);font-weight:500;font-size:12px;background:var(--card2)}
td .ip{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11.5px}
.badge.g{background:var(--ok-dim);color:var(--ok)}
.badge.r{background:var(--err-dim);color:var(--err)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}

/* 消息与提示 */
.msg{display:none;margin-top:12px;padding:9px 12px;border-radius:8px;font-size:12.5px;line-height:1.6}
.msg.show{display:block}
.msg.ok{background:var(--ok-dim);color:var(--ok)}
.msg.err{background:var(--err-dim);color:var(--err)}
.msg.info{background:var(--accent-dim);color:var(--accent2)}
[data-theme="light"] .msg.info{color:#c96408}
pre.code{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;font-size:11.5px;line-height:1.55;font-family:ui-monospace,Consolas,monospace;overflow:auto;max-height:260px;white-space:pre-wrap;word-break:break-all;color:var(--dim)}

/* 悬浮操作栏 */
.fbar{position:fixed;right:22px;bottom:22px;display:flex;gap:10px;z-index:60;align-items:center}
.fbar .btn{box-shadow:var(--shadow)}
.saved-at{font-size:11.5px;color:var(--faint);background:var(--card);border:1px solid var(--border);border-radius:8px;padding:5px 10px;box-shadow:var(--shadow);white-space:nowrap}
.toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(80px);background:var(--card);border:1px solid var(--border);color:var(--text);padding:10px 20px;border-radius:10px;font-size:13px;opacity:0;transition:all .25s;z-index:100;box-shadow:var(--shadow);pointer-events:none;max-width:86vw}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:var(--ok);color:var(--ok)}
.toast.err{border-color:var(--err);color:var(--err)}
.toast.warn{border-color:var(--warn);color:var(--warn)}

/* 分区 */
.sec-title{font-size:12px;color:var(--faint);letter-spacing:1px;margin:20px 0 10px;font-weight:600}
.danger-zone{border:1px solid var(--err);border-radius:12px;padding:16px;background:var(--err-dim)}
.qrbox{display:flex;justify-content:center;padding:12px 0 4px}
.qrbox img{width:168px;height:168px;image-rendering:pixelated;border-radius:8px}
.note-box{background:var(--card2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:12px 14px;font-size:12.5px;color:var(--dim);line-height:1.7;margin-bottom:12px}
.steps{list-style:none;counter-reset:st}
.steps li{counter-increment:st;position:relative;padding:0 0 14px 34px;font-size:13px;color:var(--dim)}
.steps li::before{content:counter(st);position:absolute;left:0;top:0;width:22px;height:22px;border-radius:50%;background:var(--accent-dim);color:var(--accent2);display:flex;align-items:center;justify-content:center;font-size:11.5px;font-weight:700}
[data-theme="light"] .steps li::before{color:#c96408}
.steps li b{color:var(--text)}

/* ===== 响应式 ===== */
@media (min-width:1100px){
  /* 右侧避让右下角浮动保存栏（尚未保存/重置/保存全部），避免遮挡筛选勾选项 */
  .filter-grid{padding-right:200px}
}
@media (max-width:960px){
  .sidebar{position:fixed;left:0;top:0;transform:translateX(-100%);transition:transform .22s ease;box-shadow:var(--shadow)}
  .sidebar.open{transform:translateX(0)}
  .hamb{display:flex}
  .content{padding:16px 16px 96px}
  .topbar{padding:12px 16px}
  .grid2,.grid3{grid-template-columns:1fr}
}
@media (max-width:560px){
  th,td{padding:8px 8px}
}
</style>
</head>
<body>
<div class="app">

<!-- ===== 侧边栏 ===== -->
<aside class="sidebar" id="sidebar">
  <div class="brand">
    <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h4l3-7 4 14 3-7h2"/></svg></div>
    <div class="bt"><b>CFNext</b><span>Cloudflare 隧道面板</span></div>
  </div>
  <nav class="nav" id="nav"></nav>
  <div class="side-foot">
    <span>部署版本</span>
    <span class="ver-chip" id="sideVer" title="点击检测更新" onclick="checkUpdate()">v—</span>
  </div>
</aside>

<!-- ===== 主区 ===== -->
<div class="main">
  <div class="topbar">
    <button class="icon-btn hamb" id="hamb" title="菜单"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
    <h1 id="pageTitle">仪表盘</h1>
    <span class="pill" id="connPill"><span class="dot"></span><span id="connText">连接中</span></span>
    <button class="icon-btn" id="themeBtn" title="主题：跟随系统；点击切换为日间" aria-label="主题：跟随系统；点击切换为日间"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path id="themeIcon" d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg></button>
  </div>
  <div class="wdwarn" id="wdwarn">当前运行在 *.workers.dev 域名上：订阅与节点下发功能正常；若遇连接不稳或访问受限，建议在 Cloudflare 面板绑定自定义域名后使用。</div>

  <div class="content" id="content">
    <!-- ===== 视图：仪表盘 ===== -->
    <section class="view" data-view="dashboard">
      <div class="view-head"><h2>仪表盘</h2><p>快速开始、订阅管理、配额速览与运行状态</p></div>
      <div class="card">
        <h3><span class="tick"></span>快速开始</h3>
        <ol class="steps">
          <li><b>部署即用</b>：绑定域名后客户端订阅即可获得海量节点（内置 300 条优选 IP 与地区域名源），默认已配好大陆直连分流（大陆应用、微软、苹果直连，国外服务走代理）。</li>
          <li><b>调优节点</b>：在「优选配置」在线测速，把最优 IP 加入优选列表（自定义订阅模式内置常用订阅源，可自行增删，可追加内置优选池与默认节点）。</li>
          <li><b>保障额度</b>：在「配额安全」开启用量监控与自动调节，辅助观察免费额度用量（需在面板设置中配置 Cloudflare 账户 ID 与 API 令牌）。</li>
        </ol>
      </div>
      <div class="card">
        <h3><span class="tick"></span>订阅地址</h3>
        <div class="row" style="margin-bottom:12px">
          <div class="field grow" style="margin:0"><label>订阅格式</label>
            <select id="subFmt">
              <option value="auto">自动识别</option>
              <option value="clash">Clash / Mihomo</option>
              <option value="singbox">Sing-box</option>
              <option value="surge">Surge</option>
              <option value="surfboard">Surfboard</option>
              <option value="loon">Loon</option>
              <option value="quanx">Quantumult X</option>
              <option value="v2ray">v2rayN / Shadowrocket</option>
              <option value="stash">Stash</option>
              <option value="plain">明文 vless</option>
            </select>
          </div>
        </div>
        <div class="field"><label>订阅链接</label>
          <div class="inrow">
            <input type="text" id="subUrl" readonly onclick="this.select()">
            <button class="btn sm" onclick="copySub()">复制</button>
            <button class="btn sm" onclick="toggleQR()">二维码</button>
            <button class="btn sm" onclick="downloadSub()">下载</button>
            <button class="btn sm primary" onclick="previewSub()">预览</button>
          </div>
        </div>
        <div id="qrWrap" style="display:none"></div>
        <p class="hint" style="margin-top:12px" id="subHint"></p>
        <div id="subPrev" style="display:none;margin-top:12px">
          <div class="kv"><span class="k">订阅类型</span><span class="v" id="prevType">—</span></div>
          <div class="kv"><span class="k">节点数量</span><span class="v" id="prevCount">—</span></div>
          <pre class="code" id="prevBody" style="margin-top:10px"></pre>
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>地区与线路筛选</h3>
        <div class="filter-region">
          <span class="filter-region-label">节点地区</span>
          <div class="pills">
            <label class="spill"><input type="checkbox" id="fl-region-all" checked><span>全部地区</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-HK"><span>香港</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-TW"><span>台湾</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-US"><span>美国</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-SG"><span>新加坡</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-JP"><span>日本</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-KR"><span>韩国</span></label>
            <label class="spill"><input type="checkbox" id="fl-region-DE"><span>德国</span></label>
          </div>
        </div>
        <div class="filter-row">
          <div class="filter-group">
            <div class="filter-group-title">IP 类型</div>
            <div class="pills">
              <label class="spill"><input type="checkbox" id="fl-ip4" checked><span>IPv4</span></label>
              <label class="spill"><input type="checkbox" id="fl-ip6" checked><span>IPv6</span></label>
            </div>
          </div>
          <div class="filter-group">
            <div class="filter-group-title">运营商偏好</div>
            <div class="pills">
              <label class="spill"><input type="checkbox" id="fl-isp-m" checked><span>移动</span></label>
              <label class="spill"><input type="checkbox" id="fl-isp-c" checked><span>联通</span></label>
              <label class="spill"><input type="checkbox" id="fl-isp-t" checked><span>电信</span></label>
            </div>
          </div>
          <div class="filter-group">
            <div class="filter-group-title">地址来源</div>
            <div class="pills nowrap">
              <label class="spill"><input type="checkbox" id="fl-native"><span>原生地址</span></label>
              <label class="spill"><input type="checkbox" id="fl-pref-domain" checked><span>优选域名</span></label>
              <label class="spill"><input type="checkbox" id="fl-pref-ip" checked><span>优选 IP</span></label>
              <label class="spill"><input type="checkbox" id="fl-custom-pref"><span>自定义优选</span></label>
              <label class="spill"><input type="checkbox" id="fl-random-pref"><span>随机优选</span></label>
            </div>
          </div>
        </div>
        <p class="hint" style="margin-top:12px">筛选按 地区 → IP 类型 → 运营商 逐级放宽，任一维度无节点时自动放宽，保证订阅始终非空。「运营商偏好」按节点名称中的运营商标记过滤（移动=移动/CM/CHINAMOBILE、联通=联通/CU/UNICOM、电信=电信/CT/CHINATELECOM），三个全选或节点池无任何运营商标记时不生效。「节点地区」支持多选，仅剔除明确标记为其它地区的节点。「地址来源」控制下发节点的来源：原生地址（工作器域名）、优选域名（第三方优选域名列表）、优选 IP（内置与实时拉取的优选 IP）、自定义优选（「优选配置」保存的优选列表）、随机优选（「优选配置」随机优选模式，与自定义优选互斥）。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>配额速览 <span class="sub" id="dbSub">未配置监控</span></h3>
        <div id="dbWrap" style="display:none">
          <div class="kv"><span class="k">当日请求量</span><span class="v" id="dbReq">—</span></div>
          <div style="margin:10px 0 6px;height:8px;border-radius:6px;background:var(--card2);overflow:hidden">
            <div id="dbBar" style="height:100%;width:0%;border-radius:6px;background:linear-gradient(90deg,var(--ok),var(--accent));transition:width .5s"></div>
          </div>
          <div class="kv"><span class="k">已用额度</span><span class="v" id="dbPct">—</span></div>
        </div>
        <p class="hint" style="margin-top:10px">免费计划 100,000 次/日。在「面板设置」配置 Cloudflare 监控选项后即可在此查看当日用量；详细策略与自动调节见「配额安全」。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>运行状态</h3>
        <div class="kv"><span class="k">协议</span><span class="v" id="stProto">—</span></div>
        <div class="kv"><span class="k">KV 持久化</span><span class="v" id="stKv">—</span></div>
        <div class="kv"><span class="k">面板入口</span><span class="v" id="stEntry">—</span></div>
      </div>
    </section>

    <!-- ===== 视图：节点配置（协议 / TLS / ECH / 落地出站） ===== -->
    <section class="view" data-view="nodes">
      <div class="view-head"><h2>节点配置</h2><p>代理协议、TLS/ECH、节点测活与落地出站（保存后立即生效）</p></div>
      <div class="grid3">
        <div class="card">
          <h3><span class="tick"></span>协议开关</h3>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="en-vless" checked><span class="sl"></span></label><span>VLESS 协议（默认开启）</span></div>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="en-trojan"><span class="sl"></span></label><span>Trojan 协议（支持Mihomo内核）</span></div>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="en-xhttp"><span class="sl"></span></label><span>XHTTP 协议（支持Mihomo内核，须绑定自定义域名并开启gRPC）</span></div>
          <div class="field" style="margin-top:12px"><label>Trojan 密码（留空使用 UUID）</label><input type="text" id="tp-pass" placeholder="Trojan 密码" autocomplete="off" oninput="onSecretInput('tp-pass')"><input type="hidden" id="tp-pass-clear" value=""><button type="button" class="btn sm" id="tp-pass-clear-btn" onclick="clearSecret('tp-pass')" style="margin-top:8px">清除已保存密码（保存后生效）</button></div>
        </div>
        <div class="card">
          <h3><span class="tick"></span>TLS 与传输</h3>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="tls-only"><span class="sl"></span></label><span>仅 TLS 端口（跳过 80/8080 等明文端口）</span></div>
          <div class="field" style="margin-top:12px"><label>ALPN 协商（h2 / http/1.1，逗号分隔）</label><input type="text" id="alpn" placeholder="留空自动，如 h2,http/1.1" autocomplete="off"></div>
          <p class="hint">明文端口节点（80/8080/8880/2052/2082/2086/2095）在开启「仅 TLS」后将从订阅中剔除。</p>
        </div>
        <div class="card">
          <h3><span class="tick"></span>节点测活</h3>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="q-probe-on"><span class="sl"></span></label><span>节点测活（TCP 探测）</span></div>
          <p class="hint" style="margin-top:12px">关闭：不做任何 TCP 握手 / HTTP 探测与剔除，节点的下发策略、出入站方式、ProxyIP 等节点相关均按 V1.x版本处理方式处理——按数据源原始顺序全量下发，客户端自行择优。<br>开启：对候选地址做 TCP 探测并剔除判死项（含精选池 / 优选 IP / 域名预检 / ProxyIP 兜底）；Cloudflare 运行时禁止出站连接 CF IP 段，故对 CF 段 IP 跳过探测、直接视为可用（内置精选池实测 97% 可用，不会被误判清空），仅对非 CF 段（反代 / ProxyIP）真实测活剔除死节点。自定义订阅 / 随机优选模式不测活。</p>
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>ECH 加密（可选）</h3>
        <div class="proto-row"><label class="switch"><input type="checkbox" id="ech-on"><span class="sl"></span></label><span>启用 ECH 加密（需绑定自定义域名）</span></div>
        <div class="grid2" style="margin-top:12px">
          <div class="field" style="margin-bottom:0"><label>ECH 域名（留空用默认 cloudflare-ech.com）</label><input type="text" id="ech-host" placeholder="cloudflare-ech.com" autocomplete="off"></div>
          <div class="field" style="margin-bottom:0"><label>自定义 ECH DNS（DoH 地址，留空用客户端默认）</label><input type="text" id="ech-dns" placeholder="https://223.5.5.5/dns-query" autocomplete="off"></div>
        </div>
        <p class="hint">开启后订阅节点将附带 ech 参数与 alpn 协商，客户端需支持 ECH 才能生效。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>落地与出站</h3>
        <div class="field"><label>反代 / 落地 IP（无出站代理时优先使用；有出站代理时作为代理和直连失败后的兜底，格式 host 或 host:port）</label><input type="text" id="s-proxyIP" placeholder="留空则直连失败后走内置地区反代" autocomplete="off"></div>
        <div class="field"><label>出站代理（可选）</label><input type="text" id="s-outbound" placeholder="socks5://user:pass@1.2.3.4:1080 或 ss://chacha20-ietf-poly1305:密码@1.2.3.4:8388" autocomplete="off" oninput="onOutboundInput()"><input type="hidden" id="s-outbound-clear" value=""><button type="button" class="btn sm" id="s-outbound-clear-btn" onclick="clearOutboundProxy()" style="margin-top:8px">清除现有出站代理（保存后生效）</button></div>
        <p class="hint">支持 socks5://（可带 user:pass@）、http(s)://、ss:// 或 host:port（默认按 socks5，端口 1080）。SS 加密支持 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305。</p>
        <div class="field" style="margin-bottom:0"><label>出站方式</label>
          <select id="s-outmode">
            <option value="">默认（优先代理，失败直连）</option>
            <option value="no">直连优先（no）</option>
            <option value="only">仅走代理（only）</option>
          </select>
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>保存与生效</h3>
        <div class="note-box" style="margin:0">所有配置修改后点击右下角「保存全部」才会写入 KV 并生效，保存成功后订阅地址与节点构成立即更新；「重置」恢复普通选项，保留访问凭据和路径。</div>
      </div>
    </section>

    <!-- ===== 视图：优选配置 ===== -->
    <section class="view" data-view="optimizer">
      <div class="view-head"><h2>优选配置</h2><p>拉取候选 IP → 本地测速 → 最优节点加入订阅</p></div>
      <div class="card">
        <h3><span class="tick"></span>在线优选</h3>
        <div class="grid3">
          <div class="field" style="grid-column:span 2;margin:0"><label>数据源</label>
            <select id="o-source">
              <option value="wetest_v4">微测网 IPv4</option>
              <option value="wetest_v6">微测网 IPv6</option>
              <option value="bestcf">优选 IP 列表（bestcf）</option>
              <option value="hostmonit">HostMonit 优选</option>
              <option value="cidr">内置 Cloudflare 地址段</option>
              <option value="custom">自定义 URL</option>
            </select>
          </div>
          <div class="field" style="margin:0"><label>测速端口</label>
            <select id="o-port" onchange="onPortSel()">
              <optgroup label="HTTPS"><option value="443">443</option><option value="2053">2053</option><option value="2083">2083</option><option value="2087">2087</option><option value="2096">2096</option><option value="8443">8443</option></optgroup>
              <optgroup label="HTTP"><option value="80">80</option><option value="8080">8080</option><option value="8880">8880</option><option value="2052">2052</option><option value="2082">2082</option><option value="2086">2086</option><option value="2095">2095</option></optgroup>
              <option value="custom">自定义…</option>
            </select>
            <input type="text" id="o-portC" style="display:none;margin-top:8px" placeholder="自定义端口号" autocomplete="off">
          </div>
        </div>
        <div class="field" id="o-customWrap" style="display:none"><label>自定义数据源 URL</label><input type="text" id="o-sourceURL" placeholder="https://example.com/ip.txt" autocomplete="off"></div>
        <div class="grid3" style="margin-top:6px">
          <div class="field" style="margin:0"><label>并发线程（1-50）</label><input type="number" id="o-threads" min="1" max="50" value="5"></div>
          <div class="field" style="margin:0"><label>候选数量</label><input type="number" id="o-count" min="1" value="20"></div>
          <div class="field" style="margin:0"><label>随机补足（0 关闭）</label><input type="number" id="o-fill" min="0" value="0"></div>
        </div>
        <div class="row" style="margin-top:14px">
          <label class="switch"><input type="checkbox" id="o-useCidr" checked><span class="sl"></span></label>
          <span style="font-size:13px;color:var(--dim)">候选不足时用 Cloudflare 地址段随机补足</span>
          <span style="flex:1"></span>
          <button class="btn primary" onclick="runPick()">开始优选</button>
          <button class="btn" onclick="addAllBest()">全部加入最优</button>
        </div>
        <div class="msg" id="oMsg"></div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>测速结果 <span class="sub">浏览器连通性参考（不代表代理链路可用）</span></h3>
        <div class="tbl-wrap">
          <table><colgroup><col style="width:42%"><col style="width:18%"><col style="width:16%"><col style="width:24%"></colgroup>
          <thead><tr><th>IP : 端口</th><th>延迟</th><th>状态</th><th>操作</th></tr></thead>
          <tbody id="oTableBody"><tr><td colspan="4" style="text-align:center;color:var(--faint)">尚未测速 — 点击「开始优选」拉取候选</td></tr></tbody></table>
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>优选节点</h3>
        <div class="grid2">
          <div class="field" style="margin:0"><label>订阅模式</label>
            <select id="o-submode" onchange="onSubMode()">
              <option value="">关闭（使用面板默认节点池）</option>
              <option value="custom">自定义订阅（支持汇聚）</option>
              <option value="random">随机优选模式（官方接口）</option>
            </select>
          </div>
          <div class="field" style="margin:0"><label>自定义模式下追加默认节点</label>
            <select id="o-subinc">
              <option value="0">关闭（仅自定义节点）</option>
              <option value="1">开启（追加内置优选池与默认地区源）</option>
            </select>
          </div>
        </div>
        <div class="field" id="sm-custom" style="margin-top:14px;display:none">
          <label>优选节点（域名 / 优选 API / IP，每行一个；IP 格式 IP:端口#名称）</label>
          <textarea id="f-preferred" rows="6" placeholder="*.cloudflare.182682.xyz&#10;104.25.246.53:443#香港&#10;https://bestcf.pages.dev/random-region/HK/100.txt"></textarea>
          <div class="hint">开启「自定义订阅」后生效；域名与优选 API 保存后自动解析为可用 IP 下发。测速结果里的「加入优选」会把最优 IP 写入此列表，保存全部后生效。</div>
          <button class="btn sm" style="margin-top:8px" onclick="fetchDomains()">拉取微测网优选域名</button>
        </div>
        <div class="field" id="sm-random" style="margin-top:14px;display:none">
          <label>随机优选数量（1-99）</label>
          <input type="number" id="o-rand" min="1" max="99" value="16">
          <div class="hint">从 Cloudflare 地址段随机生成指定数量的优选节点直接下发，不经域名解析。</div>
        </div>
      </div>
    </section>

    <!-- ===== 视图：配额安全 ===== -->
    <section class="view" data-view="quota">
      <div class="view-head"><h2>配额安全</h2><p>查看 Cloudflare 账户用量快照；下发规模调节仅供减负，不保证账户额度（需在面板设置中配置 Cloudflare 账户 ID 及 API 令牌）</p></div>
      <div class="card">
        <h3><span class="tick"></span>Cloudflare 用量监控 <span class="sub" id="qQuotaSub">未配置</span></h3>
        <div id="qQuotaWrap">
          <div class="kv"><span class="k">当日请求量</span><span class="v" id="qReq">—</span></div>
          <div style="margin:10px 0 6px;height:10px;border-radius:6px;background:var(--card2);overflow:hidden">
            <div id="qBar" style="height:100%;width:0%;border-radius:6px;background:linear-gradient(90deg,var(--ok),var(--accent));transition:width .5s"></div>
          </div>
          <div class="kv"><span class="k">已用额度</span><span class="v" id="qPct">—</span></div>
          <div class="kv"><span class="k">剩余额度</span><span class="v" id="qRemain">—</span></div>
          <div class="kv"><span class="k">Workers CPU P50</span><span class="v" id="qCpu">—</span></div>
          <div class="kv"><span class="k">子请求数</span><span class="v" id="qSub">—</span></div>
          <div class="kv"><span class="k">数据更新</span><span class="v" id="qAt">—</span></div>
        </div>
        <div id="qQuotaEmpty" style="display:none">
          <div class="note-box" style="margin:0">尚未配置 Cloudflare 监控：在「面板设置」填写 Cloudflare 账户 ID 与 API 令牌（或部署时配置环境变量 CF_ACCOUNT_ID / CF_API_TOKEN），即可实时查看当日请求量并启用自动调节。</div>
        </div>
        <div id="qQuotaErr" style="display:none">
          <div class="note-box" style="margin:0;border-left-color:var(--err)" id="qQuotaErrText">用量查询失败</div>
        </div>
        <div class="row" style="margin-top:14px">
          <label class="switch"><input type="checkbox" id="q-auto-on"><span class="sl"></span></label>
          <span style="font-size:13px">自动调节：当日用量 ≥ 60% 时按比例收缩节点上限（辅助降低订阅生成成本）</span>
          <span style="flex:1"></span>
          <button class="btn sm" onclick="refreshQuota()">刷新用量</button>
        </div>
        <p class="hint">自动调节仅使用当前运行实例中最近 5 分钟的监控快照，以 300 条为基准收紧节点上限；没有有效快照时使用正常上限。此功能不能限制请求总数或保证免费额度不超限，付费账户也不适用此免费配额基准。</p>
      </div>
      <div class="grid2">
        <div class="card">
          <h3><span class="tick"></span>下发控制</h3>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="q-nl-on"><span class="sl"></span></label><span>精确节点数量控制</span></div>
          <div class="field" style="margin-top:10px"><label>节点上限（1-800）</label><input type="number" id="q-nl-count" min="1" max="800" value="300"></div>
          <p class="hint">默认 300 条；结构化格式最多 300 条，明文最多 800 条，与自定义上限取较小值。上限约束所有协议总数，实际数量取决于可用来源。</p>
        </div>
        <div class="card">
          <h3><span class="tick"></span>轮询换新</h3>
          <div class="proto-row"><label class="switch"><input type="checkbox" id="q-poll-on"><span class="sl"></span></label><span>启用轮询（默认关闭）</span></div>
          <p class="hint" style="margin-top:12px">每 15 分钟按配置版本与客户端标识轮换候选顺序，不写入 KV。开启或关闭均遵守节点上限；不保证相邻窗口完全不重复。</p>
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>当前下发策略</h3>
        <div class="grid3">
          <div class="field" style="margin:0"><div class="kv"><span class="k">节点数量控制</span><span class="v" id="qNl">—</span></div><div class="kv"><span class="k">精确节点上限</span><span class="v" id="qNlCount">—</span></div></div>
          <div class="field" style="margin:0"><div class="kv"><span class="k">节点测活</span><span class="v" id="qProbe">—</span></div><div class="kv"><span class="k">轮询换新机制</span><span class="v" id="qPoll">—</span></div></div>
          <div class="field" style="margin:0"><div class="kv"><span class="k">行式格式上限</span><span class="v">800 节点</span></div><div class="kv"><span class="k">结构化格式上限</span><span class="v">300 节点</span></div></div>
        </div>
        <p class="hint" style="margin-top:10px">每次订阅请求都会消耗 Worker 的 CPU 时间（免费计划 10ms/请求）。节点上限仅降低开销，实际 CPU 时间仍需在部署后的 Metrics 中验证。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>保护机制说明</h3>
        <div class="note-box">请求预算、并发、响应大小和节点上限共同降低生成开销。用量数据属于分析估算，存在延迟；缩减节点数不能阻止大量请求，不能作为账户级硬配额控制。</div>
      </div>
    </section>

    <!-- ===== 视图：面板设置 ===== -->
    <section class="view" data-view="account">
      <div class="view-head"><h2>面板设置</h2><p>部署基础信息：UUID、面板路径、管理密码与绑定域名</p></div>
      <div class="card">
        <h3><span class="tick"></span>基础配置</h3>
        <div class="field"><label>UUID（订阅节点身份）</label>
          <div class="inrow">
            <input type="text" id="a-uuid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autocomplete="off">
            <button class="btn sm" onclick="genUuid()">生成</button>
          </div>
        </div>
        <div class="field"><label>面板路径（访问入口，留空用 UUID）</label><input type="text" id="a-path" placeholder="留空自动使用 UUID" autocomplete="off"></div>
        <div class="field"><label>自定义订阅别名（如 AAZ；留空使用令牌路径）</label><input type="text" id="a-suburl" placeholder="AAZ" autocomplete="off"></div>
        <div class="field"><label>管理密码（至少 8 位，留空保留已配置密码）</label><input type="password" id="a-admin" placeholder="设置后访问面板需登录" autocomplete="new-password"></div>
        <div class="field" style="margin-bottom:0"><label>绑定域名（留空使用当前访问域名）</label><input type="text" id="a-host" placeholder="node.example.com" autocomplete="off"></div>
        <p class="hint" style="margin-top:10px">「绑定域名」用于订阅节点的 SNI/Host，不负责域名解析。请先在 Cloudflare 对应 Pages 或 Worker 项目绑定域名并确认有效证书。留空使用当前访问域名。未绑定 KV K 时不能保存配置；环境变量优先于面板配置。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>Cloudflare 监控选项（可选）</h3>
        <div class="grid2">
          <div class="field" style="margin:0"><label>账户 ID（Account Tag）</label><input type="text" id="a-cfid" placeholder="32 位十六进制 ID，位于 dash.cloudflare.com 右侧栏「账户 ID」" autocomplete="off"></div>
          <div class="field" style="margin:0"><label>API 令牌（Bearer）</label><input type="password" id="a-cftoken" placeholder="40 位令牌（My Profile → API Tokens 创建）" autocomplete="new-password" oninput="onSecretInput('a-cftoken')"><input type="hidden" id="a-cftoken-clear" value=""><button type="button" class="btn sm" id="a-cftoken-clear-btn" onclick="clearSecret('a-cftoken')" style="margin-top:8px">清除已保存令牌（保存后生效）</button></div>
        </div>
        <p class="hint" style="margin-top:10px">账户 ID 是 32 位十六进制字符串（<b>不是邮箱</b>），打开并登录Cloudflare账户后，点击「左侧栏」→「管理账户」→「帐户 API 令牌」→「创建令牌」。查询失败提示 401 时请检查这两项是否填错。</p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>备份与恢复</h3>
        <p class="hint" style="margin-top:0;margin-bottom:12px">以 JSON 格式导出普通配置（不含密码、出站凭据、监控令牌与订阅令牌），可保存到本地或迁移到其他部署；导入后请点右下角「保存全部」生效。</p>
        <div class="inrow">
          <button class="btn" onclick="exportConfig()">导出配置</button>
          <button class="btn" onclick="$('importFile').click()">导入配置</button>
          <input type="file" id="importFile" accept=".json,application/json" style="display:none" onchange="importConfig(this)">
        </div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>运行信息</h3>
        <div class="kv"><span class="k">面板版本</span><span class="v" id="aVer">—</span></div>
        <div class="kv"><span class="k">KV 持久化</span><span class="v" id="aKv">—</span></div>
        <div class="kv"><span class="k">轮询窗口</span><span class="v">15 分钟无状态轮换</span></div>
        <div class="kv"><span class="k">构建日期</span><span class="v">2026-09-26</span></div>
      </div>
      <div class="danger-zone">
        <h3 style="margin-bottom:8px;color:var(--err)">危险操作</h3>
        <p style="font-size:13px;color:var(--dim);margin-bottom:12px">重置恢复普通选项的默认值，保留 UUID、管理密码、路径及已保存的访问凭据。</p>
        <button class="btn danger" onclick="resetAll()">重置普通配置</button>
      </div>
    </section>

    <!-- ===== 视图：关于 ===== -->
    <section class="view" data-view="about">
      <div class="view-head"><h2>关于项目</h2><p>CFNext — Cloudflare 全新代理管理面板（独立界面 + 独立实现）</p></div>
      <div class="card">
        <h3><span class="tick"></span>相关链接</h3>
        <p style="font-size:13px;color:var(--dim)">YouTube @数字派：<a href="https://www.youtube.com/@PAI_CN" target="_blank" rel="noopener">youtube.com/@PAI_CN</a></p>
        <p style="font-size:13px;color:var(--dim);margin-top:6px">Telegram 交流群：<a href="https://t.me/SZ_PAI" target="_blank" rel="noopener">t.me/SZ_PAI</a></p>
      </div>
      <div class="card">
        <h3><span class="tick"></span>特别鸣谢</h3>
        <p style="font-size:13px;color:var(--dim);margin-bottom:10px">本面板为全新独立设计/全新编写：后端代理、订阅与优选逻辑参考以下开源项目的功能清单</p>
        <div class="tbl-wrap"><table>
          <colgroup><col style="width:34%"><col style="width:66%"></colgroup>
          <thead><tr><th>参考仓库</th><th>地址</th></tr></thead>
          <tbody>
            <tr><td>cmliu/edgetunnel</td><td><a href="https://github.com/cmliu/edgetunnel" target="_blank" rel="noopener">github.com/cmliu/edgetunnel</a></td></tr>
            <tr><td>zizifn/edgetunnel</td><td><a href="https://github.com/zizifn/edgetunnel" target="_blank" rel="noopener">github.com/zizifn/edgetunnel</a></td></tr>
            <tr><td>6Kmfi6HP/EDtunnel</td><td><a href="https://github.com/6Kmfi6HP/EDtunnel" target="_blank" rel="noopener">github.com/6Kmfi6HP/EDtunnel</a></td></tr>
            <tr><td>IonRh/Cloudflare-BestIP</td><td><a href="https://github.com/IonRh/Cloudflare-BestIP" target="_blank" rel="noopener">github.com/IonRh/Cloudflare-BestIP</a></td></tr>
            <tr><td>zvos/CF-Workers-Monitor</td><td><a href="https://github.com/zvos/CF-Workers-Monitor" target="_blank" rel="noopener">github.com/zvos/CF-Workers-Monitor</a></td></tr>
            <tr><td>MetaCubeX/meta-rules-dat</td><td><a href="https://github.com/MetaCubeX/meta-rules-dat" target="_blank" rel="noopener">github.com/MetaCubeX/meta-rules-dat</a></td></tr>
            <tr><td>666OS/rules</td><td><a href="https://github.com/666OS/rules" target="_blank" rel="noopener">github.com/666OS/rules</a></td></tr>
            <tr><td>DustinWin/ruleset_geodata</td><td><a href="https://github.com/DustinWin/ruleset_geodata" target="_blank" rel="noopener">github.com/DustinWin/ruleset_geodata</a></td></tr>
            <tr><td>blackmatrix7/ios_rule_script</td><td><a href="https://github.com/blackmatrix7/ios_rule_script" target="_blank" rel="noopener">github.com/blackmatrix7/ios_rule_script</a></td></tr>
            <tr><td>TG-Twilight/AWAvenue-Ads-Rule</td><td><a href="https://github.com/TG-Twilight/AWAvenue-Ads-Rule" target="_blank" rel="noopener">github.com/TG-Twilight/AWAvenue-Ads-Rule</a></td></tr>
            <tr><td>Koolson/Qure</td><td><a href="https://github.com/Koolson/Qure" target="_blank" rel="noopener">github.com/Koolson/Qure</a></td></tr>
          </tbody>
        </table></div>
      </div>
      <div class="card">
        <h3><span class="tick"></span>调用接口</h3>
        <div class="tbl-wrap"><table>
          <colgroup><col style="width:40%"><col style="width:60%"></colgroup>
          <thead><tr><th>用途</th><th>接口</th></tr></thead>
          <tbody>
            <tr><td>HostMonit 优选</td><td class="mono">stock.hostmonit.com/CloudFlareYes</td></tr>
            <tr><td>优选 IP 列表</td><td class="mono">cf.090227.xyz/ip.164746.xyz</td></tr>
            <tr><td>bestcf 地区优选池</td><td class="mono">bestcf.pages.dev/random-region/{HK|TW|JP|SG|US|KR}/100.txt</td></tr>
            <tr><td>DoH 解析</td><td class="mono">cloudflare-dns.com / dns.alidns.com / doh.pub</td></tr>
            <tr><td>Cloudflare 用量监控（GraphQL）</td><td class="mono">api.cloudflare.com/client/v4/graphql</td></tr>
            <tr><td>版本更新检测</td><td class="mono">raw.githubusercontent.com/PAICNI/CFNext/...</td></tr>
            <tr><td>远程规则集（sing-box / Clash）</td><td class="mono">raw.githubusercontent.com/MetaCubeX/meta-rules-dat/...</td></tr>
            <tr><td>面板二维码库</td><td class="mono">cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js</td></tr>
          </tbody>
        </table></div>
      </div>
    </section>
  </div>
</div>
</div>

<div class="fbar">
  <span class="saved-at" id="savedAt">尚未保存</span>
  <button class="btn danger" id="resetBtn" onclick="resetAll()">重置</button>
  <button class="btn primary" id="saveBtn" onclick="saveAll()"><span class="dirty-dot"></span>保存全部</button>
</div>
<div class="toast" id="toast"></div>

<script>
/* ===== 基础 ===== */
var APIPATH = location.pathname.replace(/\/+$/, '');
var CFG = null;
var LAST = [];
var toastTimer = null;
function $(id){ return document.getElementById(id); }
function api(p, opts){
  return fetch(APIPATH + '/api/' + p, opts).then(function(r){ return r.json(); });
}
function toast(t, ty){
  var el = $('toast');
  el.textContent = t;
  el.className = 'toast show ' + (ty || '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function(){ el.className = 'toast'; }, 2600);
}
function showMsg(id, t, ty){
  var el = $(id);
  el.textContent = t;
  el.className = 'msg show ' + (ty || 'info');
}
function copyText(t){
  var done = false;
  function fin(ok2){
    if (done) return; done = true;
    toast(ok2 ? '已复制' : '复制失败，请手动复制', ok2 ? 'ok' : 'err');
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    var p = null;
    try { p = navigator.clipboard.writeText(t); } catch (e) { fin(fallbackCopy(t)); return; }
    if (p && typeof p.then === 'function') {
      p.then(function(){ fin(true); }, function(){ fin(fallbackCopy(t)); });
      setTimeout(function(){ fin(fallbackCopy(t)); }, 600); // 剪贴板 API 悬空（无权限等）时回退
    } else { fin(true); }
  } else {
    fin(fallbackCopy(t));
  }
}
function fallbackCopy(t){
  var ta = document.createElement('textarea');
  ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  var ok2 = false;
  try { ok2 = document.execCommand('copy'); } catch (e) { ok2 = false; }
  document.body.removeChild(ta);
  return ok2;
}
function copySub(){ copyText($('subUrl').value || makeSub()); }
function markDirty(){
  $('saveBtn').classList.add('dirty');
  $('savedAt').textContent = '有未保存的修改';
}

/* ===== 导航 ===== */
var NAV = [
  { id:'dashboard', name:'仪表盘', icon:'<path d="M4 4h7v7H4zM13 4h7v4h-7zM4 13h7v7H4zM13 11h7v9h-7z"/>' },
  { id:'nodes', name:'节点配置', icon:'<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12l8-4.5M12 12L4 7.5"/>' },
  { id:'optimizer', name:'优选配置', icon:'<path d="M12 19a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM12 8v4l2.5 2.5M3 3l3 3"/>' },
  { id:'quota', name:'配额安全', icon:'<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6zM9 12l2 2 4-4"/>' },
  { id:'account', name:'面板设置', icon:'<path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21c0-3.5 3.6-6 8-6s8 2.5 8 6"/>' },
  { id:'about', name:'关于项目', icon:'<path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v5M12 8h.01"/>' }
];
var TITLES = { dashboard:'仪表盘', nodes:'节点配置', optimizer:'优选配置', quota:'配额安全', account:'面板设置', about:'关于项目' };
function buildNav(){
  var html = '';
  NAV.forEach(function(n){
    html += '<button class="nav-item" data-v="' + n.id + '" onclick="switchView(\'' + n.id + '\')"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + n.icon + '</svg>' + n.name + '</button>';
  });
  $('nav').innerHTML = html;
}
function switchView(id){
  document.querySelectorAll('.nav-item').forEach(function(b){
    b.classList.toggle('on', b.getAttribute('data-v') === id);
  });
  document.querySelectorAll('.view').forEach(function(x){
    x.classList.toggle('on', x.getAttribute('data-view') === id);
  });
  $('pageTitle').textContent = TITLES[id] || '';
  $('sidebar').classList.remove('open');
}
$('hamb').addEventListener('click', function(){ $('sidebar').classList.toggle('open'); });

/* ===== 主题 ===== */
function storedTheme(){ return window.cfTheme.get(); }
function setThemeIcon(t){
  var p = document.getElementById('themeIcon');
  if (!p) return;
  if (t === 'light') p.setAttribute('d', 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4');
  else p.setAttribute('d', 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z');
}
function updateThemeButton(){
  setThemeIcon(document.documentElement.getAttribute('data-theme'));
  var mode = storedTheme();
  var labels = {auto:'跟随系统',light:'日间',dark:'夜间'};
  var next = {auto:'light',light:'dark',dark:'auto'}[mode];
  var label = '主题：' + labels[mode] + '；点击切换为' + labels[next];
  $('themeBtn').title = label;
  $('themeBtn').setAttribute('aria-label', label);
}
function setTheme(t){
  window.cfTheme.set(t);
  toast(t === 'auto' ? '已切换为跟随系统' : (t === 'light' ? '已切换为日间模式' : '已切换为夜间模式'), 'ok');
}
$('themeBtn').addEventListener('click', function(){
  setTheme({auto:'light',light:'dark',dark:'auto'}[storedTheme()]);
});
window.addEventListener('cf-theme-change', updateThemeButton);
updateThemeButton();

/* ===== 更新检测 ===== */
var topVerText = 'v—';
function legacyCopy(t){
  try {
    var ta = document.createElement('textarea');
    ta.value = t;
    ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    var ok2 = false;
    try { ok2 = document.execCommand('copy'); } catch (e) { ok2 = false; }
    document.body.removeChild(ta);
    return ok2;
  } catch (e) { return false; }
}
function copyClipboard(t){
  return new Promise(function(ok){
    var done = false;
    function finish(v){ if (done) return; done = true; ok(v); }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        var p = null;
        try { p = navigator.clipboard.writeText(t); } catch (e) { finish(legacyCopy(t)); return; }
        if (p && typeof p.then === 'function') {
          p.then(function(){ finish(true); }, function(){ finish(legacyCopy(t)); });
          setTimeout(function(){ finish(legacyCopy(t)); }, 600); // 剪贴板 API 悬空（无权限等）时回退
        } else { finish(true); }
      } else {
        finish(legacyCopy(t));
      }
    } catch (e) { finish(legacyCopy(t)); }
  });
}
function checkUpdate(){
  var sv = $('sideVer');
  if (sv.classList.contains('checking')) return;
  sv.classList.add('checking');
  sv.textContent = '检测中…';
  api('update').then(function(r){
    sv.classList.remove('checking');
    if (!r || !r.ok || !r.data) { sv.textContent = topVerText; toast('检测更新失败，请稍后重试', 'err'); return; }
    var d = r.data;
    var kindName = (d.kind === '混淆') ? '混淆版' : '明文版';
    topVerText = 'v' + d.current + ' ' + kindName;
    sv.textContent = topVerText;
    if (d.hasUpdate && d.code) {
      sv.classList.add('has-update');
      var kind = (d.kind === '混淆') ? '混淆' : '明文';
      copyClipboard(d.code).then(function(copied){
        toast(copied ? '检测到更新，已复制最新' + kind + '代码到剪贴板' : '检测到更新（v' + d.latest + '），复制失败，请前往仓库获取', copied ? 'ok' : 'err');
      });
    } else if (d.hasUpdate) {
      toast('检测到更新（v' + d.latest + '），但未能获取代码', 'err');
    } else if (d.latest) {
      sv.classList.remove('has-update');
      toast('已是最新版本（v' + d.current + ' ' + kindName + '）', 'ok');
    } else {
      toast('检测更新失败：' + (d.error || '仓库暂不可达'), 'err');
    }
  }).catch(function(){
    sv.classList.remove('checking');
    sv.textContent = topVerText;
    toast('检测更新失败，请稍后重试', 'err');
  });
}

/* ===== 配置加载与回填 ===== */
function loadAll(){
  if (/\.workers\.dev$/i.test(location.hostname)) $('wdwarn').style.display = 'block';
  api('status').then(function(r){
    if (r && r.ok) renderStatus(r.data);
  }).catch(function(){});
  api('config').then(function(r){
    if (r && r.ok){
      CFG = r.data;
      fillForm();
      renderAll();
      makeSub(false);
      setConn(true);
      refreshQuota();
      toast('配置已加载', 'ok');
    } else if (r && r.status === 403) {
      location.href = '/login?next=' + encodeURIComponent(APIPATH);
    } else {
      setConn(false);
      toast('无法连接服务器', 'err');
    }
  }).catch(function(){
    setConn(false);
    toast('无法连接服务器', 'err');
  });
}
function setConn(ok){
  var p = $('connPill');
  p.className = 'pill ' + (ok ? '' : 'off');
  $('connText').textContent = ok ? '运行中' : '无法连接';
}
function renderStatus(d){
  $('stEntry').textContent = location.origin + '/' + (d.path || '');
  var wd = !!(d.workersDev) || /\.workers\.dev$/i.test(location.hostname);
  $('wdwarn').style.display = wd ? 'block' : 'none';
  $('subHint').textContent = wd
    ? '当前为 *.workers.dev 域名：Cloudflare 可能限制该域名直连，若客户端更新订阅失败（提示无效订阅），请在客户端开启系统代理或「更新订阅使用代理」后重试；节点连接不受影响（直连优选 IP）。'
    : '';
  var kv = d.kv;
  var kvTxt = kv ? '已绑定（配置持久化）' : '未绑定（配置仅内存）';
  $('stKv').textContent = kvTxt;
  $('stKv').className = 'v ' + (kv ? 'ok' : 'bad');
  $('aKv').textContent = kvTxt;
  $('aKv').className = 'v ' + (kv ? 'ok' : 'bad');
  var v = d.version || '—';
  var kindName = (d.kind === '混淆版') ? '混淆版' : '明文版';   // 部署形态（明文版 / 混淆版），由后端自检
  $('sideVer').textContent = 'v' + v + ' ' + kindName;
  topVerText = 'v' + v + ' ' + kindName;
  $('aVer').textContent = v + ' ' + kindName;
}
function protoText(){
  if (!CFG) return '—';
  var a = [];
  if (CFG.enableVless !== false) a.push('VLESS');
  if (CFG.enableTrojan) a.push('Trojan');
  if (CFG.enableXhttp) a.push('XHTTP');
  return a.length ? a.join(' / ') : '未启用';
}
function renderAll(){
  $('stProto').textContent = protoText();
  renderQuota();
}
function renderQuota(){
  var nl = !!(CFG && CFG.nodeLimit);
  $('qNl').textContent = nl ? '已开启' : '关闭（默认分档上限）';
  $('qNl').className = 'v ' + (nl ? 'ok' : '');
  $('qNlCount').textContent = nl ? (CFG.nodeLimitCount || 300) + ' 节点' : '—';
  var po = !(CFG && CFG.polling === false);
  $('qPoll').textContent = po ? '已开启（每轮换新 IP）' : '关闭（每次下发全部）';
  $('qPoll').className = 'v ' + (po ? 'ok' : '');
  // 节点测活：开启 = 红字提醒（会误杀 CF 段精选池），关闭 = 绿字（推荐状态，对齐 V1.0.6）
  var pa = !!(CFG && CFG.probeAlive);
  $('qProbe').textContent = pa ? '已开启（剔除死节点，体感更快）' : '关闭（不测活，按 V1.x 原序下发）';
  $('qProbe').className = 'v ' + (pa ? 'warn' : 'ok');
}
function fmtNum(n){
  if (n == null || isNaN(n)) return '—';
  n = Number(n);
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}
function showQuotaState(kind, text){
  $('qQuotaWrap').style.display = (kind === 'data') ? '' : 'none';
  $('qQuotaEmpty').style.display = (kind === 'empty') ? '' : 'none';
  $('qQuotaErr').style.display = (kind === 'err') ? '' : 'none';
  if (kind === 'err') $('qQuotaErrText').textContent = quotaErrText(text);
  if (kind === 'data'){ $('qQuotaEmpty').style.display = 'none'; }
}
function quotaErrText(e){
  var m = String(e || '');
  if (m.indexOf('401') >= 0) return '认证失败（CF API 401）：请检查账户 ID 是否为 32 位十六进制、API 令牌是否有效且勾选 Account Analytics 读取权限';
  if (m.indexOf('403') >= 0) return '无权限（CF API 403）：API 令牌缺少账户 Analytics 读取权限';
  if (m.indexOf('429') >= 0) return 'CF API 限流（429）：已自动退避 15 分钟，期间沿用缓存数据';
  if (m.indexOf('未找到账户') >= 0) return m + '：请核对 dash.cloudflare.com 右侧栏的 32 位账户 ID';
  return m || '用量查询失败';
}
function renderQuotaData(d){
  updDbQuota(d);
  if (!d || !d.configured){
    $('qQuotaSub').textContent = '未配置';
    showQuotaState('empty');
    return;
  }
  if (d.error && !d.stale){
    $('qQuotaSub').textContent = '查询失败';
    showQuotaState('err', d.error);
    return;
  }
  $('qQuotaSub').textContent = d.stale ? '缓存数据' : '已连接';
  showQuotaState('data');
  $('qReq').textContent = fmtNum(d.today.requests) + ' / ' + fmtNum(d.limit);
  var p = d.percent || 0;
  $('qBar').style.width = Math.min(100, p) + '%';
  $('qBar').style.background = p >= 90 ? 'linear-gradient(90deg,var(--err),var(--warn))' : (p >= 60 ? 'linear-gradient(90deg,var(--warn),var(--accent))' : 'linear-gradient(90deg,var(--ok),var(--accent))');
  $('qPct').textContent = p + '%';
  $('qPct').className = 'v ' + (p >= 90 ? 'bad' : (p >= 60 ? '' : 'ok'));
  $('qRemain').textContent = fmtNum(d.remaining != null ? d.remaining : (d.limit - d.today.requests));
  $('qCpu').textContent = (d.today.cpuTime != null) ? (d.today.cpuTime / 1000).toFixed(2) + ' ms' : '—';
  $('qSub').textContent = fmtNum(d.today.subrequests);
  $('qAt').textContent = (d.updatedAt ? String(d.updatedAt).replace('T', ' ').replace('Z', '') + ' UTC' : '—') + (d.stale ? '（限流缓存）' : '');
}
function updDbQuota(d){
  if (!d || !d.configured){ $('dbSub').textContent = '未配置监控'; $('dbWrap').style.display = 'none'; return; }
  if (d.error && !d.stale){ $('dbSub').textContent = '查询失败'; $('dbWrap').style.display = 'none'; return; }
  $('dbSub').textContent = d.stale ? '缓存数据' : '已连接';
  $('dbWrap').style.display = '';
  $('dbReq').textContent = fmtNum(d.today.requests) + ' / ' + fmtNum(d.limit);
  var p = d.percent || 0;
  $('dbBar').style.width = Math.min(100, p) + '%';
  $('dbBar').style.background = p >= 90 ? 'linear-gradient(90deg,var(--err),var(--warn))' : (p >= 60 ? 'linear-gradient(90deg,var(--warn),var(--accent))' : 'linear-gradient(90deg,var(--ok),var(--accent))');
  $('dbPct').textContent = p + '%';
  $('dbPct').className = 'v ' + (p >= 90 ? 'bad' : (p >= 60 ? '' : 'ok'));
}
function refreshQuota(){
  $('qQuotaSub').textContent = '查询中…';
  api('quota').then(function(r){
    if (r && r.ok) renderQuotaData(r.data);
    else { $('qQuotaSub').textContent = '查询失败'; showQuotaState('err', (r && r.msg) || '查询失败'); }
  }).catch(function(){ $('qQuotaSub').textContent = '查询失败'; showQuotaState('err', '无法连接服务器'); });
}
function parseIps(t){
  var out = [];
  String(t || '').split(/[\n,;]+/).map(function(s){ return s.trim(); }).filter(Boolean).forEach(function(s){
    var name = '';
    if (s.indexOf('#') >= 0){ var a = s.split('#'); s = a[0]; name = a[1]; }
    var m;
    if ((m = s.match(/^\[([0-9a-fA-F:]+)\](?::(\d+))?$/))){ out.push({ ip: m[1], port: parseInt(m[2]) || 443, name: name }); return; }
    if ((m = s.match(/^(\d+\.\d+\.\d+\.\d+)(?::(\d+))?$/))){ out.push({ ip: m[1], port: parseInt(m[2]) || 443, name: name }); }
  });
  return out;
}
function renderPreferred(){
  if (!CFG) return;
  var lines = [];
  String(CFG.preferredDomains || '').split(/[\n,;]+/).map(function(s){ return s.trim(); }).filter(Boolean).forEach(function(s){ lines.push(s); });
  (CFG.preferredIPs || []).forEach(function(x){
    lines.push((String(x.ip).indexOf(':') >= 0 ? '[' + x.ip + ']' : x.ip) + ':' + (x.port || 443) + (x.name ? ('#' + x.name) : ''));
  });
  $('f-preferred').value = lines.join('\n');
}
function fillPort(pv){
  pv = String(pv == null ? 443 : pv);
  var sel = $('o-port');
  var found = false;
  for (var i = 0; i < sel.options.length; i++){ if (sel.options[i].value === pv){ found = true; break; } }
  if (found){ sel.value = pv; $('o-portC').style.display = 'none'; }
  else { sel.value = 'custom'; $('o-portC').value = pv; $('o-portC').style.display = ''; }
}
function fillForm(){
  if (!CFG) return;
  $('en-vless').checked = CFG.enableVless !== false;
  $('en-trojan').checked = !!CFG.enableTrojan;
  $('tp-pass').value = CFG.trojanPassword || '';
  $('en-xhttp').checked = !!CFG.enableXhttp;
  $('tls-only').checked = !!CFG.tlsOnly;
  $('alpn').value = CFG.alpn || '';
  $('ech-on').checked = !!CFG.ech;
  $('ech-host').value = CFG.echHost || '';
  $('ech-dns').value = CFG.echDns || '';
  var fl = CFG.filter || {};
  var region = fl.region || 'all';
  var regionArr = Array.isArray(region) ? region : (region === 'all' ? ['all'] : [region]);
  $('fl-region-all').checked = regionArr.indexOf('all') >= 0;
  ['HK', 'TW', 'US', 'SG', 'JP', 'KR', 'DE'].forEach(function(r){ $('fl-region-' + r).checked = regionArr.indexOf(r) >= 0; });
  var ipType = fl.ipType || ['IPv4', 'IPv6'];
  $('fl-ip4').checked = ipType.indexOf('IPv4') >= 0;
  $('fl-ip6').checked = ipType.indexOf('IPv6') >= 0;
  var isp = fl.isp || ['移动', '联通', '电信'];
  $('fl-isp-m').checked = isp.indexOf('移动') >= 0;
  $('fl-isp-c').checked = isp.indexOf('联通') >= 0;
  $('fl-isp-t').checked = isp.indexOf('电信') >= 0;
  var src = CFG.src || {};
  $('fl-native').checked = src.native === true;
  $('fl-pref-domain').checked = src.prefDomain !== false;
  $('fl-pref-ip').checked = src.prefIp !== false;
  $('fl-custom-pref').checked = src.customPref === true;
  var o = CFG.optimizer || {};
  $('o-source').value = o.source || 'wetest_v4';
  $('o-sourceURL').value = o.sourceURL || '';
  fillPort(o.port);
  $('o-threads').value = o.threads || 5;
  $('o-count').value = o.count || 20;
  $('o-fill').value = (o.fillCount == null ? 0 : o.fillCount);
  $('o-useCidr').checked = o.useCidr !== false;
  $('o-submode').value = o.subMode || '';
  $('o-subinc').value = (o.subIncludeDefault ? '1' : '0');
  $('o-rand').value = o.subRandomCount == null ? 16 : o.subRandomCount;
  $('q-nl-on').checked = !!CFG.nodeLimit;
  $('q-nl-count').value = CFG.nodeLimitCount || 300;
  $('q-poll-on').checked = CFG.polling !== false;
  $('q-probe-on').checked = !!CFG.probeAlive;
  $('q-auto-on').checked = !!CFG.quotaAuto;
  $('a-uuid').value = CFG.uuid || '';
  $('a-path').value = CFG.path || '';
  $('a-suburl').value = CFG.subUrl || '';
  $('a-admin').value = CFG.admin || '';
  $('a-host').value = CFG.host || '';
  $('a-cfid').value = CFG.cfAccountId || '';
  $('a-cftoken').value = CFG.cfApiToken || '';
  [['a-admin','admin'],['a-cftoken','cfApiToken'],['s-outbound','outboundProxy'],['tp-pass','trojanPassword']].forEach(function(pair){var el=$(pair[0]);var locked=(CFG.lockedFields||[]).includes(pair[1]);var clear=$(pair[0]+'-clear');if(clear){clear.value='';$(pair[0]+'-clear-btn').disabled=locked || !(CFG.secretConfigured&&CFG.secretConfigured[pair[1]]);}el.placeholder=CFG.secretConfigured&&CFG.secretConfigured[pair[1]]?'已配置，留空保留；输入新值替换':'尚未配置';el.disabled=locked;});
  [['a-uuid','uuid'],['a-path','path']].forEach(function(pair){$(pair[0]).disabled=(CFG.lockedFields||[]).includes(pair[1]);});
  $('s-proxyIP').value = CFG.proxyIP || '';
  $('s-outbound').value = CFG.outboundProxy || '';
  $('s-outmode').value = CFG.outboundMode || '';
  renderPreferred();
  bindRegionPills();
  onSubMode();
  $('o-customWrap').style.display = ($('o-source').value === 'custom') ? '' : 'none';
}
function onSecretInput(id){ $(id+'-clear').value=''; $(id+'-clear-btn').disabled=false; }
function clearSecret(id){
  $(id).value='';
  $(id+'-clear').value='1';
  $(id+'-clear-btn').disabled=true;
  markDirty();
}
function onOutboundInput(){ onSecretInput('s-outbound'); }
function clearOutboundProxy(){ clearSecret('s-outbound'); }
// 节点地区多选互斥：勾选具体地区时取消「全部地区」；全部取消时自动恢复「全部地区」（保证筛选非空）
function bindRegionPills(){
  if (window.__regionPillsBound) return;
  window.__regionPillsBound = true;
  var codes = ['HK', 'TW', 'US', 'SG', 'JP', 'KR', 'DE'];
  var all = $('fl-region-all');
  all.addEventListener('change', function(){
    if (all.checked) codes.forEach(function(r){ $('fl-region-' + r).checked = false; });
  });
  codes.forEach(function(c){
    $('fl-region-' + c).addEventListener('change', function(){
      if ($('fl-region-' + c).checked) all.checked = false;
      var any = codes.some(function(r){ return $('fl-region-' + r).checked; });
      if (!any) all.checked = true;
    });
  });
}
function collectForm(){
  if (!CFG) return null;
  var ipLines = [], domLines = [];
  String($('f-preferred').value).split(/[\n,;]+/).map(function(s){ return s.trim(); }).filter(Boolean).forEach(function(s){
    if (parseIps(s).length) ipLines.push(s); else domLines.push(s);
  });
  var ips = [], seen = {};
  ipLines.forEach(function(s){
    var p = parseIps(s);
    if (!p.length) return;
    var k = p[0].ip + ':' + (p[0].port || 443);
    if (seen[k]) return;
    seen[k] = 1;
    ips.push(p[0]);
  });
  return {
    uuid: $('a-uuid').value.trim(),
    path: $('a-path').value.trim() || $('a-uuid').value.trim(),
    subUrl: $('a-suburl').value.trim(),
    admin: $('a-admin').value,
    clearSecrets: [['a-cftoken','cfApiToken'],['s-outbound','outboundProxy'],['tp-pass','trojanPassword']].filter(function(p){return $(p[0]+'-clear')&&$(p[0]+'-clear').value==='1';}).map(function(p){return p[1];}),
    host: $('a-host').value.trim(),
    alpn: $('alpn').value,
    ech: $('ech-on').checked,
    echHost: $('ech-host').value.trim() || 'cloudflare-ech.com',
    echDns: $('ech-dns').value.trim(),
    tlsOnly: $('tls-only').checked,
    nodeLimit: $('q-nl-on').checked,
    nodeLimitCount: parseInt($('q-nl-count').value) || 300,
    polling: $('q-poll-on').checked,
    probeAlive: $('q-probe-on').checked,
    cfAccountId: $('a-cfid').value.trim(),
    cfApiToken: $('a-cftoken').value.trim(),
    quotaAuto: $('q-auto-on').checked,
    enableVless: $('en-vless').checked,
    enableTrojan: $('en-trojan').checked,
    trojanPassword: $('tp-pass').value,
    enableXhttp: $('en-xhttp').checked,
    proxyIP: $('s-proxyIP').value.trim(),
    outboundProxy: $('s-outbound').value.trim(),
    outboundMode: $('s-outmode').value,
    preferredDomains: domLines.join('\n'),
    preferredIPs: ips,
    optimizer: {
      source: $('o-source').value,
      sourceURL: $('o-sourceURL').value.trim(),
      port: parseInt($('o-port').value === 'custom' ? $('o-portC').value : $('o-port').value) || 443,
      threads: parseInt($('o-threads').value) || 5,
      count: parseInt($('o-count').value) || 20,
      fillCount: parseInt($('o-fill').value) || 0,
      useCidr: $('o-useCidr').checked,
      subMode: $('o-submode').value,
      subRandomCount: parseInt($('o-rand').value) || 16,
      subIncludeDefault: $('o-subinc').value === '1'
    },
    filter: {
      region: (function(){
        if ($('fl-region-all').checked) return ['all'];
        var a = [];
        ['HK', 'TW', 'US', 'SG', 'JP', 'KR', 'DE'].forEach(function(r){ if ($('fl-region-' + r).checked) a.push(r); });
        return a.length ? a : ['all'];
      })(),
      ipType: (function(){ var a = []; if ($('fl-ip4').checked) a.push('IPv4'); if ($('fl-ip6').checked) a.push('IPv6'); return a; })(),
      isp: (function(){ var a = []; if ($('fl-isp-m').checked) a.push('移动'); if ($('fl-isp-c').checked) a.push('联通'); if ($('fl-isp-t').checked) a.push('电信'); return a; })()
    },
    src: {
      native: $('fl-native').checked,
      prefDomain: $('fl-pref-domain').checked,
      prefIp: $('fl-pref-ip').checked,
      customPref: $('fl-custom-pref').checked
    }
  };
}
function saveAll(){
  if (!CFG){ toast('配置尚未加载', 'err'); return; }
  var body = collectForm();
  var btn = $('saveBtn');
  btn.disabled = true;
  api('config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    .then(function(r){
      if (r && r.ok){
        CFG = r.data;
        fillForm();
        renderAll();
        makeSub(false);
        refreshQuota();
        btn.classList.remove('dirty');
        $('savedAt').textContent = '已保存：' + new Date().toLocaleTimeString();
        toast(r.msg || '已保存', 'ok');
        if(r.next && r.next!==location.pathname){location.href=r.next;}
      } else toast((r && r.msg) || '保存失败', 'err');
    })
    .catch(function(){ toast('保存失败：无法连接服务器', 'err'); })
    .then(function(){ btn.disabled = false; });
}
function resetAll(){
  if (!confirm('确定重置普通配置？访问路径、UUID 和管理凭据会保留。')) return;
  var btn = $('resetBtn');
  btn.disabled = true;
  api('reset', { method: 'POST' })
    .then(function(r){
      if (r && r.ok){ toast(r.msg || '已重置', 'ok'); setTimeout(function(){ location.reload(); }, 900); }
      else toast((r && r.msg) || '重置失败', 'err');
    })
    .catch(function(){ toast('重置失败：无法连接服务器', 'err'); })
    .then(function(){ btn.disabled = false; });
}
function genUuid(){
  var u = '';
  if (window.crypto && crypto.randomUUID){ u = crypto.randomUUID(); }
  else { toast('当前浏览器不支持安全生成 UUID，请在 HTTPS 环境操作','err'); return; }
  $('a-uuid').value = u;
  markDirty();
  toast('已生成新 UUID', 'ok');
}
// 备份：把当前面板表单值收集成 JSON 下载（与保存配置同一套字段，恢复后可直接保存）
function exportConfig(){
  try {
    var data = collectForm();
    ['admin','trojanPassword','outboundProxy','cfApiToken','clearSecrets'].forEach(function(key){delete data[key];});
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    var ts = new Date();
    var pad = function(n){ return String(n).padStart(2, '0'); };
    a.download = 'cfnext-backup-' + ts.getFullYear() + pad(ts.getMonth()+1) + pad(ts.getDate()) + '-' + pad(ts.getHours()) + pad(ts.getMinutes()) + '.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
    toast('配置已导出（不含密码和出站凭据）', 'ok');
  } catch (e) { toast('导出失败：' + e.message, 'err'); }
}
// 恢复：读取 JSON 填充表单，标记未保存，由用户点「保存全部」写盘
function importConfig(input){
  var file = input.files && input.files[0];
  if (!file) return;
  if(file.size>131072){toast('配置文件不能超过 128 KB','err');return;}
  var reader = new FileReader();
  reader.onload = function(){
    try {
      var data = JSON.parse(reader.result);
      CFG = Object.assign({}, CFG, data);
      fillForm();
      renderAll();
      markDirty();
      toast('配置已导入，请点「保存全部」生效', 'ok');
    } catch (e) { toast('导入失败：JSON 格式不正确', 'err'); }
    input.value = '';
  };
  reader.readAsText(file, 'utf-8');
}
document.querySelectorAll('input,select,textarea').forEach(function(el){
  var id = el.id || '';
  var prefixes = ['f-', 'o-', 'a-', 's-', 'q-', 'e-', 't-', 'fl-', 'en-'];
  for (var i = 0; i < prefixes.length; i++){ if (id.indexOf(prefixes[i]) === 0){ el.addEventListener('change', markDirty); break; } }
});

/* ===== 订阅 ===== */
function subUrlOf(fmt){
  // 自定义订阅路径优先：自动保留当前域名（location.origin），只替换路径段；
  // 用户只填 UUID/别名段（如 AAZ），拼成 https://当前域名/AAZ/sub；留空用面板路径。
  // 填了 /sub 结尾或带前后斜杠时自动归一，格式后缀（clash/singbox 等）拼为 /sub/<格式>
  var custom = (window.CFG && CFG.subUrl) ? String(CFG.subUrl).trim().replace(/^\/+/, '').replace(/\/sub$/, '').replace(/\/+$/, '') : '';
  var base = custom ? (location.origin + '/' + custom) : (location.origin + APIPATH);
  var u = location.origin + '/s/' + encodeURIComponent(CFG.subToken) + '/sub';
  if(custom)u=base+'/sub';
  if(fmt)u+='/'+fmt;
  return custom ? u+'?token='+encodeURIComponent(CFG.subToken) : u;
}
function makeSub(showQR){
  var fmt = $('subFmt').value;
  var url = subUrlOf(fmt === 'auto' ? '' : fmt);
  $('subUrl').value = url;
  if (showQR) showQRCode(url);
}
$('subFmt').addEventListener('change', function(){ makeSub(false); });
function toggleQR(){
  var w = $('qrWrap');
  if (w.style.display === 'block'){ w.style.display = 'none'; return; }
  showQRCode($('subUrl').value || subUrlOf(''));
}
function showQRCode(url){
  var w = $('qrWrap');
  w.style.display = 'block';
  if (typeof qrcode === 'undefined'){ w.innerHTML = '<div class="hint">二维码库加载失败，请直接复制链接</div>'; return; }
  try {
    var fmt = ($('subFmt') && $('subFmt').value) || 'auto';
    var q = qrcode(0, 'M');
    q.addData(qrPayloadOf(fmt, url));
    q.make();
    w.innerHTML = '<div class="qrbox">' + q.createImgTag(4, 10) + '</div>';
  } catch(e) { w.innerHTML = '<div class="hint">二维码生成失败：' + e.message + '</div>'; }
}
// 二维码内容随订阅格式（客户端）联动：
// Clash/Mihomo、Stash → clash://install-config（FlyClash / Clash Verge / Stash 扫码装订阅，配置名取订阅响应头 filename=CFNext）
// Sing-box → sing-box://import-remote-profile?url=...#CFNext（官方 scheme，# 后为配置文件名称）
// Surge → surge:///install-config（Surge 官方 scheme）
// auto / v2rayN+Shadowrocket / Loon / Quantumult X / 明文 → 直接使用订阅链接（Shadowrocket / Loon / QuanX 扫码识别）
function qrPayloadOf(fmt, url){
  var enc = encodeURIComponent(url);
  if (fmt === 'clash' || fmt === 'stash') return 'clash://install-config?url=' + enc;
  if (fmt === 'singbox') return 'sing-box://import-remote-profile?url=' + enc + '#CFNext';
  if (fmt === 'surge') return 'surge:///install-config?url=' + enc;
  return url;
}
function downloadSub(){
  var fmt = $('subFmt').value;
  var a = document.createElement('a');
  a.href = subUrlOf(fmt === 'auto' ? '' : fmt);
  a.download = 'cfnext-sub.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
}
function previewSub(){
  var fmt = $('subFmt').value;
  var box = $('subPrev');
  box.style.display = 'block';
  $('prevType').textContent = '请求中…';
  $('prevCount').textContent = '—';
  $('prevBody').textContent = '';
  api('sub?fmt=' + encodeURIComponent(fmt === 'auto' ? '' : fmt))
    .then(function(r){
      if (!r || !r.ok){ $('prevType').textContent = '预览失败'; $('prevBody').textContent = (r && r.msg) || '未知错误'; return; }
      var body = r.body || '';
      var type = r.type || '';
      $('prevType').textContent = type || '—';
      var n = 0;
      if (/clash|yaml/i.test(type)) n = (body.match(/- name:/g) || []).length;
      else if (/json/i.test(type)) n = (body.match(/"tag"/g) || []).length;
      else {
        var t = body;
        if (!/^(vless|trojan|ss|xhttp):\/\//m.test(t)) {
          try { t = atob(t); } catch (e) { /* 保持原样 */ }
        }
        n = t.split('\n').filter(function(l){ return /^(vless|trojan|ss|xhttp):\/\//.test(l.trim()); }).length;
      }
      $('prevCount').textContent = n + ' 个节点';
      $('prevBody').textContent = body.length > 2600 ? body.slice(0, 2600) + '\n…（已截断，完整内容请下载）' : body;
    })
    .catch(function(){ $('prevType').textContent = '预览失败：无法连接服务器'; $('prevBody').textContent = ''; });
}

/* ===== 优选配置 ===== */
function onPortSel(){
  var sel = $('o-port');
  var c = $('o-portC');
  c.style.display = sel.value === 'custom' ? '' : 'none';
}
function onSubMode(){
  var m = $('o-submode').value;
  $('sm-custom').style.display = (m === 'custom') ? '' : 'none';
  $('sm-random').style.display = (m === 'random') ? '' : 'none';
  // 「追加内置优选池与默认地区源」仅在自定义订阅 / 随机优选模式下可选；
  // 订阅模式关闭（使用面板默认节点池）时强制为关闭并禁用，避免默认模式下误开追加导致行为不符
  if (m === '') {
    $('o-subinc').value = '0';
    $('o-subinc').disabled = true;
  } else {
    $('o-subinc').disabled = false;
  }
  // 订阅模式与仪表盘「地址来源」胶囊互斥同步（三态全部明确跟随）：
  // custom → 自定义优选开、随机优选关；random → 随机优选开、自定义优选关；关闭 → 两个胶囊都关
  if (m === 'custom') {
    $('fl-custom-pref').checked = true;
    $('fl-random-pref').checked = false;
  } else if (m === 'random') {
    $('fl-custom-pref').checked = false;
    $('fl-random-pref').checked = true;
  } else {
    $('fl-custom-pref').checked = false;
    $('fl-random-pref').checked = false;
  }
}
// 仪表盘「地址来源 → 自定义优选」与优选配置「订阅模式」联动：
// 勾选 → 订阅模式切为「自定义订阅（支持汇聚）」并关闭随机优选；取消 → 订阅模式关闭（使用面板默认节点池）
$('fl-custom-pref').addEventListener('change', function(){
  if (this.checked) {
    $('fl-random-pref').checked = false;   // 与随机优选互斥
    $('o-submode').value = 'custom';
  } else {
    if ($('o-submode').value === 'custom') $('o-submode').value = '';
  }
  onSubMode();
});
// 仪表盘「地址来源 → 随机优选」与优选配置「订阅模式 → 随机优选模式（官方接口）」联动：
// 勾选 → 订阅模式切为 random 并关闭自定义优选；取消 → 订阅模式关闭（若当前为 random）
$('fl-random-pref').addEventListener('change', function(){
  if (this.checked) {
    $('fl-custom-pref').checked = false;   // 与自定义优选互斥
    $('o-submode').value = 'random';
  } else {
    if ($('o-submode').value === 'random') $('o-submode').value = '';
  }
  onSubMode();
});
$('o-source').addEventListener('change', function(){
  $('o-customWrap').style.display = ($('o-source').value === 'custom') ? '' : 'none';
});
function pingIp(ip, port, timeout){
  var t0 = Date.now();
  var addr = ip.indexOf(':') >= 0 ? '[' + ip + ']' : ip;
  var proto = (port === 80 || port === 8080 || port === 8880 || port === 2052 || port === 2082 || port === 2086 || port === 2095) ? 'http' : 'https';
  var ctrl = new AbortController();
  var timer = setTimeout(function(){ ctrl.abort(); }, timeout);
  return fetch(proto + '://' + addr + ':' + port + '/', { mode: 'no-cors', cache: 'no-store', redirect: 'manual', signal: ctrl.signal })
    .then(function(){ clearTimeout(timer); return { ok: true, latency: Date.now() - t0 }; })
    .catch(function(){
      clearTimeout(timer);
      var ms = Date.now() - t0;
      if (proto === 'http' && ms < 100) return pingHttps(ip, port, timeout);
      return { ok: false, latency: -1 };
    });
}
function pingHttps(ip, port, timeout){
  var t0 = Date.now();
  var addr = ip.indexOf(':') >= 0 ? '[' + ip + ']' : ip;
  var ctrl = new AbortController();
  var timer = setTimeout(function(){ ctrl.abort(); }, timeout);
  return fetch('https://' + addr + ':' + port + '/', { mode: 'no-cors', cache: 'no-store', redirect: 'manual', signal: ctrl.signal })
    .then(function(){ clearTimeout(timer); return { ok: true, latency: Date.now() - t0 }; })
    .catch(function(){ clearTimeout(timer); var ms = Date.now() - t0; return { ok: false, latency: -1 }; });
}
function localTest(cands, threads, timeout){
  var results = [], idx = 0, pending = 0;
  threads=Math.max(1,Math.min(4,Number(threads)||4));
  if(!cands.length)return Promise.resolve([]);
  return new Promise(function(resolve){
    function next(){
      while (pending < threads && idx < cands.length) {
        (function(c){
          pending++;
          pingIp(c.ip, c.port, timeout).then(function(r){
            pending--;
            results.push({ ip: c.ip, port: c.port, ok: r.ok, latency: r.latency });
            if (results.length === cands.length) resolve(results);
            else next();
          });
        })(cands[idx++]);
      }
    }
    next();
  });
}
function runPick(){
  if (!CFG){ toast('配置尚未加载', 'err'); return; }
  var o = collectForm().optimizer;
  showMsg('oMsg', '正在拉取候选 IP…', 'info');
  api('candidates', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) })
    .then(function(r){
      if (!r || !r.ok){ showMsg('oMsg', (r && r.msg) || '拉取失败', 'err'); return; }
      var cands = r.data || [];
      if (!cands.length){ showMsg('oMsg', (r && r.msg) || '没有可测的 IP，请换一个数据源', 'err'); return; }
      var st = r.stats || {};
      var parts = [];
      if (st.preset) parts.push('预设源 ' + st.preset + ' 条');
      if (st.presetErr) parts.push('预设源失败(' + st.presetErr + ')');
      if (st.custom) parts.push('自定义源 ' + st.custom + ' 条');
      if (st.customErr) parts.push('自定义源失败(' + st.customErr + ')');
      if (st.cidr) parts.push('CF 补足 ' + st.cidr + ' 条');
      showMsg('oMsg', '拉取 ' + cands.length + ' 条（' + (parts.join('，') || '无') + '），本地测速中…', 'info');
      localTest(cands, o.threads || 5, 3000).then(function(results){
        results.sort(function(a, b){ return (a.latency < 0 ? 1e9 : a.latency) - (b.latency < 0 ? 1e9 : b.latency); });
        renderResults(results);
        var okc = results.filter(function(x){ return x.ok; }).length;
        showMsg('oMsg', '测速完成：' + okc + '/' + results.length + ' 可用（本地 → 目标）', okc ? 'ok' : 'err');
      });
    })
    .catch(function(){ showMsg('oMsg', '拉取失败：无法连接服务器', 'err'); });
}
function renderResults(list){
  var seen = {};
  var dedup = [];
  (list || []).forEach(function(r){
    if (seen[r.ip]) return;
    seen[r.ip] = 1;
    dedup.push(r);
  });
  LAST = dedup;
  var tb = $('oTableBody');
  tb.innerHTML = '';
  if (!LAST.length){ tb.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--faint)">没有可用结果</td></tr>'; return; }
  LAST.forEach(function(r, i){
    var tr = document.createElement('tr');
    var ok = r.ok;
    var lag = ok ? (r.latency + 'ms') : '—';
    var badge = '<span class="badge ' + (ok ? 'g' : 'r') + '">' + (ok ? 'HTTP 可达' : '失败/无法判定') + '</span>';
    var btn = ok ? '<button class="btn sm primary" onclick="useIp(' + i + ')">加入优选</button>' : '<span style="color:var(--faint)">—</span>';
    tr.innerHTML = '<td class="ip">' + r.ip + ':' + r.port + '</td><td>' + lag + '</td><td>' + badge + '</td><td>' + btn + '</td>';
    tb.appendChild(tr);
  });
}
function useIp(i){
  var r = LAST[i];
  if (!r) return;
  var ta = $('f-preferred');
  var line = r.ip + ':' + r.port + (r.name ? ('#' + r.name) : '');
  var exists = false;
  String(ta.value || '').split(/[\n,;]+/).forEach(function(s){
    var p = parseIps(s);
    if (p.length && p[0].ip === r.ip) exists = true;
  });
  if (exists){ toast('该 IP 已在优选列表中', 'warn'); return; }
  var s = ta.value.trim();
  ta.value = s ? (s + '\n' + line) : line;
  markDirty();
  toast('已加入优选列表，点击「保存全部」下发', 'ok');
}
function addAllBest(){
  var n = parseInt($('o-count').value) || 20;
  var seen = {};
  var list = [];
  LAST.filter(function(r){ return r.ok; }).forEach(function(r){
    if (seen[r.ip] || list.length >= n) return;
    seen[r.ip] = 1;
    list.push(r);
  });
  if (!list.length){ toast('没有可用结果', 'err'); return; }
  var arr = [];
  list.forEach(function(r, i){ arr.push(r.ip + ':' + r.port + '#优选' + (i + 1)); });
  $('f-preferred').value = arr.join('\n');
  markDirty();
  toast('已加入最快的 ' + list.length + ' 个优选 IP，点击「保存全部」下发', 'ok');
}
function fetchDomains(){
  api('domains').then(function(r){
    if (r && r.ok && r.data && r.data.length){ $('f-preferred').value = r.data.join('\n'); markDirty(); toast('已拉取优选域名', 'ok'); }
    else toast((r && r.msg) || '拉取失败', 'err');
  }).catch(function(){ toast('拉取失败：无法连接服务器', 'err'); });
}

/* ===== 启动 ===== */
buildNav();
var initView = 'dashboard';
try {
  var qv = new URLSearchParams(location.search).get('v');
  if (qv && TITLES[qv]) initView = qv;
} catch(e) {}
switchView(initView);
loadAll();
</script>
</body>
</html>

`;

// ---------------------------------------------------------------------------
// 登录页
// ---------------------------------------------------------------------------
const loginHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${THEME_SCRIPT}
<title>CFNext · 登录</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect x='3' y='3' width='18' height='18' rx='5' fill='%23f6821f'/%3E%3Cpath d='M8 15V9l8 6V9' stroke='%230d131b' stroke-width='2' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0b0f14;--card:#131a23;--border:#243041;--text:#e8eef6;--dim:#8fa3ba;--accent:#f6821f;--accent2:#ff9a3d;--accent-dim:rgba(246,130,31,.14);--err:#ff5c5c;--err-dim:rgba(255,92,92,.13)}
[data-theme="light"]{--bg:#f3f5f9;--card:#ffffff;--border:#dde4ee;--text:#1b2634;--dim:#5d6b7d;--accent:#e8720e;--accent2:#f6821f;--accent-dim:rgba(232,114,14,.10);--err:#d94848;--err-dim:rgba(217,72,72,.10)}
body{background:var(--bg);color:var(--text);font-family:"PingFang SC","Microsoft YaHei","Segoe UI",system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.box{width:340px;max-width:100%;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:30px 28px;box-shadow:0 18px 50px rgba(0,0,0,.25)}
[data-theme="light"] .box{box-shadow:0 14px 40px rgba(30,45,70,.10)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.mark{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center}
.mark svg{width:20px;height:20px}
.mark path{stroke:#0d131b}
.brand .bt{display:flex;flex-direction:column;line-height:1.25}
.brand .bt b{font-size:16px}
.brand .bt span{font-size:11.5px;color:var(--dim)}
h1{font-size:15px;margin-bottom:4px}
p{color:var(--dim);font-size:13px;margin-bottom:18px}
input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:10px 13px;font-size:14px;outline:none;margin-bottom:12px;font-family:inherit}
input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
button{width:100%;background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;color:#201308;border-radius:9px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{filter:brightness(1.06)}
button:disabled{opacity:.6;cursor:not-allowed}
.msg{color:var(--err);font-size:13px;margin-bottom:12px;display:none;background:var(--err-dim);padding:8px 12px;border-radius:8px}
.foot{margin-top:16px;text-align:center;font-size:11.5px;color:var(--dim)}
</style>
</head>
<body>
<div class="box">
  <div class="brand">
    <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h4l3-7 4 14 3-7h2"/></svg></div>
    <div class="bt"><b>CFNext</b><span>Cloudflare 全新代理管理面板</span></div>
  </div>
  <h1>登录</h1>
  <p>请输入管理密码以继续</p>
  <div class="msg" id="msg">密码错误，请重试</div>
  <form id="form">
    <input type="password" id="pwd" placeholder="管理密码" autofocus autocomplete="current-password">
    <button type="submit" id="btn">登录</button>
  </form>
  <div class="foot">登录会话 24 小时后过期；密码更改后需重新登录</div>
</div>
<script>
(function(){
  var next = new URLSearchParams(location.search).get('next') || '/';
  document.getElementById('form').addEventListener('submit', function(e){
    e.preventDefault();
    var btn = document.getElementById('btn');
    var msg = document.getElementById('msg');
    btn.disabled = true; msg.style.display = 'none';
    fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'password=' + encodeURIComponent(document.getElementById('pwd').value) + '&next=' + encodeURIComponent(next) })
      .then(function(r){ return r.json(); })
      .then(function(r){
        if (r && r.ok){ location.href = r.next || '/'; }
        else { msg.style.display = 'block'; btn.disabled = false; }
      })
      .catch(function(){ msg.textContent = '网络错误，请重试'; msg.style.display = 'block'; btn.disabled = false; });
  });
})();
</script>
</body>
</html>

`;

// ---------------------------------------------------------------------------
// 路由与调度
// ---------------------------------------------------------------------------
function isBrowserUA(ua) {
  // 任何包含 Mozilla 的 UA 视为浏览器；curl / ClashForAndroid / Sing-box 等客户端不含
  return (ua || '').toLowerCase().includes('mozilla');
}

async function requireAuth(request,cfg){
  if(!cfg.admin || !cfg._sessionKey)return false;
  const m=(request.headers.get('Cookie')||'').match(/(?:^|;\s*)luma_auth=([^;]+)/);
  if(!m)return false;
  const parts=m[1].split('.');
  if(parts.length!==3 || !/^\d{10}$/.test(parts[0]) || !isUUID(parts[1]) || !/^[a-f0-9]{64}$/.test(parts[2]))return false;
  const now=Math.floor(Date.now()/1000),expires=Number(parts[0]);
  if(expires<=now || expires>now+86400)return false;
  return constantEqual(parts[2],await sessionSignature(cfg,parts[0]+'.'+parts[1]));
}
const LOGIN_ATTEMPTS=new Map();
function sameOrigin(request){const origin=request.headers.get('Origin');return !origin || origin===new URL(request.url).origin;}
function safeNext(value,cfg){return value==='/' + cfg.path ? value : '/' + cfg.path;}
async function handleRequest(request,env){
  const url=new URL(request.url), path=url.pathname.replace(/^\/+|\/+$/g,''),segs=path.split('/');
  const UA=request.headers.get('User-Agent')||'';
  if(url.protocol==='http:')return Response.redirect(url.href.replace('http:','https:'),301);
  if(path==='version'&&request.method==='GET')return json({version:VERSION});
  if(path==='favicon.ico')return new Response(null,{status:204});
  if(!['GET','POST'].includes(request.method))return json({ok:false,msg:'请求方法不支持'},405);
  if(request.method==='POST'&&!sameOrigin(request))return json({ok:false,msg:'来源不匹配'},403);
  const cfg=await loadConfig(env);
  const isManagement=segs[0]===cfg.path;
  const authenticated=()=>requireAuth(request,cfg);
  if(path==='') {
    if(await authenticated())return Response.redirect(new URL('/'+cfg.path,url).href,302);
    return new Response('Not Found',{status:404,headers:{'Cache-Control':'no-store'}});
  }
  if(path==='login'){
    if(!cfg.admin)throw new AppError(503,'管理面板未启用，请设置 ADMIN Secret');
    if(request.method==='GET')return new Response(loginHTML,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer'}});
    const ip=request.headers.get('CF-Connecting-IP')||'unknown',now=Date.now();
    const attempt=LOGIN_ATTEMPTS.get(ip);
    if(attempt&&attempt.until>now&&attempt.count>=5)return json({ok:false,msg:'登录尝试过多，请稍后重试'},429);
    const state=attempt&&attempt.until>now?attempt:{count:0,until:now+60000};state.count++;boundedSet(LOGIN_ATTEMPTS,ip,state,256);
    const params=new URLSearchParams(TD.decode(await withTimeout(readBounded(request.body,4096),5000,'登录读取超时')));
    if(!constantEqual(params.get('password')||'',cfg.admin))return json({ok:false,msg:'密码错误'},403);
    LOGIN_ATTEMPTS.delete(ip);
    return new Response(JSON.stringify({ok:true,next:safeNext(params.get('next'),cfg)}),{headers:{'Content-Type':'application/json','Cache-Control':'no-store','Set-Cookie':'luma_auth='+await createSession(cfg)+'; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict'}});
  }
  const upgrade=(request.headers.get('Upgrade')||'').toLowerCase();
  if(isManagement&&segs.length===1&&upgrade==='websocket'){
    if(!cfg.enableVless&&!cfg.enableTrojan)throw new AppError(403,'WebSocket 协议已关闭');
    return handleWebSocketProxy(request,cfg);
  }
  if(isManagement&&segs.length===1&&request.method==='POST'){
    if(!cfg.enableXhttp)throw new AppError(403,'XHTTP 已关闭');
    return handleXhttpProxy(request,cfg);
  }
  const tokenRoute=segs[0]==='s'&&segs[2]==='sub'&&segs.length<=4;
  const aliasRoute=cfg.subUrl&&segs[0]===cfg.subUrl&&segs[1]==='sub'&&segs.length<=3;
  const panelSub=isManagement&&segs[1]==='sub'&&segs.length<=3;
  if(tokenRoute||aliasRoute||panelSub){
    if(request.method!=='GET')throw new AppError(405,'订阅仅支持 GET');
    const token=tokenRoute?segs[1]:url.searchParams.get('token')||'';
    if(!constantEqual(token,cfg.subToken)&&!(panelSub&&await authenticated()))throw new AppError(403,'订阅令牌无效');
    const format=tokenRoute?segs[3]||'':segs[2]||url.searchParams.get('format')||'';
    return subscriptionResponse(cfg,request,format,env);
  }
  if(isManagement&&segs.length===1&&request.method==='GET'){
    if(!cfg.admin)throw new AppError(503,'管理面板未启用，请设置 ADMIN Secret');
    if(!await authenticated())return Response.redirect(new URL('/login?next='+encodeURIComponent('/'+cfg.path),url).href,302);
    return new Response(PANEL_HTML,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"frame-ancestors 'none'; base-uri 'none'"}});
  }
  if(!isManagement||segs[1]!=='api'||segs.length!==3)return new Response('Not Found',{status:404});
  if(!await authenticated())throw new AppError(403,'未授权（需要管理密码）');
  const api=segs[2];
  if(!['config','reset','candidates'].includes(api)&&request.method!=='GET')throw new AppError(405,'仅支持 GET');
  if(api==='config'){
    if(request.method==='GET')return json({ok:true,data:publicConfig(cfg,env)});
    if(!/^application\/json(?:;|$)/i.test(request.headers.get('Content-Type')||''))throw new AppError(415,'需要 application/json');
    const body=await readRequestJson(request);
    if(!body||typeof body!=='object'||Array.isArray(body))throw new AppError(400,'配置格式错误');
    const merged={...cfg};
    const allowed=new Set([...Object.keys(DEFAULT_CONFIG),'subUrl','src']);
    const locked=publicConfig(cfg,env).lockedFields;
    for(const [key,value] of Object.entries(body)){
      if(!allowed.has(key)||locked.includes(key))continue;
      if(PRIVATE_FIELDS.includes(key)&&value==='')continue;
      merged[key]=value;
    }
    if(body.clearSecrets){
      if(!Array.isArray(body.clearSecrets))throw new AppError(400,'clearSecrets 格式错误');
      for(const key of body.clearSecrets){if(!PRIVATE_FIELDS.includes(key)||locked.includes(key)||key==='admin')throw new AppError(400,'该凭据不能在面板清空');merged[key]='';}
    }
    merged.optimizer={...cfg.optimizer,...(body.optimizer||{})};
    if(body.optimizer&&typeof body.optimizer!=='object')throw new AppError(400,'优选配置错误');
    if(merged.admin&&merged.admin.length<8)throw new AppError(400,'管理密码至少需要 8 个字符');
    await saveConfig(env,merged);
    const fresh=await loadConfig(env);
    return json({ok:true,data:publicConfig(fresh,env),msg:'配置已保存；其他地区可能稍后更新',next:'/'+fresh.path});
  }
  if(api==='reset'){
    if(request.method!=='POST')throw new AppError(405,'仅支持 POST');
    // Reset only ordinary settings. Authentication and routing must survive the reset.
    const reset={...JSON.parse(JSON.stringify(DEFAULT_CONFIG))};
    for(const key of ['uuid','path','admin','trojanPassword','outboundProxy','cfApiToken','cfAccountId','subUrl'])reset[key]=cfg[key];
    await saveConfig(env,reset);
    return json({ok:true,msg:'普通配置已重置，访问凭据和路径保留'});
  }
  if(api==='status')return json({ok:true,data:{version:VERSION,kind:'明文版',host:url.hostname,path:cfg.path,region:request.cf?.colo||'unknown',kv:!!env.K,workersDev:/\.workers\.dev$/i.test(url.hostname),scheduledSupported:false}});
  if(api==='update')return json({ok:true,data:await checkUpdate(env)});
  if(api==='quota')return json({ok:true,data:await getQuota(env,cfg)});
  if(api==='sub'){
    const sub=await generateSubscription(cfg,request.url,url.searchParams.get('fmt')||'',UA,request.cf?.colo,env);
    return json({ok:true,type:sub.type,body:sub.body});
  }
  if(api==='candidates'){
    if(request.method!=='POST')throw new AppError(405,'仅支持 POST');
    const body=await readRequestJson(request,32768);
    const cand=await collectCandidates({...cfg.optimizer,...body,_io:cfg._io});
    return json({ok:true,data:cand.candidates,stats:cand.stats});
  }
  if(api==='domains'){
    const src=OPTIMIZE_SOURCES[url.searchParams.get('source')||'wetest_cname']||OPTIMIZE_SOURCES.wetest_cname;
    const res=await fetchTimeout(src.url,{},6000,cfg._io);
    if(!res||!res.ok)throw new AppError(502,'域名来源暂不可用');
    return json({ok:true,data:extractDomains(await res.text()).slice(0,24)});
  }
  throw new AppError(404,'未知接口');
}
async function subscriptionResponse(cfg,request,format,env){
  if(cfg.polling)cfg._rotationSeed=cfg.configVersion+'|'+Math.floor(Date.now()/900000)+'|'+(request.headers.get('User-Agent')||'');
  // Quota is advisory. Only a recent snapshot can reduce output; never block a subscription on Analytics.
  if(cfg.quotaAuto&&QUOTA_CACHE&&Date.now()-QUOTA_CACHE.at<QUOTA_TTL&&QUOTA_CACHE.accountId===cfg.cfAccountId && QUOTA_CACHE.data?.updatedAt?.slice(0,10)===new Date().toISOString().slice(0,10)){
    const q=QUOTA_CACHE.data;
    if(q?.today&&q.percent>=60)cfg._quotaCap=Math.max(20,Math.round(300*Math.max(0.1,(1-q.percent/100)/0.4)));
  }
  const sub=await generateSubscription(cfg,request.url,format,request.headers.get('User-Agent')||'',request.cf?.colo,env);
  return new Response(sub.body,{headers:{'Content-Type':sub.type+'; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Disposition':'attachment; filename="CFNext"'}});
}

// 定时自动优选：拉取候选 → 测速 → 取最优写入优选节点
async function handleScheduled() {
  // Pages has no Cron trigger. Edge TCP measurements of CF addresses do not measure client reachability.
  console.warn(JSON.stringify({event:'scheduled_disabled',reason:'use_client_side_measurements'}));
}

export default {
  async fetch(request, env, ctx) {
    const started=Date.now(),io=createIO();
    try { return await handleRequest(request,{...env,_ctx:ctx,_io:io}); }
    catch(error){
      const status=error instanceof AppError?error.status:500;
      console.warn(JSON.stringify({event:'request_failed',status,method:request.method,externalRequests:io.used,upstreamFailures:io.failures,durationMs:Date.now()-started}));
      return json({ok:false,status,msg:error instanceof AppError?error.message:'请求处理失败，请检查服务日志'},status);
    }
  },
  async scheduled(){return handleScheduled();}
};
