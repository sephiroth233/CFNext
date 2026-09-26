# CFNext 2.0.2

Cloudflare Workers / Pages 单文件代理与订阅管理面板。仓库主脚本为 `workers.js`，保留 VLESS over WebSocket、Trojan over WebSocket、VLESS XHTTP，以及 SOCKS5、HTTP/HTTPS CONNECT、Shadowsocks AEAD 出站。当前实现仅转发 TCP；客户端应使用本地 DNS 或 DoH，不支持通用 UDP 转发。

本次修复对应已有的 **Pages 项目 `cfnext`**。2.0.1 已于 2026-09-26 发布到生产环境，发布记录见文末。

## 2.0.2 主题行为

登录页与管理面板默认跟随系统的浅色/深色设置，并在系统主题变化时自动更新。主题在页面首次绘制前初始化，避免先显示深色再切换。管理面板右上角按钮按「跟随系统 → 日间 → 夜间 → 跟随系统」循环；手动选择保存在当前浏览器，登录页与其他同站标签页同步。已有手动偏好继续保留，可通过按钮恢复跟随系统。

## 从 2.0 升级

1. 保留线上原有配置备份和可回滚的部署。在预览环境使用独立 KV，避免预览保存操作修改生产配置。
2. 设置有效的 `U`（UUID）和 `ADMIN` Secret。未设置管理密码时管理面板关闭；KV 读取异常返回 503，不会降级成免登录。
3. 打开 `/login` 登录，或访问 `/<D>`（未配置 D 时为 `/<UUID>`）。根路径对未登录访问返回 404，避免泄露管理路径。
4. **重新复制订阅地址**。新默认地址为 `/s/<订阅令牌>/sub`，指定格式例如 `/s/<令牌>/sub/clash`。别名地址为 `/<别名>/sub?token=<令牌>`。旧的无令牌公开订阅地址已关闭；已登录管理者仍可使用原管理路径下的订阅。
5. 旧 Cookie 不再有效。新会话通过 HMAC 签名，服务端验证 24 小时有效期；变更管理密码或会话密钥会使旧会话失效。跨地区生效仍受 KV 一致性影响，紧急撤销应通过 Secret 更新和重新部署完成。
6. 若使用 Surfboard，先启用 Trojan。转换使用实际 Trojan 密码，未配置独立密码时使用 UUID。所有客户端配置恢复 TLS 证书验证，需要正确的部署域名与有效证书。

`SUB_TOKEN` 未配置时由 UUID 派生。需要让订阅令牌与代理 UUID 独立轮换时，显式配置随机 `SUB_TOKEN`。拿到订阅的人能获取代理凭据，订阅地址应按凭据保管。

## 部署

### Pages（现有项目使用的方式）

Pages Advanced mode 的入口必须叫 **`_worker.js`**。仓库仍保留 `workers.js`；发布时在仓库外建立临时目录并复制，避免混入第二份源代码。

```sh
stage_dir=$(mktemp -d /tmp/cfnext-pages.XXXXXX)
cp workers.js "$stage_dir/_worker.js"
# 以下命令会发布预览部署，需已登录 Wrangler，并准备好预览环境绑定。
npx wrangler pages deploy "$stage_dir" --project-name cfnext --branch repair-2-0-1
```

在 Pages 项目设置中分别配置 Production / Preview 的环境变量、Secrets 与 KV `K`。生产部署应在预览验收后再发布到项目的生产分支。Pages Advanced mode 接管请求路由；本脚本没有静态资源兜底。Pages 不提供本脚本所需的 Cron Trigger，旧 `BESTIP_AUTO` 定时优选已停用。[Pages Advanced mode 官方说明](https://developers.cloudflare.com/pages/functions/advanced-mode/)

### Workers

使用模块 Worker，把入口指向 `workers.js`，配置相同绑定即可。无需 Node.js 兼容标志。脚本虽保留 `scheduled` 入口用于输出停用提示，但不执行定时优选；不要依赖旧定时任务更新节点。

本次本地 workerd 验证使用 compatibility date `2026-08-01`。生产应明确设置兼容日期，并在更改日期时重新验证协议行为。

## 环境变量与绑定

优先级为 **默认值 < KV 已保存配置 < 显式环境变量**。Secret 建议在 Cloudflare 控制台设置，不放入 Git。

| 名称 | 用途 |
| --- | --- |
| `U` | 代理 UUID；首次部署必需，也可以读取已有 KV 中的有效 UUID |
| `ADMIN` | 管理密码，建议随机且至少 12 字符；也兼容旧 `admin` 名称 |
| `D` / `PATH` | 管理与代理路径，单个路径段；默认 UUID。优先使用 `D`，不要同时设置冲突的别名 |
| `K` | KV Namespace 绑定；不绑定时可以运行环境变量配置，但面板保存明确返回失败 |
| `SUB_TOKEN` | 可选独立订阅令牌，32–128 位字母、数字、下划线或连字符 |
| `SESSION_SECRET` | 可选会话签名密钥，默认使用管理密码 |
| `HOST` | 订阅中的 SNI/Host，默认当前访问域名；不负责添加 DNS 或 Cloudflare 域名绑定 |
| `TROJAN` / `TROJAN_PASSWORD` | 启用 Trojan（`true` / `1`）及独立密码；密码留空使用 UUID |
| `S` / `OUTBOUND` | 出站地址，支持 `socks5://`、`http://`、`https://`、`ss://` |
| `PROXYIP` | 自定义透明中继地址，可带端口；IPv6 带端口时使用方括号 |
| `PROBE_ALIVE` | `0` 强制关闭云端测活（默认关闭），`1` 开启有限探测 |
| `YX` / `YXURL` | 优选 IP 列表 / 优选器自定义来源 URL |
| `ECH` / `ALPN` | 保留原有客户端参数；具体支持情况取决于客户端版本 |
| `CF_ACCOUNT_ID` / `CF_API_TOKEN` | 可选 Analytics 查询配置；令牌需要对应账户分析读取权限 |
| `UPDATE_REPO` | 可选更新检查仓库，格式 `owner/repo`；默认关闭，无自动安装 |
| `UPDATE_BRANCH` / `UPDATE_FILE` | 更新检查分支与路径，默认 `main` / `workers.js` |
| `RELAY_EXIT_PROBE` | 兼容旧名称；`0` 仅关闭节点名称中的来源地点后缀，不是出口 IP 验证开关 |

环境变量覆盖的核心凭据在面板中锁定。密码、Trojan 密码、出站凭据和 API 令牌不回传明文；留空保存代表保留，清空必须勾选专门选项。环境变量中的凭据需要在 Cloudflare 设置中修改。

配置导出不包含上述敏感字段或订阅令牌，但**仍包含 UUID 和管理路径**，请妥善保管。迁移后需要重新设置未导出的 Secrets。重置仅恢复普通选项，保留 UUID、路径及已保存的访问凭据。

## 修复内容

- 代理在建立出站连接前验证 VLESS UUID / Trojan 密码和协议开关；处理拆包、截断头、WebSocket Early Data 与非法命令。
- 管理 API 使用有效期签名会话，拒绝跨来源写入；KV 失败关闭访问，未绑定 KV 不再虚报保存成功。
- Shadowsocks 恢复标准 EVP_BytesToKey、按密钥长度生成 salt、HKDF-SHA1、从零递增的小端 nonce、目标地址首帧和最大 16383 字节分片。三种算法与独立实现交叉验证。
- HTTPS CONNECT 实际使用 TLS；SOCKS5 / HTTP 握手有超时、长度校验和残留数据保留，IPv6 编码正确。连接失败、取消和晚到连接会清理资源。
- WebSocket 上行串行写入，有握手时限、队列字节上限和写入超时；XHTTP 下行按需读取、处理取消并释放资源。
- 外部数据获取统一预算：每请求最多 40 次 fetch、4 并发、单响应 1 MiB、获取总窗口 20 秒。重定向也计数；外部失败时可使用现有候选或有限期旧缓存。
- 默认 13 个域名的双栈 DNS 在首选解析器成功时为 26 次查询，备用解析器顺序调用，缓存区分 IPv4 / IPv6。
- 订阅不再写 KV `issued`；轮换使用配置版本、客户端标识和 15 分钟窗口。结构化格式最多 300 条，明文最多 800 条，再与自定义上限取小值。
- 浏览器测速网络错误不再被判作成功；HTTP 可达仅是辅助信息，不代表代理协议可用。更新来源显式配置，不再指向旧脚本路径。

## Cloudflare 资源注意事项

以下依据 2026-09-26 查阅的官方文档，套餐调整后应以控制台和官方文档为准。

| 资源 | 当前免费计划约束与脚本处理 |
| --- | --- |
| 请求量 | Workers 与 Pages Functions 共享每日 100,000 次，UTC 0 点重置。缩减节点数不会减少入口请求次数 |
| CPU | 免费计划每请求 10 ms；等待网络不计 CPU。限制节点数不能保证永不触发 1102，特别是纯 JS ChaCha20 长流和大文本解析 |
| 内存 | 每 isolate 128 MB，多请求共享。单请求字节上限不能替代总并发容量测试 |
| 子请求 | 免费计划外部请求上限 50；脚本为受控 fetch 留出余量。付费计划规则不同，不能继续套用旧的统一 1000 次结论 |
| 连接 | 平台最多 6 个同时等待初始响应的连接；脚本外部抓取最多 4 并发 |
| KV | 免费每日 100,000 次读、1,000 次写；单键每秒最多 1 次写。`cacheTtl` 命中也算一次 KV get 操作；本地 5 秒缓存只能减少同实例重复读取 |

来源：[Workers limits](https://developers.cloudflare.com/workers/platform/limits/)、[Pages Functions pricing](https://developers.cloudflare.com/pages/functions/pricing/)、[KV limits](https://developers.cloudflare.com/kv/platform/limits/)、[KV pricing](https://developers.cloudflare.com/kv/platform/pricing/)。

KV 是最终一致存储。保存后更新当前实例的缓存，但其他地区可能继续读到旧配置；频繁保存同一个 key 也可能受写限流影响。[KV 读取及缓存行为](https://developers.cloudflare.com/kv/api/read-key-value-pairs/)

Cloudflare 禁止 TCP sockets 直连 Cloudflare IP 段。因此云端跳过这类地址的 TCP 探测，不代表它们已经通过连通性测试；客户端网络下的代理握手与实际下载才是验收依据。内置第三方优选源、域名和透明中继有可用性与信任边界，建议使用自己控制的出站。`only` 模式失败即终止，不会回退直连。[TCP sockets 官方限制](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)

用量监控是可选辅助功能：5 分钟成功缓存、错误短缓存、429 退避。显示 Analytics 请求估算和 Workers CPU P50，不是账单或 CPU 总时长。自动调节只使用当前实例最近的有效快照；面板不查询时可能没有快照，也不能提供账户级硬限流。登录尝试限制同样只在当前实例内生效；需要统一保护时应使用 Cloudflare 可用的边缘规则或独立状态服务。

## 验证与发布验收

可重复执行的测试收录在 [REPAIR_TESTS.md](REPAIR_TESTS.md)，依赖、测试文件与 Pages 临时入口均在 `/tmp`，仓库保持单主脚本。

已完成：29 项功能/安全检查、5 组独立协议测试、11 项 workerd 检查，以及浏览器登录、保存、订阅预览验证。外部来源使用测试替身，测试未携带生产凭据。

尚需在预览部署验证：真实客户端的 VLESS/Trojan/XHTTP 双向流、真实出站代理握手、长连接取消、慢客户端、高并发 CPU/内存与错误率、各客户端配置解析及 Analytics 账户权限/字段兼容。生产发布后的基础 HTTP 检查已经通过；这些真实代理链路和容量场景仍未由本次验收覆盖。

发布前应确认新订阅可以导入、错 UUID/密码无法转发、管理接口未登录返回拒绝、KV 故障不会开放权限，以及 Metrics 中没有持续 1101 / 1102 / 子请求超限。Git 保留修复前基线和修复提交；Cloudflare 保留上一版本部署用于发布后回滚。

## 2.0.1 生产发布记录

- 发布时间：2026-09-26 11:27（Asia/Shanghai）。
- 平台及项目：Cloudflare Pages / `cfnext`，生产分支 `main`，Direct Upload。
- 线上地址：[登录页](https://cfnext-5p4.pages.dev/login)、[版本接口](https://cfnext-5p4.pages.dev/version)。
- 生产部署：`293029a6-c191-4b16-b93f-752e0776b7b8`，控制台状态 `success`。
- 发布源码：Git 提交 `42d0d2b` 中的 `workers.js`，打包时命名为 `_worker.js`。
- 脚本 SHA-256：`7ba1e2cdc0bc6a67a9b0b4dde684712908cb5d32a95e6b1b4c87117762a2f4ec`。
- 沿用生产环境的 `U`、`ADMIN` Secrets、KV `K` 绑定及兼容日期 `2026-09-25`；没有写入或重置生产 KV 配置。
- 回滚版本：`0488c9d4-4aa4-4283-9964-13fed71c1a51`，可在 Pages 部署列表中回滚。

线上基础检查：`GET /version` 返回 200 与 `2.0.1`；`GET /login` 返回 200；未登录 `GET /` 返回 404；无效订阅令牌和错误登录密码均返回 403。检查使用普通浏览器 User-Agent，未获取生产密码或 UUID，未验证登录后的真实代理流量。
