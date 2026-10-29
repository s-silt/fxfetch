# Chrome 连接前隔离设计草案

状态：设计/本机合成 POC，**不构成生产放行**。现有 `browser_guard_unavailable` 保持；此文件不授权访问任何目标。

## 已验证与未验证分开

- `windows_browser_sandbox.probe_chrome` 仅允许自身固定 `about:blank` 诊断参数，不提供租约、不连接采集服务。
- 本机以非管理员令牌成功调用 `CreateAppContainerProfile`、`CreateProcessW` + `STARTUPINFOEX / PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`。实际子进程令牌查询为 `TokenIsAppContainer=true`、`TokenCapabilities=0`；固定本机命令通过显式继承匿名 pipe 返回内容；受 Job Object 约束并清理临时 AppContainer。
- 本机已安装签名有效的 Chrome 156.0.8078.48。在无网络能力 AppContainer 内，无论可写 profile、只读 profile，或复制本机安装目录，均在 CDP 响应前于 `chrome_elf.dll` 异常退出，代码 `0x80000003`。一次关闭 Chrome 内部 sandbox 的诊断也未改变结果，不能据此引入关闭 sandbox 的生产配置。
- 这证明本机该版本 Chrome 的 lowbox 启动存在兼容性阻挡；不是“已经有网络隔离的可用 Chrome”。也未证明只读 profile 能支持完整运行。未访问真实目标；私有结果在 `.runtime/browser-appcontainer-poc/`。

## 首选轻量路线：零网络能力 AppContainer + brokered_chrome

1. Chrome 及所有后代自启动时处于没有 `internetClient`、`internetClientServer`、`privateNetworkClientServer` 的 AppContainer。绝不授予 loopback exemption。用实际 token 验证，不以布尔配置代替。
2. Chrome 不开 TCP 调试端口。父进程显式继承两个匿名 pipe；Windows Chrome 接收 `--remote-debugging-pipe` 和 `--remote-debugging-io-pipes=readHandle,writeHandle`。对 Playwright 可提供父端本机 CDP bridge；bridge 只连接 inherited pipe，不能成为 Chrome 的网络出口。
3. 浏览器请求在发送前暂停，由父端 Python 受控客户端携带对应 method、原始 URL、Cookie、Referer 及必要请求头发送一次。逐跳执行当前公网 DNS、固定 IP、TLS 和大小/时间/数量预算，不重新消费入口，不使用系统 Fake-IP 做归因。
4. 小型 HTML/JS/API 响应先有界保存，再 fulfill。必须保留多值 Set-Cookie、跳转/Origin/CORS、缓存和状态语义；不能用独立 CookieJar 冒充浏览器会话。若只支持 GET，遇到 POST 必须明确 partial/unsupported，不能换成 GET 或丢请求体。
5. 发现 APK/IPA 流后直接在 Python 有界流式保存/校验，浏览器该请求终止；不得把大包整体 base64 fulfill 回浏览器。原生浏览器下载设置 deny，不能 `save_as` 后才测大小。
6. Service Worker 明确禁用；WebSocket 需要独立转发并共享预算，不支持时明确缺口。DNS、WebRTC/STUN/TURN、WebTransport、QUIC、预连接和后台请求不能依赖 route 拦截，必须由零网络能力边界拒绝，并以合成 TCP/TLS/UDP 计数和 OS 证据验收。
7. 证据模式写 `brokered_chrome`。TLS 由 Python 客户端而非 Chrome 与目标协商，不能声称原生 Chrome 网络栈、证书连接 IP 或完整原设备等价。仍需保持同一 Chrome 进程完成人工处理。

**剩余阻挡**：本机 Chrome lowbox loader 启动失败；以及 profile/IndexedDB/Cache/OPFS 的硬写盘限制。AppContainer 本身不限制 profile 容量；fulfill 输入限量和磁盘大小巡检不能代替硬限制。

## 可实施的管理员后备路线：独立 Chrome 副本 + WFP + 有界文件系统

- 只复制本机已安装签名 Chrome，锁定可执行文件及依赖清单/哈希；不下载浏览器、不改用户日常 Chrome、不修改系统代理。所有可能启动的辅助 EXE 也要纳入策略或被禁止启动；不能只保护主 browser PID。
- WFP 在 `ALE_AUTH_CONNECT_V4/V6` 按副本应用 ID/受控身份拒绝连接；native-CONNECT 模式唯一允许的出口为专用 broker 的精确 loopback TCP 地址/端口。明确覆盖其他 loopback 端口、所有 IPv6、UDP、QUIC、STUN/TURN、mDNS/LLMNR；不得用“Block Any + Allow broker”期望例外胜出。
- 独立 broker 严格校验 HTTP absolute-form、Host、CONNECT authority，拒绝凭据混淆、特殊协议与私有/特殊 IP。DNS 仅用服务既定公共解析器，锁定实际 IP；CONNECT 可沿既定本地代理建立到已验证 IP 的隧道，Chrome 保留证书校验。不装根证书，不 TLS MITM。broker 对整个 TLS 隧道实施保守 wire-byte/并发/时间预算，CDP 对逻辑响应另计预算；不能声称隧道内完整 HTTP 计数。
- 警惕 DNS Client 服务等委托网络请求：程序路径规则只约束 Chrome socket，不能未经实测就宣称阻断所有代理服务的出站。禁用浏览器隐式 DNS/代理发现只是减面措施；合成捕获仍须证明无泄漏。
- Chrome 所有可写路径、TEMP/TMP、profile、缓存、native download 均进入固定容量专用 VHD/VHDX 或等价硬限制文件系统。禁止把 writable AppContainer package 存储或用户 LocalAppData 留在外部。单独明确总任务预算与其他 Python 输出预留，容量阈值由真实文件写入失败证明，不能以目录巡检代替。
- 固定容量卷的创建/挂载及 WFP 规则安装需要管理员上下文；当前服务非管理员。安装动作只能作用于项目独立副本/新建私有虚拟盘，必须生成精确 rollback 清单，不改全机默认入站/出站策略，不修改已有用户规则。
- 防护对象与 Chrome Job Object 生命周期绑定。策略消失时先终止 Chrome；仅“dynamic WFP session close 自动删规则”会存在保护先消失、Chrome 后存活的 fail-open 窗口，不能据此放行。策略移除前必须确认进程树已退出。

## 放行票据与验收

`GuardedBrowserLease` 由后端守卫签发并实时验证，至少绑定：模式、实际 executable/hash、profile/download 根、进程树身份、无网络能力 token 或实际 WFP 策略指纹、broker 身份、卷标识/硬容量、任务 ID、发放/过期时间。无有效租约时首次导航前失败。不可从 HTTP 参数、可编辑 JSON 或测试替身布尔值创建生产票据。

验收必须覆盖：IPv4/IPv6 literal、混合 DNS/重绑定、HTTP/JS/meta 跳转到私网、iframe/OOPIF/popup/worker、新 WebSocket、Service Worker、预连接、WebRTC/STUN/TURN、UDP/QUIC、DNS、其他 loopback 端口。被拒目标的 TCP/TLS/HTTP 或 UDP 计数为零；同一副本正常 broker 路线仍能访问合成允许端点。功能靶场的回环放行只存在测试传输注入，不进生产配置。

磁盘验收应主动写满临时卷，确认跨 profile、cache、download、JS 存储均在硬边界内失败，任务 failed 且不登记部分产物。确认停止/超时/服务崩溃/守卫退出时全部 Chrome 后代消失，下一任务可运行，用户现有 Chrome 和网络配置不受影响。全部通过前不标 enabled。

## 官方依据

- [Microsoft: Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Microsoft: UWP network capability and firewall diagnostics](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)
- [Microsoft: ALE connect filtering before TCP connect / UDP send](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- [Microsoft: WFP loopback condition](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-flags-)
- [Chromium: proxy rules and implicit localhost/link-local bypass](https://github.com/chromium/chromium/blob/main/net/docs/proxy.md)
- [Chromium: Windows inherited debugging pipe implementation](https://chromium.googlesource.com/chromium/src/+/refs/tags/136.0.7102.0/content/browser/devtools/devtools_agent_host_impl.cc)
- [Playwright: Service Worker requests may be absent from route interception](https://playwright.dev/docs/service-workers)
- [Microsoft: DiskPart virtual disk operations](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskpart)
