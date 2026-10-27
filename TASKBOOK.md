# fxfetch 开发任务书

本文件是**给执行 agent（本地 Codex）的实施任务书**。边界见 [AGENTS.md](AGENTS.md)，定位见 [README.md](README.md)。

执行环境：Windows + Python 3.11+，本机已装 Chrome。配套 fxapk 以可编辑方式安装在同一环境。

## 1. 目标

操作者把一个分发链接粘进窗口、点一次「下载」，后台自动：识别链接形态 → 按 Android 与 iPhone 两种设备身份各走一遍 → 跟完跳转与挑战 → 取回 APK / IPA → 算哈希、留逐跳证据 →（可选）调 fxapk 分析。

卡住时才需要人：自动过不去的挑战弹出可见浏览器窗口，操作者手点一下，程序接着跑完。

## 2. 为什么不能只做「取页面 + 正则找 .apk」

涉诈分发链接普遍挂在**前置过滤层**（俗称「防红」）后面，常见形态如下。设计必须按这些形态来，否则拿到的只是空壳页：

| 形态 | 对下载器的要求 |
| --- | --- |
| 入口 URL 带加密参数，先 302 到一个换取凭据的路径，再回落地页 | 逐跳跟随，保留 Cookie 与会话 |
| 下发的会话 Cookie 与**客户端出口 IP** 绑定 | 全程同一出口、同一会话；中途换代理或换网络即失效 |
| 按 UA / 设备类型分流：移动端给真页，桌面端或爬虫给空壳、验证码或错误码 | 用移动端 UA，且 Android 与 iPhone 分别取 |
| 入口限定在社交 App 内置浏览器中打开 | UA 需覆盖常见移动端浏览器形态；拿不到时如实记 `blocked`，不猜 |
| 页面靠 JS 渲染，或要点一下按钮才出下载地址 | 需要真浏览器执行 JS，纯 `requests` 取不到 |
| 字符 / 滑块验证码 | 有限次本地自动识别，失败转人工 |
| 通过验证后由前置层**反向代理**到真实源站，页面上看不到源站地址 | 逐跳记录实连 IP 与证书，源站与前置层分开记 |
| 入口参数带时效，过期即失效 | 拿到链接立即走完全程，不隔轮重试 |

**后果铁律**：以上任何一环没过去，结果都是 `blocked`（内容未知），不是 `not_found`。把 `blocked` 报成「没有包」会直接误导侦查方向。

## 3. 架构

```
src/fxfetch/
  cli.py          # 命令行入口（fxfetch <url>）
  core/
    classify.py   # 链接形态识别（纯离线，不发请求）
    session.py    # 统一会话：Cookie、UA 画像、出口一致性、逐跳记录
    http_mode.py  # 静态模式：requests 逐跳，不执行 JS
    browser.py    # 浏览器模式：CDP 驱动本机 Chrome
    download.py   # 流式下载 + SHA-256 + 大小上限 + 文件名安全
    guard.py      # SSRF / 实连 peer / 重定向判据（见 3.2）
    manifest.py   # itms-services / manifest.plist / .mobileconfig 解析
    evidence.py   # evidence.json 写出（逐跳、哈希、时间、状态）
    challenge.py  # 挑战识别与自动通过（见 4.3）
  gui/app.py      # Tkinter 窗口
tests/
  range/          # 本地防红靶场（见 7.1）
```

### 3.1 与 fxapk 的关系

- fxfetch **不** import fxapk 的私有模块。两边都要的 SSRF 判据在 fxapk 侧提升为公开 API 后由 fxfetch 调用；在它提升之前，fxfetch 的 `guard.py` 自带等价实现，并在注释里标明「与 fxapk `config/fetch.py` 同口径，改一处要同步」。
- 分析调用只走子进程命令行：`fxapk analyze <file> --out <dir>`。不在进程内 import fxapk。
- fxapk 侧的 `fetch-ipa` 命令是 CLI 用户的最小路径；fxfetch 是带浏览器与界面的完整路径。两者口径（状态四分、留证字段名）必须一致。

### 3.2 安全判据（`guard.py`，每一跳都要重跑）

- URL 预解析：host 的**全部**解析地址都须是公网地址，任一落私有 / 回环 / 链路本地 / 保留 / 多播段即拒；IPv6 内嵌的 IPv4（v4-mapped / NAT64 / 6to4 / Teredo）一并按公网判。
- 连接层：TCP 建连后、TLS 与 HTTP 发出**之前**校验实际 peer IP，堵 DNS rebinding。
- 不隐式跟随重定向：逐跳显式发起，跳数上限 10。
- 忽略环境代理与 `.netrc`，确保校验的是目标服务的实连 peer（需要专用出口时由操作者在系统网络层安排，不在程序内配代理）。
- 浏览器模式下 Chrome 自己会跟随跳转，无法逐跳拦截 → 用 CDP 的 `Network.responseReceived` 取每个响应的 `remoteIPAddress` 与 `securityDetails` **事后**核验，发现非公网地址即中止会话并记录。两种模式的防护强度不同，必须在 `evidence.json` 里标明本次用的是哪种模式。

### 3.3 依赖

- 必需：`requests`、`websocket-client`（CDP）、`cryptography`（CMS 解析 `.mobileconfig` / `embedded.mobileprovision`）。版本与 fxapk 的 `requirements.lock` 对齐。
- **不用 Playwright / Selenium**：它们要下载自带浏览器二进制，与「用本机 Chrome、独立配置文件」的要求冲突，也把体积和供应链面放大。直接用 `--remote-debugging-port` 启动本机 Chrome + CDP over WebSocket。
- 可选：`ddddocr`（本地离线字符验证码识别），进 `[ocr]` extra，缺失时自动降级为人工模式，不报错。
- 打包：PyInstaller 单文件 exe，仅本地构建，不进 CI 产物。

## 4. 分期

一期一个 PR。**先做 P1**：它是其余各期的地基，且可完全离线验收。

### 4.1 P1：CLI 核心（静态模式）

```
fxfetch <url> --out <dir> [--authorized-active] [--ua android|ios|both] [--max-bytes N] [--timeout S]
```

- 默认零流量：只打印形态判定、将访问的主机与解析到的 IP、计划步骤。
- 形态识别（`classify.py`，纯离线）：直链 `.apk` / `.ipa`；`itms-services://?action=download-manifest&url=`；`.plist`；`.mobileconfig`；App Store / TestFlight（识别后**只记录不访问**）；其余按落地页处理。
- 静态模式逐跳：`--ua both` 时 Android 与 iPhone 各走一遍同一入口，**两条链路分别留档、不合并**——同一 URL 在不同 UA 下返回不同内容本身就是证据。
- 落地页抽取：从 HTML 与响应头里抽下载候选（`a[href]`、`meta refresh`、`Location`、内联 JS 里的字符串字面量中的 `.apk` / `.ipa` / `itms-services` / `.mobileconfig`）。抽到的候选不自动下载完事，要全部列进证据。
- `manifest.plist`：取 `assets[]` 中 `kind=software-package` 的 `url`，连同 `bundle-identifier`、`bundle-version`、`title` 一并留档，原文存盘并记哈希。
- `.mobileconfig`：只保存与解析（`PayloadOrganization`、`PayloadIdentifier`、`PayloadDisplayName`、签名证书主体与指纹、`PayloadContent` 内的 URL）。**不**据其向任何地址提交设备标识。
- 下载（`download.py`）：
  - 流式写盘，边写边算 SHA-256，不整包进内存；
  - `Content-Length` 预检 + 实际字节数双重判长，不一致要记录；
  - 默认上限 512 MiB，超限即中断、保留已落盘部分并标 `truncated`，**不**标 `downloaded`；
  - 落盘文件名用 `sha256` + 判定出的扩展名，**不**用 URL 或 manifest 给的文件名（对手可控：路径穿越、Windows 保留名 `CON`/`NUL`/`AUX`、超长路径都走这条进来）；
  - 真实类型按文件头判（ZIP 魔数 + 内部结构：含 `AndroidManifest.xml` → apk，含 `Payload/*.app/` → ipa），与扩展名不符要记录。
- `evidence.json`（`evidence.py`）：
  - `run`：工具版本、UTC 开始/结束时间、模式（http / browser）、UA 画像、本次是否授权；
  - `hops[]`：序号、链路标识（android / ios）、请求 URL、方法、UA、状态码、`Location`、响应头（有界）、**实连 peer IP**、TLS 证书指纹与有效期与 SAN、响应体哈希与大小、是否截断；
  - `artifacts[]`：落盘文件、sha256、大小、判定类型、来源 hop;
  - `outcome`：`downloaded` / `not_found` / `blocked` / `failed`（四分，见 AGENTS §3），附判定依据。
- 原始入口 URL **原样保存**（含全部查询参数）。前置层的入口参数往往是加密载荷，将来取得服务端密钥即可离线复原路由，是独立于页面内容的证据。

### 4.2 P2：窗口程序

- Tkinter 单窗口：URL 输入框、设备身份选择（Android / iPhone / 两者都要）、输出目录、「下载」按钮、日志区、结果区。
- 点「下载」=本次授权，程序即在后台线程跑完整流程；UI 不卡死，实时刷新每一跳。
- 结果区按链路分组展示：形态判定、每一跳、产物哈希、`outcome`。可一键打开输出目录、一键复制 `evidence.json` 路径。
- 可选「下载后分析」勾选框：勾上则在产物就绪后调 `fxapk analyze`，输出目录与下载同级。失败只提示，不影响已取得的证据。
- 不做：剪贴板自动监听、启动时预取、历史链接自动重试——任何不经点击就发请求的路径都违反 AGENTS §1。

### 4.3 P3：浏览器模式与自动过挑战

- 启动本机 Chrome：独立 `--user-data-dir`（放输出目录下，与操作者日常浏览器完全隔离，避免把个人 Cookie 带进嫌疑站点）、`--remote-debugging-port`、默认 `--headless=new`。
- 用 CDP `Emulation.setUserAgentOverride` + `setDeviceMetricsOverride` + `setTouchEmulation` 模拟移动端：UA 字符串与 `navigator.userAgent`、屏幕尺寸、触摸能力必须一致，只改请求头会被页面 JS 识破。
- 监听 `Network.*` 事件，**覆盖全部 frame**（下载地址常出现在子框架里），按 `classify.py` 的同一套判据识别下载候选。
- 取回在同一浏览器会话内进行（带上 Cookie，保持与挑战时相同的出口），不另起裸 `requests` 请求——会话一换，IP 绑定的凭据即失效。
- 挑战处理（`challenge.py`）：
  1. 纯 JS 挑战（算 Cookie、自动跳转）：浏览器自己执行，等待即可；
  2. 「继续访问」类按钮：按选择器与可见文本匹配点击；
  3. 滑块：按轨迹拖动；
  4. 字符验证码：装了 `[ocr]` extra 时本地识别并填入。
  每个挑战**至多 3 次**，全局挑战预算 10 次；超限即停，`outcome=blocked` 并记录卡在哪一步（截图 + DOM 快照一并留档）。不爆破、不绕过风控本身。
- 静态模式判定为挑战页时自动升级到浏览器模式；两种模式的尝试都要留档。

### 4.4 P4：人工兜底

- `--interactive` / GUI 勾选：自动过不去时把 Chrome 从 headless 切为可见窗口（重启浏览器但**保留** `user-data-dir`，Cookie 不丢），提示操作者手动完成挑战。
- 操作者完成后程序自动继续：仍由 CDP 监听，识别到下载请求即接管下载与留证。
- 人工介入必须在 `evidence.json` 里留痕（哪一步、何时、介入前后的 URL），不得让人工操作在证据里不可见。

## 5. 上限（常量集中在 `core/limits.py`）

| 项 | 上限 | 理由 |
| --- | --- | --- |
| 下载总字节 | 512 MiB（`--max-bytes` 可调） | IPA 实际体量 |
| 单个页面响应体 | 8 MiB | 页面不该这么大；超限只留哈希与前段 |
| 重定向跳数 | 10 | 跳转环 |
| 单链路墙钟 | 600 s | 慢速响应拖死进程 |
| 单挑战尝试 | 3 次；全局 10 次 | 避免变成爆破 |
| plist / CMS 解析输入 | 16 MiB，嵌套深度 64 | `plistlib` 无内建深度限制 |
| 落地页抽取候选数 | 200 | 候选炸弹 |
| CDP 事件缓存 | 20000 条 | 事件洪水 |

被上限挡下的一律**计数并写进证据**，不得静默跳过。

## 6. 不做（不要再提）

- **Chrome 插件形态**：拿不到服务器 TLS 证书指纹、做不了实连 IP 校验、读不到下载后的文件算哈希、改不了页面 JS 可见的 `navigator.userAgent`（除非挂 `chrome.debugger`，浏览器会常驻「正在调试」提示条）、Windows 版 Chrome 还打不开 `itms-services://`。取证留痕上是硬伤。已有的 LiteDownload 插件后续只加一个「把当前页面链接发给 fxfetch」的按钮即可，不在插件里重做下载与留证。
- **伪造设备 UDID 换超级签包**：主动欺骗嫌疑服务器、会在对方开发者账号登记假设备、可能打草惊蛇。
- **内置代理池 / 自动换 IP**：会话凭据与出口 IP 绑定，换 IP 等于主动作废会话；出口选择属于操作者的网络安排，不由程序代劳。
- **把 App Store / TestFlight 链接也去抓包**：显式排除，只记录链接本身。

## 7. 验收

### 7.1 本地防红靶场（`tests/range/`）

用 `http.server` / `wsgiref` 写一个**自带**的仿真服务，复刻前置过滤层的常见形态，全部用合成值（域名用 `*.synthetic.test`，地址用保留段，令牌用固定假串）：

- `/?token=<串>` → 302 到换凭据路径 → 下发与客户端 IP 绑定的 Cookie → 回落地页；
- UA 分流：移动端 UA 给真页，桌面 UA 给空壳 + 错误码；
- 三种挑战页：纯 JS 跳转、「继续访问」按钮、固定字符验证码；
- 过关后反向代理到「源站」路径提供一个合成 APK / IPA；
- 失败分支：过期 token、验证码错、直接访问下载路径（无 Cookie）。

### 7.2 必测用例

形态识别（每种一例）/ 静态模式逐跳与 Cookie 保持 / UA 分流下两条链路分别留档且不合并 / manifest.plist 与 .mobileconfig 解析 / 下载上限与截断不标 `downloaded` / SHA-256 与文件头判型 / 路径穿越与 Windows 保留名文件名被拒 / SSRF 预解析与实连 peer 校验与 DNS rebinding（靶场提供解析到保留段的 host）/ 重定向跳数上限 / 挑战自动通过三类各一例 / 挑战超限后 `outcome=blocked` 且不是 `not_found` / 默认零流量（不带 `--authorized-active` 时靶场**收到 0 个请求**，用计数断言）/ 人工介入在证据里留痕。

### 7.3 每期验收命令

```bash
python -m ruff check src tests
python -m pyright src
python -m pytest -q
```

PR 描述必须分开写：**已实测验收 / 仅实现未验收 / 未实现**。没在靶场上跑过的能力不写「已完成」；真实链接上的通过率在拿到真实样本验证前一律不作承诺。
