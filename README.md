# fxfetch

局域网中的网址取包工具：粘贴网址，或添加二维码图片，优先取得 APK；确认静态链路没有 APK 时再尝试 IPA。未取得原包时，手动点击「打包 APK」，生成普通 Android WebView 应用。已经取得的可见页面与可保存静态资源可随 APK 提供离线浏览。

## 现在可以使用什么

- 轻量网页：桌面输入/结果双栏，手机单栏并可快速跳到任务；下载文件优先显示，链路记录可滚动查看。原生 HTML/CSS/JavaScript，无 CDN、无前端构建步骤；无活动任务时停止轮询。
- URL 输入自动补齐 `https://`，兼容 `https:/` 的单斜杠误写，保留已有 `http://` 和路径/参数；二维码文件选择/拖入/粘贴、一图多码选择和编辑。输入规范化和图片解码都不会打开目标网址。
- 受限 HTTP 下载、逐跳重定向、静态页面明确下载链接、IPA manifest、APK/IPA 结构与完整性检查。
- 登录、会话隔离、CSRF/Origin/Host 检查；持久任务、幂等提交、取消、刷新清空当前会话记录和附件下载。
- 网页任务限时执行：采集 10 分钟、打包 15 分钟；排队分别最多等待 10/15 分钟。执行超时终止任务进程及子进程，保留已落盘材料并继续队列，不自动重试或当成没有 APK。
- 动态链路显示实际访问、跳转、页面收到、发现下载入口、接收文件与校验过程；显示耗时、剩余时间和已收字节，总长度可靠时才显示百分比。
- 按钮构建 APK：固定模板、持久签名、版本递增、域名命名、签名验证、单文件交付。构建不会重新访问目标。
- 局部离线页面：只保存已取得的内容，清除脚本、表单和远程活动链接；登录与服务器接口仍需联网。不填充文件凑体积。

Chrome 动态采集通过独立 Android worker 接入，实际是否就绪由 `/api/capabilities` 的实时环境检查决定。仅有配置文件或环境安装不能放行，连接前出站隔离和硬磁盘限额必须通过验收。未配置 worker 的基础安装保持 HTTP 采集；需 JS、验证码或未覆盖流程时明确返回缺口。环境说明见 [Android worker](scripts/android-worker/README.md)，后续 Mac mini 部署见 [Docker](deploy/docker/README.md)。多个下载地址可在网页上选择一个继续；新下载保留父任务来源，但使用独立请求会话，不继承原页面 Cookie。一个候选结束后可返回原任务选择其他候选，不自动批量访问。

## Windows Docker 部署

当前部署工作以本机 Windows Docker 为目标，说明见 [Android Docker](deploy/android-docker/README.md)。Docker 管理包含 Android 环境的 QEMU/KVM worker 与 API 两个容器；需要实际可用的 KVM，不能用容器启动成功替代 Android Chrome 下载验收。PVE 不参与运行，Mac 暂未验证。源码不包含已配置的私有磁盘、浏览器二进制或 SSH 密钥，不能只复制源码便视为环境就绪。

下面保留原 Windows Python 服务的启动方式；切换到 Docker 后使用对应 Compose 配置，不运行旧 VM 恢复脚本。

## Windows 启动

需要 Python 3.11+。本机已验证 Python 3.12、JDK 17、Android Platform 35 与 Build Tools 37.0.0。

```powershell
cd E:\fxfetch
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m fxfetch init --out .runtime/service
.\.venv\Scripts\python.exe -m fxfetch serve --out .runtime/service --host 127.0.0.1 --port 8765
```

`init` 在本机终端交互设置口令，至少 12 个字符；不在聊天、网址或前端代码中填写。初始化一次即可。本机已有口令时不重复初始化。

局域网部署同时配置具体 RFC1918 网卡 IP 和允许的客户端子网。服务目录的 `server.json` 仅接受 `host`、`port`、`allowed_networks`、`proxy_host`、`proxy_port`；默认仅允许 IPv4 回环。例：`{"host":"192.168.12.2","port":8765,"allowed_networks":["192.168.12.0/24","127.0.0.0/8"],"proxy_host":null,"proxy_port":7890}`。客户端打开 `http://该IP:8765` 登录。这里只是合成配置示例，须换成实际网卡和网段。普通 HTTP 不加密局域网传输；第二台设备访问需独立验证。

也可以运行 [启动脚本](scripts/start.ps1)，默认沿用 `server.json`，显式参数覆盖文件。已配置 Android worker 时，脚本只恢复本项目登记的专用 VM 和空闲网络守卫，不启动网页采集；恢复失败仍启动 API 并报告 Chrome 未就绪。`-SkipAndroid` 可跳过此次环境恢复。禁止通配监听、公网地址和主机名；不信任 `X-Forwarded-For`，按连接 peer 校验允许网段。Windows 管理员可审阅后运行 [LAN 防火墙脚本](scripts/configure-lan.ps1)：只为指定程序、本机 IP、端口和子网放行，同时显式阻断其他 IPv4 来源，不更改全局策略、网络类别、路由或 UPnP。脚本要求防火墙已开启。源 NAT 可能把远端来源改写成允许的 LAN peer，应用无法辨识其原始来源。

## APK 构建准备

只有打包需要 Android 工具链。使用官方 Android SDK Manager 预先安装 `platforms;android-35` 和 `build-tools;37.0.0`，准备 JDK 17，然后：

```powershell
.\.venv\Scripts\python.exe -m fxfetch init-build --out .runtime/service `
  --sdk "E:\fxfetch\.tools\android-sdk" `
  --build-tools "$env:LOCALAPPDATA\Android\Sdk\build-tools\37.0.0" `
  --java-home "$env:JAVA_HOME"
.\.venv\Scripts\python.exe -m fxfetch doctor --out .runtime/service
```

以上是本机配置示例，其他电脑使用自己的安装位置。`init-build` 生成并保留私有签名密钥，之后离线构建。备份服务目录时保留 `.build-private` 和 SQLite，避免丢失签名及包名/版本映射；这些文件不作为下载附件。

命名示例：`m.123456789.com` → `m.12345.com.apk`，包名 `com.a12345.m`。非公共后缀标签最多 5 个字符，URL 的路径、参数、片段完整保留。不同域名碰撞时仅包名加稳定区分；APK 不加工具名、水印、生成标签或取证材料。

打包默认包含已保存的静态网页资源；没有有效快照时提供普通离线入口和联网指引。当前服务已启用本地字体，真实构建两种路径均约 13.6 MB、约 4.9 秒。成品大小随内容变化，目标 10–30 MB，生成 APK 上限 30,000,000 字节，不添加无功能填充。尚未进行手机安装/运行验收；局部快照不等于完整网页业务。

## 核心与验证

```text
src/fxfetch/
  core/          URL、网络守卫、HTTP、包校验、发现、扫码、离线页面、构建
  store.py       SQLite 事务、状态、幂等、命名/版本映射
  service.py     串行采集与构建 worker、私有证据和产物登记
  security.py    口令和文件路径边界
  web/api.py     HTTP 接口、会话、上传边界
  web/static/    轻量前端
  templates/     自有 Android WebView 模板
  build_setup.py 本地工具链和持久签名初始化
  cli.py         离线预览、授权 CLI、服务入口
tests/           合成测试；不包含真实案件输入
```

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pyright src
.\.venv\Scripts\python.exe -m pytest -q
```

CLI `fxfetch <url>` 默认只做离线分类，DNS/HTTP 请求为零。只有显式 `--authorized-active` 才采集。服务运行目录、工具链、产物、密钥和测试截图均不进入源码交付。

接口见 [API.md](API.md)，实际验收与未实现项见 [IMPLEMENTATION.md](IMPLEMENTATION.md)。完整路线见 [TASKBOOK.md](TASKBOOK.md)，项目选型依据见 [RESEARCH.md](RESEARCH.md)。

右上「刷新」及浏览器整页刷新会清空当前会话的记录、重置输入，并停止该会话尚未完成的任务；不会重新访问目标，不影响其他会话。记录不再通过任务或附件接口访问，后端原始文件保留。演示文件入口已移除。

## 网络与图片补充

授权采集默认使用固定地址的 AliDNS HTTPS DNS（223.5.5.5），仅服务或传输失败时回退 DNSPod（119.29.29.29）；公网地址校验和固定 IP 连接仍生效。按最新要求，本机服务与 Docker 部署均为直连，`server.json.proxy_host=null`；不读取 Windows 全局或环境代理，不把 Fake-IP 当公网地址。保留的旧 CLI 候补参数不代表当前部署启用了代理。URL 离线预览仍零 DNS、零目标连接。

上传扫码支持 PNG/JPEG/WebP、HEIC/HEIF、BMP、GIF、TIFF、AVIF，依实际解码器能力验证格式；多帧与动画拒绝，超限和解码失败单独记录。授权网页采集中也会有界读取明确图片引用并本机扫码，最多 8 张、总图片 20 MiB、累计解码 20 秒，不猜路径、不跑目标 JavaScript。多码和覆盖缺口不会自动变成无 APK。

对于已识别的公开 CryptoJS 配置落地页，采集会继续读取入口明确引用的同源脚本和配置，依据经过核验的下载模板提取真实 APK 地址，最多按配置顺序验证 4 个同一文件的 CDN 地址，取得完整 APK 即停止。全部请求使用既有网络守卫和任务预算；不执行远程 JavaScript，不将未知页面模式当成无包。首次 TCP 连接失败可尝试同一已验证 DNS 结果中的其他地址，最多 4 个；已发送的 HTTP 请求不会在该层重放。普通连接或 TLS 握手中断可继续页面明确配置的备用 CDN，每个节点仍进行完整证书校验；证书校验、地址守卫及访问阻挡错误终止。

## 可选离线中文字体

本机可预置官方 Noto Sans CJK SC Regular `Sans2.004`（16,437,364 字节），不随构建联网下载。服务目录可选 `offline-font.json` 严格包含 `path`、`license_path`（绝对本机路径）、`size`、`sha256`、`git_blob_sha1`、`license_sha256`；这些摘要必须匹配构建器内固定官方版本，文件内容也逐项校验。省略该文件则禁用。它不是客户端 API 参数。

字体实际应用于静态快照或普通离线入口页的正文，中文与英文均可使用；字体、许可、页面和资源共用 28 MiB 预算，空间不足时优先保留站点内容，不删除采集内容腾空间。APK 的「字体许可」菜单保留完整 SIL OFL 1.1/版权文本，无工具水印。此服务的字体已启用；在其他机器上没有配置字体时，成品可能明显更小，界面按实际大小显示。官方来源：[固定字体](https://github.com/notofonts/noto-cjk/blob/Sans2.004/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf)、[许可](https://github.com/notofonts/noto-cjk/blob/Sans2.004/LICENSE)。

原包下载失败后，采集流程会在剩余预算内保存最近正常页面的明确静态资源；遇拦截、安全错误或限额时只使用已取得的内容，不补发请求。构建本身仍不访问目标。界面区分「网站离线内容」与「仅离线入口页」，并显示成品大小、资源数量和未压缩资源体积。

## 下载候选与中文显示

明确的下载按钮优先于文章、分类、导航和当前页链接。同一地址的重复按钮合并；仍有多个地址时显示候选名称与完整网址，点击「继续下载所选地址」才创建后续任务。每个候选最多采集一次，同一父任务同时只运行一个后续任务；结束后可查看结果或改选其他候选。旧记录没有保存精确选择集时要求重新提交入口，不猜选历史链接。

HTML 按一致的 BOM、HTTP charset 或 meta 声明解码，支持明确声明的 GB2312/GBK/GB18030 等，并统一输出 UTF-8。非法字节、冲突编码或已有替换字符明确报告缺口。固定离线字体实际覆盖正文和子元素，不能通过扩大字体文件修复已经损坏的原网页文字。真实 GB18030 → UTF-8 → 签名 APK → 本地 Chrome 字体加载及桌面/375px 中文显示验收已通过；Android 实机运行仍未验收。

Flutter 页面只沿明确的同源启动脚本和 mainJsPath 做静态检查，分别上限 256 KiB 和 64 MiB。主脚本按 64 KiB 分块落盘、增量解码与解析，任务累计网页正文上限 128 MiB；普通 HTML 仍为 8 MiB。所有步骤共用请求、时间、磁盘和取消预算；完整读取后才发布候选，字面包地址需用户选取。超限或必须运行脚本时保持覆盖不完整。

验证码 SDK、翻译字典或普通脚本里的关键词本身不算访问受阻。当前检查验证提示与控件、专用挑战结构或明确设备门槛；隐藏备用内容、文章提词和普通登录表单不会仅因验证码关键词而标为受阻。`blocked` 表示此次访问存在验证或控制证据，不判断网站是否正规，也不能解释为没有 APK。

动态采集优先读取已正常加载的 DOM 中明确 APK/IPA 锚点，包括页面生成的隐藏文件链接；单个匹配当前链的链接沿原 Chrome 会话下载，多个不同地址仍需选择。即使页面显示验证，只要已实际下发这样的链接，也可有界尝试；页面验证观察仍保留，取得文件不表示验证码或真机验证通过。没有明确链接或文件地址继续拒绝时保持受阻，不猜接口、不伪造设备标识。

遇到验证阻挡而没有文件锚点时，还会静态提取当前页面内联脚本里已下发的明确 HTML GET 地址，沿原会话打开内容页后继续寻找 APK。当前支持字面量 `fetch` 的 `.html/.htm` 地址，不执行验证函数、不计算动态表达式、不重放 POST，也不扫描外部脚本；多个内容地址要求选择，重复地址和交互/时间限额会停止追踪。验证观察与实际下载结果始终分别保留。

“解析并保存应用”默认先走 HTTP；HTTP 能完成的任务不启动 Android Chrome，动态页面或特定响应错误才进入一次浏览器尝试。两个阶段共享总预算并分别留证，切换不会继承 HTTP Cookie。粘贴 APK/IPA 直链后还会出现“直接下载到当前设备”：这是客户端浏览器访问原地址，不经后端取包，也没有服务端完整性确认；需要原采集会话的地址可能无法在另一台设备下载，已保存文件仍可从任务附件获取。

页面重绘、重复下载按钮、明确的 `div/span` 下载控件和慢脚本均有专门处理。失败的旁路资源仍受网络防护阻断，但不会取消另一个合法文件的传输；未取得包时保留失败或受阻原因。相同内容的心跳不再无限延长等待，连续 30 秒没有新内容或下载操作时结束观察；正在接收正文时继续遵守原读取、字节和任务总预算。
