# 相关项目调研与选型

核验日期：2026-10-28。目标是完善局域网下载、二维码输入、Chrome 防红流程及网页 APK 按钮。依据为 GitHub 官方仓库、源码、Android 官方文档和本机 fxapk 源码；没有访问 handoff 中的真实分发目标，也没有安装依赖或运行这些第三方项目。当前方案只用 Chrome，不做指纹轮换；网页打包只输出一个无工具标识的普通 APK。

本文中的提交是调研快照，不是推荐直接安装的开发版。实施时需选择兼容 Windows / Python 目标版本的发布版并锁定依赖；项目活跃、README 声明或接口存在都不等于 fxfetch 已完成集成。

## 1. 选型结论

| 项目 | 核验内容 | 对 fxfetch 的决定 |
| --- | --- | --- |
| [Playwright Python](https://github.com/microsoft/playwright-python) | 浏览器控制；官方支持 Chrome channel，独立上下文、下载事件 | 采用其页面交互能力，控制已装 Chrome；CDP 补足网络证据。修正原计划「必须下载浏览器所以不用」的判断 |
| [Chrome DevTools Protocol](https://github.com/ChromeDevTools/devtools-protocol) | Fetch 重定向拦截、响应流接管；Network 网络事件 | 作为 Playwright 的补充，不再从零手写完整浏览器控制层；实际 Chrome 版本须验证协议能力 |
| [FastAPI](https://github.com/fastapi/fastapi) | 上传接口与 UploadFile | 保留 FastAPI + Uvicorn；自行实现上传前限流/限量、持久任务与访问隔离 |
| [ZXing-C++](https://github.com/zxing-cpp/zxing-cpp) | Python `read_barcodes`，多码、位置、Pillow 图像输入 | 选作服务器本地 QR 解码器；只开放二维码格式并保留识别来源 |
| [Pillow](https://github.com/python-pillow/Pillow) | 格式限制、图像验证与像素/解压炸弹机制 | 验证与规范化上传图像；原图另存，解码在受限进程执行 |
| [html5-qrcode](https://github.com/mebjas/html5-qrcode) | 浏览器文件/摄像头扫码；README 明确维护暂停状态 | 可参考输入交互，不列为首版依赖；本地后端解码统一证据和限额，更符合本项目需求 |
| [DrissionPage](https://github.com/g1879/DrissionPage) | 浏览器/HTTP 自动化与 LICENSE 原文 | 不选为默认依赖：其当前自定义许可含用途限制，不能按普通宽松许可证假定使用；也不复制其实现 |

所有选择都是本项目工程判断。未选择不等于相关项目没有价值；不按 star 数替代功能、许可和实际验收。

## 2. 关键官方依据及设计影响

### 浏览器控制

[Playwright 的浏览器文档](https://playwright.dev/python/docs/browsers#google-chrome--microsoft-edge)允许使用已安装的 Google Chrome channel。因而可以同时满足「复用本机 Chrome」与「减少手写点击/等待逻辑」；运行前仍要验证 Chrome/Playwright 兼容性和企业策略影响，不自动执行 `playwright install`。

[下载文档](https://playwright.dev/python/docs/downloads)说明下载临时文件与上下文生命周期相关，须在关闭前保存。本项目由此要求先完成证据封存再关闭上下文；`save_as` 不能单独承担实际字节和磁盘硬限额。

[BrowserContext 路由文档](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route)提示 Service Worker 会影响拦截。首版关闭并记录 Service Worker，显式说明页面受影响时的覆盖限制；不宣称设置一个 route 就完成全浏览器出站防护。

[CDP Fetch 源码](https://github.com/ChromeDevTools/devtools-protocol/blob/ebca9061ecc4c77b7d6b5b8f7b8afe19dc3ab9ed/pdl/domains/Fetch.pdl)支持报告跳转及其后续请求，也提供响应流接管。因此原计划「Chrome 跳转无法逐跳拦截」不成立。但协议事件仍不能代替连接前的网络隔离；接管响应流后必须正确结束原请求，不能继续原样下载。

### 图片扫码

[ZXing-C++ Python README](https://github.com/zxing-cpp/zxing-cpp/blob/b59e3b397b1c593f59f3be0c5671214da1546752/wrappers/python/README.md)及[绑定源码](https://github.com/zxing-cpp/zxing-cpp/blob/b59e3b397b1c593f59f3be0c5671214da1546752/wrappers/python/zxing.cpp)支持多码读取和 Pillow 图像输入。由此选择「后端上传解码 → 展示候选 → 操作者选取」；不需要为 QR 引入 OCR。当前 Python `read_barcodes` 公开参数没有结果数量硬限制，页面 16 项上限应在应用层处理，CPU/内存另靠进程预算，不能杜撰参数。

[Pillow Image 文档](https://pillow.readthedocs.io/en/stable/reference/Image.html)提供格式选择、延迟加载和解压炸弹防护机制。本项目另外制定明确的字节、像素、内存和时间限制；原始上传必须与缩略图、旋转副本区分，不能只看扩展名或 MIME。

[FastAPI 上传文档](https://fastapi.tiangolo.com/tutorial/request-files/)说明 `UploadFile` 使用暂存文件，并需要 multipart 解析支持。暂存不是上传配额，故任务书要求解析前限制总请求体、接收时核实际文件字节，再限制解码资源。

[html5-qrcode README](https://github.com/mebjas/html5-qrcode/blob/d505e505022cbb6680e6c8babd964e3be9a2d586/README.md)在该快照声明维护暂停、寻求接手者。它有文件扫码能力，但本项目首版不依赖它。实时摄像头还涉及 [getUserMedia 的安全上下文要求](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia#privacy_and_security)；用户需要的是添加图片扫码，首版不扩成摄像头项目。

### 许可核验

Playwright 与 ZXing-C++ 的仓库元数据为 Apache-2.0，FastAPI 为 MIT，DevTools Protocol 为 BSD-3-Clause，html5-qrcode 为 Apache-2.0。Pillow 与 DrissionPage 元数据没有给出标准 SPDX 结论，继续读取实际许可证：

- [Pillow LICENSE](https://github.com/python-pillow/Pillow/blob/75d6d6db2fa61940552fe2df0a54943a5596702b/LICENSE)声明 MIT-CMU；分发时保留适用声明，并核对实际发布包及其原生组件。
- [DrissionPage LICENSE](https://github.com/g1879/DrissionPage/blob/7761b855300a2dc4efc32c000be8150b60d21b97/LICENSE)对学习/合法非营利用途及商业使用授权作出限制。本项目不将其视为可无条件集成的默认依赖。

这里只记录取证到的许可文本与选型决定，不将 GitHub 的 NOASSERTION 推断成「无许可证」。打包时还应核实际依赖树的 notices，不能仅用本表替代分发检查。

## 3. 本地 fxapk 与样本材料对计划的影响

已结合 `E:\fxapk` 的网页相关实现和 handoff 中的离线材料归纳功能，公开计划只保留合成场景，不收录真实目标、参数、截图或案件身份。

| 观察到的形态 / 当前能力 | 任务书中的落实 |
| --- | --- |
| 外链 JS 从 API 的 Android 地址字段生成链接；API 可能报错或为空 | 浏览器监听必要脚本/API；空字段和生成无效 URL 是失败/缺口，不是明确无 APK |
| HAR 保存了 302/403，采集状态却只表示收到响应 | 下载状态独立于 HTTP 采集状态；保留挑战与访问错误 |
| 采集为 partial，目标请求数为零 | 保留未访问/未知，不用来证明目标不可用或没有包 |
| 页面可能是业务系统或登录入口 | 不提交业务表单；候选及页面性质不明时明确限制 |
| fxapk `capture-web`：固定 IP、有界 HTTP GET、TLS 检查 | 借鉴防护方法，不当成 JS 浏览器或取包引擎 |
| fxapk `analyze-web`：对本地网页材料做离线提取 | 输出独立 web 目录供可选分析，避免把 profile/日志混入输入 |
| REA trace 的 origin、目标种类和记录范围有限 | 导入走其专用合同，保留来源与覆盖；不替代完整浏览器下载记录 |
| fxapk APK analyze 的默认路径可联网；IPA 合同未验证 | 显式 `--offline`；IPA 首版仅获取与留证，不声明内容分析 |

可复核的本地入口：`apkscan/core/web_capture.py`、`apkscan/commands/web.py`、`plugins/fxapk-rea/README.md`、`apkscan/cli.py`。这些位置用于核能力边界，fxfetch 不导入其私有模块。实现时再核本机版本与 CLI 帮助，避免将当前快照视为永久接口。

## 4. 调研快照

以下仓库在查询时均未 archived；这不等于所有功能均积极维护，尤其 html5-qrcode 要以 README 的明确说明为准。

| 仓库 | 查询时默认分支提交 |
| --- | --- |
| microsoft/playwright-python | `5306360397109b09704cf87ea611f3b74f79a368` |
| ChromeDevTools/devtools-protocol | `ebca9061ecc4c77b7d6b5b8f7b8afe19dc3ab9ed` |
| fastapi/fastapi | `79cab5bed28b24d92c185d236feb33f5783dfeb3` |
| zxing-cpp/zxing-cpp | `b59e3b397b1c593f59f3be0c5671214da1546752` |
| python-pillow/Pillow | `75d6d6db2fa61940552fe2df0a54943a5596702b` |
| mebjas/html5-qrcode | `d505e505022cbb6680e6c8babd964e3be9a2d586` |
| g1879/DrissionPage | `7761b855300a2dc4efc32c000be8150b60d21b97` |

待实现验证重点：Windows wheel 与打包、本机 Chrome 兼容、浏览器连接前防护、同会话限额下载、图片受限解码、多码与来源记录、局域网第二设备操作。没有这些验收，不能据项目文档宣称 fxfetch 已可用。

## 5. Chrome 防红与实际下载地址

本项目的目标是沿正常页面流程完成挑战并取得 APK/IPA 字节。所谓“真实下载地址”是本次会话实际取回文件的请求地址；反向代理背后的源站、长期有效直链和无 Cookie 可重放地址不一定可见，不能混为同一结果。

| GitHub 实现 | 核验结果 | 对当前方案的影响 |
| --- | --- | --- |
| [Patchright Python](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python/blob/af11f22ec8d845a46a9ef88fe8cf8acf5f10bba4/README.md) | 可控制 Chrome；针对 Playwright 自动化暴露面作补丁，建议使用原生配置；Console 功能有差异 | 保留为 Chrome 驱动对比候选，不默认叠加随机指纹。移动端配置与 CDP 采集必须单独回归，不能套用项目“不可检测”宣传 |
| [nodriver](https://github.com/ultrafunkamsterdam/nodriver/blob/0233da5bfbe98dc58341f0863526b6315a97e646/README.md) | 直接使用 CDP 和已安装 Chromium 浏览器；提供独立 profile 与页面交互 | 可参考会话与 iframe 处理；另换 API 会重复适配，当前不引入。仓库元数据为 AGPL-3.0，分发需另核许可 |
| [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr/blob/cc2224b21e31c09a713eb25690a8e8dcdf50d8d8/README.md) | 持久浏览器会话、等待挑战、返回页面/Cookie；提醒 Cookie 使用的 UA 需一致 | 参考挑战等待，不把“解挑战代理”当取证下载器；不复制启动外联检查、默认监听所有地址或 Cookie 跨客户端裸重放 |
| [curl_cffi](https://github.com/lexiforest/curl_cffi/blob/78301ad1ce8bb042a451ffdb05d3037ac9fa2ed1/docs/faq.rst) | TLS/HTTP 指纹只是站点判据的一部分，不能据此保证通过挑战 | 当前固定 Chrome 会话方案不增加 TLS 指纹轮换客户端，也不为取包把已验证会话转成另一 HTTP 身份 |

额外核对了 [Patchright 驱动补丁入口](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright/blob/e2876b7bc0bef67b38164794b3108eadbc2eb647/patchright_driver_patch.ts)：补丁涉及页面、网络和执行上下文，不能只看 API 名称兼容就认为证据采集兼容。主动开启额外 Runtime/Console 调试功能也可能改变其行为，需和本项目的防护及事件记录一起验收。

重要差异见 [FlareSolverr 当前服务源码](https://github.com/FlareSolverr/FlareSolverr/blob/cc2224b21e31c09a713eb25690a8e8dcdf50d8d8/src/flaresolverr_service.py)：响应结果的 `status` 写为固定 200、`headers` 写空对象，并非真实服务器状态和响应头。因此不可将这个返回值直接写入 fxfetch 的逐跳 HTTP 证据，更不能据它标 `downloaded`。项目通用 CAPTCHA solver 的 README 说明也不支持“一定能过所有验证码”的结论。

确定路线：本机 Chrome + Playwright/CDP 先实现完整跳转、会话、挑战等待和同会话下载；达到预算后人工处理或保留 blocked/failed。未证实的地址只列候选；保存最终请求、必要条件与字节校验结果，文件由本机后端提供下载。指纹生成器、指纹注入、专用替代浏览器不在当前实施范围。

## 6. 网页生成普通 APK

已确定的交互为：没有取得原始 APK/IPA → 显示「打包 APK」→ 点击才构建 → 只下载一个 APK。应用没有工具名称、水印、生成说明或额外取证页面；名称按网址，域名标签最多 5 字符，例 `m.123456789.com` → `m.12345.com.apk`。Android 必要的包名、版本、签名正常保留，入口 URL 不截短。

| 项目 / 官方方案 | 核验与决定 |
| --- | --- |
| [Android WebView](https://developer.android.com/develop/ui/views/layout/webapps/webview) | 支持在普通 Activity 内加载网址。实施复核改用自有最小 Java/WebView 模板，直接调用 SDK 工具以减少编译依赖；Android WebView 与后端 Chrome 会话不同，防红结果不能直接继承 |
| [android/views-widgets-samples 的 WebView 示例](https://github.com/android/views-widgets-samples/tree/main/WebView) | Android 官方文档链接的示例；仓库已归档，只参考结构，不照搬旧 SDK/Gradle 配置作为当前工具链 |
| [Bubblewrap](https://github.com/GoogleChromeLabs/bubblewrap/blob/80d97ad2007fd80941ae56588f603bff5b5546b9/README.md) / [android-browser-helper](https://github.com/GoogleChrome/android-browser-helper/blob/05f859f431abf9f82d16ec6c023881492a66367c/README.md) | 主要服务 TWA/Custom Tabs。[TWA 无浏览器界面需要网站 Digital Asset Links 验证](https://developer.chrome.com/docs/android/trusted-web-activity/quick-start)，任意分发网址通常无法配置其域名，故不作为默认封装方案 |
| [Capacitor 配置声明](https://github.com/ionic-team/capacitor/blob/463225f31d9edade1098ccbadef766deb1aafbe8/cli/src/declarations.ts) | `server.url` 被说明为开发 live-reload 用途；对简单远端网址壳引入整套框架与原生桥不合本项目需求，不选作首版模板 |

[Android 命令行构建](https://developer.android.com/build/building-cmdline)支持生成 APK；本项目采用本地 release 构建并使用受控签名密钥，[apksigner](https://developer.android.com/tools/apksigner)验证签名后才交付。安装运行另行验收，编译/签名成功不代表网页在手机上可用。构建不访问目标、不迁移 Cookie，不把整个网站复制成离线应用。

实施追加：用户选择增加实际离线内容而非补足 20 MB。授权采集得到的页面和有界静态资源经清理后可放入 APK；采用受控 HTTPS asset 地址加载，离线关闭 JS/网络，不迁移网站会话。无可见内容或缺失资源如实标缺口，仍不承诺完整离线业务。Windows 已实际完成 SDK 直构建、签名和 ZIP/Manifest 核验，手机断网运行尚未验收。

为适配未信任网页，模板不提供任意 JS→原生权限桥，保留 TLS 校验；HTTP 入口按 [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)作有限域名配置，不全局放宽安全设置。构建工具链先预置与锁定，运行期只使用固定模板和结构化 URL 输入。

### fxapk 能解析什么

已核对本机当前源码，而非仅按“APK 扩展名”推断：

| 本机源码位置 | 能力与限制 |
| --- | --- |
| `apkscan/analyzers/endpoints.py:322` | 从 DEX、资源、Manifest 等提取 URL/域名/IP；普通 WebView APK 中明文入口可以进入这条路径 |
| `apkscan/analyzers/manifest.py:104`、`webview_jsbridge.py:98` | APK Manifest 与 WebView/桥接相关静态线索可分析；模板自身的结构不等于目标站原生应用结构 |
| `apkscan/core/registry.py:135` | 分析器按平台能力分流，Android 上下文不会自动运行要求 web 的分析器 |
| `apkscan/analyzers/web_evidence.py:354`、`:484`、`:651`，`web_har.py:60` | 网页内联配置、跳转链、请求构造和 HAR 使用 web 路线，裸 APK 不会自动获得这些页面与历史请求 |

结论：生成的标准 APK 可按普通 APK 交给 fxapk；只含入口的联网 WebView 包不能达到完整 HTML/JS/HAR 材料的分析深度。为满足“只要一个 APK”，打包不强制双路分析、不附带网页材料、不向 APK 填充取证资产。后续是否分析已有网页材料属于独立功能。

附加调研快照：

| 仓库 | 提交 |
| --- | --- |
| Kaliiiiiiiiii-Vinyzu/patchright-python | `af11f22ec8d845a46a9ef88fe8cf8acf5f10bba4` |
| Kaliiiiiiiiii-Vinyzu/patchright | `e2876b7bc0bef67b38164794b3108eadbc2eb647` |
| ultrafunkamsterdam/nodriver | `0233da5bfbe98dc58341f0863526b6315a97e646` |
| FlareSolverr/FlareSolverr | `cc2224b21e31c09a713eb25690a8e8dcdf50d8d8` |
| lexiforest/curl_cffi | `78301ad1ce8bb042a451ffdb05d3037ac9fa2ed1` |
| GoogleChromeLabs/bubblewrap | `80d97ad2007fd80941ae56588f603bff5b5546b9` |
| GoogleChrome/android-browser-helper | `05f859f431abf9f82d16ec6c023881492a66367c` |
| ionic-team/capacitor | `463225f31d9edade1098ccbadef766deb1aafbe8` |

## 2026-10-28 文字编码与 Android 资源复核

[WHATWG Encoding](https://encoding.spec.whatwg.org/) 说明 UTF-8 及传统编码的标签和转换行为。本项目的保存材料解码采取更保守的声明一致性检查：冲突或非法字节报告缺口，不用替换字符掩盖错误；输出统一 UTF-8，并通过 GB18030 中文构建链路实测。

[Android WebResourceResponse 文档](https://developer.android.com/reference/android/webkit/WebResourceResponse) 将 MIME 类型、字符编码和数据流分别传入。现模板对本地 HTML/CSS 使用 UTF-8，字体等二进制使用空编码，OTF 通过同源资产路径加载；本机 Chrome 字体加载检查及签名构建不代替 Android 运行验收。

## 2026-10-28 Android Chrome 路线复核

- [Damru](https://github.com/akwin1234/damru) 使用 Redroid/Android Chrome，其默认方案还包含设备配置和系统层修改，不能等同于原样 Chrome，也没有通用通过所有真机验证的证据。仓库许可有非商业使用限制，本项目没有复制其指纹补丁、安装脚本或整套服务。采用官方 Ubuntu、Redroid 与 Google SDK 来源的 Chrome，并自行实现任务、出站守卫和下载控制。
- [Mobilebridge](https://github.com/VulpineOS/mobilebridge) 的 ADB/CDP 桥接可参考控制面结构；连接 Android Chrome 不等于通过硬件证明。目标 URL 不进入远程 shell 命令，控制端点不暴露给 LAN。
- [emulator-android](https://github.com/code-root/emulator-android) 是更重的模拟器管理系统，整套依赖与本项目轻量网页不匹配。无需把其管理端、数据库、设备指纹修改一起引入。
- [Chrome Android 调试文档](https://developer.chrome.com/docs/devtools/remote-debugging/)说明了真实 Android Chrome 的调试入口。普通跳转、Cookie、脚本、按钮和下载应在同一会话处理；自动化特征减少、模拟移动视口和真实设备硬件证明是不同问题。
- REA 的作用范围是运行时脚本/请求关系与有界操作追踪，不是通用验证码或硬件验证解法。这里借鉴会话与请求关联方法，不导入 fxapk 私有模块，也不向目标提交设备标识。

实现验证分为三层：桌面 Chrome 合成捕获、Android worker 环境与守卫验收、网页任务至原包的整体集成。某一层通过不替代其他层；不存在可直接宣传的跨站“成功率更高”百分比。当前用户已取消代理，网络路径保持直连。
