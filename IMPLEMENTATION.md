# 实现状态与验收

## 独立网页材料采集（第一阶段）

本阶段实现为独立且有界的 `fxfetch capture-web` 工作流，包含 HTTP/浏览器采集器、每次采集独立的 JSONL provenance ledger，以及基于 `fxfetch.web-evidence.v1` 的离线目录导出/验证（例如 `fxfetch export-web CAPTURE_DIR --out NEW_BUNDLE_DIR`、`fxfetch verify-web BUNDLE_DIR`）。覆盖范围始终为 partial；浏览器命令必须显式提供 `--service-root .runtime/service` 并使用已有受保护的 Android worker。证据包可能包含私有查询参数和正文，不会匿名化；ledger 只适用于独立采集，不升级旧服务下载任务。本阶段没有 HAR、UI 或 fxapk 集成，也不改变既有下载行为。字节预算不包含 JSONL ledger 与元数据开销。验证覆盖合成真实 Chrome，实际 Android wrapper 尚未测试；哈希只保证完整性，不是真实性认证。

网页采集已按职责拆为生命周期编排、HTTP/浏览器采集、材料整理、浏览器观测、schema 校验、安全文件操作及来源关联校验。浏览器观测模块不发送 CDP 命令；传输与权限控制仍由原采集引擎管理。

统一下载任务的数据包采用独立 `fxfetch.task-evidence.v1` schema：传输观察者记录实际保存的正文和有界观察；每个已执行任务在终态后离线封存独立 ZIP，包括失败结果。原始 APK / IPA 继续单独保存在 artifact 路径，不作为 ZIP 材料；`GET /api/jobs/{id}/data-package` 只读取已就绪归档，`verify-data` 离线验证 ZIP。这个新 ZIP 不替代或修改 `fxfetch.web-evidence.v1`。

本轮合并重整增加了包用途浏览器的事实观察、带生命周期收据的有界 JSONL、来源关联校验、包字节排除、API 封存状态和安全封存限制。本地最终验证的失败、修复和限制记录如下；不将这些检查扩展解释为真实网站、DNS 或 Android worker 验证。

以下为此前独立网页模块重构及较早项目验收的历史记录，不代表本轮任务数据包重整的检查结果。此前网页改动曾有全量回归 896 passed、22 skipped；后续小修的定向回归为 64 passed，合成 Chrome 选择为 9 passed、59 deselected，Ruff 与 Pyright 通过。历史记录还包括 869 passed、7 项平台专用跳过等不同范围的结果，不应相互合并。本轮最终聚焦验证结果记录在下方。

### Codex 审查问题修复与本地验证（2026-10-29）

- 网页用途响应处理完成即返回，不再落入取包分支二次消费；模拟 CDP 回归覆盖 302 跳转与两种用途的单次读取。
- 浏览器按实际字节识别 ZIP/APK/IPA 容器前缀，完整正文及失败/限额截断前缀均记录 `package_stream`；不足四字节但仍可能匹配容器签名的失败前缀也保守排除。标记不代表包结构校验成功，不凭该标记创建 artifact。回归贯穿响应分发、来源日志、ZIP 封存及离线校验。
- 维护线程直接终结排队超时任务后走统一离线封存，记录 `queue_timeout` / `not_started`；封存期间保持 `building`，结束前不可下载。实测覆盖已有运行任务、真实维护循环、暂停封存、ZIP 内容及归档所有权清理。
- 数据库终态提交后先落盘最终证据摘要，再封存独立 ZIP；封存阻塞期间摘要已提交，原始结果不等待 ZIP。数据库与文件仍是两个提交步骤，读取测试按 `terminal_status=committed` 有界等待，而非固定延迟。
- 定向集成测试：101 passed。最后的证据落盘顺序修复后，相关 API/维护线程回归：15 passed。浏览器回归最后定向运行：模式/正常正文归档 1 passed，包正文及失败前缀归档 4 passed；各组有重叠，不相加当总数。
- 本轮唯一一次全量：938 passed、22 skipped、2 failed。证据摘要时序失败已修复；取消测试单项复测通过，但首次失败根因未确认。两项之后均定向通过，最后修改后未再跑全量，不能宣称最终全量全绿。
- Ruff 通过；最终 Pyright 为 0 errors、0 warnings、0 informations；CRLF-aware diff 检查通过。存在一条既有 Starlette/httpx deprecation warning。
- 真实 Chrome 合成子集 6 skipped（当前环境未找到已安装 Chrome，未自动下载）。模拟 CDP 不等于真实浏览器验收。没有访问真实站点、DNS、进行 UI/Android worker 测试或 fxapk 联调，也没有再次调用付费模型。

### 后续 Codex 审查三项修复与本地验证（2026-10-29）

- 浏览器网页模式按公开 CDP target ID 关联渲染后的验证码/设备拒绝快照；同 URL 的弹窗挑战仅记日志，不改变主页面结果。模拟浏览器回归分别验证干净 200 正文与渲染 DOM。
- HTTP 网页采集延迟加载浏览器模块；新进程通过拒绝所有 Playwright 导入的导入钩子验证离线预览和本地合成 HTTP 采集。
- 在构造 `ZipFile` 前独立有界解析 ZIP/标准 ZIP64 结束记录及中心目录：最多 2002 项、目录不超过 8 MiB，并检查期限、声明数量和目录边界；不解压正文。小型 ZIP64 有效包及超限/伪造计数等输入均有回归覆盖。
- 定向浏览器、网页采集和任务归档测试：58 passed；Ruff 通过；Pyright 为 0 errors、0 warnings、0 informations。
- 本轮唯一一次全量 pytest：953 passed、22 skipped、0 failed。跳过项为 5 个 Linux 浏览器网关、15 个需 PowerShell 的防火墙和 2 个 POSIX/Linux 进程限制测试。存在一条既有 Starlette/httpx deprecation warning。
- 未访问真实站点或 DNS，未安装 Chrome，未运行应用服务器。详细输出保存在 `.runtime/review-task-evidence/fix-logs/codex-*.log`。

### 前一轮任务数据包重整的本地验证（2026-10-29，修复前历史）

- 两个定向回归预检：2 passed，1 条既有 Starlette/httpx deprecation warning。
- 唯一一次全量 pytest（修复前）：928 passed、22 skipped、4 failed，1 条既有 Starlette/httpx deprecation warning。4 个失败分别是浏览器清理异常保留挑战结果、两个构建任务缺少任务目录、HTTP 保存正文的日志路径字段被省略。
- 修复后仅重跑受影响测试：4 passed；因遵守单次全量运行要求，未在修复后重跑全量套件。全量结果因此不能表述为修复后全绿。
- 已恢复原有独立 WebView 构建磁盘计量；两个 task supervision 回归复测为 2 passed。
- 22 个跳过项：5 个 Linux 浏览器网关行为、15 个需 PowerShell 的防火墙测试、2 个 POSIX/Linux 进程限制测试。未启用 live-site、Chrome UI 或 Android worker 测试。
- Ruff `check src tests`：通过；Pyright `src`：0 errors、0 warnings、0 informations；Node `--check`：`app.js` 与 `data-package.js` 均通过。
- `git diff --check` 因 Windows `core.autocrlf=true` 将 CRLF 报为新增行尾空白而退出 2；`git -c core.whitespace=cr-at-eol diff --check` 通过，未见其他空白问题。
- 本轮没有进行真实目标、DNS、浏览器 UI 或 Android worker 测试。

以下为 2026-10-29 的既有能力及历史记录，不代表本轮重新运行所有历史验收；实时可用性以 `/api/capabilities` 和实际任务结果为准。

## 当前能力

| 模块 | 已实现 |
| --- | --- |
| 输入 | URL 离线补齐、图片二维码识别、多码选择和编辑；预览不访问目标 |
| HTTP | APK 优先、IPA manifest、逐跳记录、候选选择、包结构与完整性校验 |
| Android Chrome | HTTP 需要动态处理或收到 403/429/502/503 时，最多尝试一次独立浏览器会话；不继承 HTTP Cookie，共享剩余预算 |
| 动态下载 | 原 Chrome 会话处理页面、按钮、Cookie 和一次性票据；从原响应流保存文件，不重发下载 GET |
| 内容页追踪 | 读取已下发 DOM 文件锚点，以及验证页面内联脚本中的字面量 HTML GET 地址；多地址须选择，循环停止 |
| 网页服务 | 登录、会话隔离、CSRF/Origin/Host 校验、幂等、进度、取消、附件下载和刷新清空 |
| APK 构建 | 固定 WebView 模板、持久签名、域名命名和版本映射；可包含清理后的局部静态内容及固定字体 |
| 部署 | Windows Docker 管理 QEMU/KVM Ubuntu worker 与独立 API；使用固定 Redroid / Chrome 环境 |

浏览器已处理慢脚本、DOM 重绘、重复按钮、div/span 下载控件及无关资源失败。连续 30 秒无实质进展停止观察；接收正文仍受原读取和总任务预算约束。

“直接下载到当前设备”由客户端浏览器访问明确 APK/IPA 链接，不创建后端任务，也不表示服务端已校验文件。候选子任务另起请求会话，不继承父任务 Cookie。

## 历史验收记录（不代表本轮重整已重跑）

以下为不同范围的历史验收，数量不能相加为同一次测试结果；它们不验证本轮任务数据包改动。

| 范围 | 记录结果 |
| --- | --- |
| 最新 Windows 标准回归 | 869 passed，7 项 Linux/POSIX 专用跳过；Ruff、Pyright、JS 语法检查通过 |
| 最新桌面 Chrome 合成回归 | 95 passed；桌面与 375px 界面、直链下载及零目标请求预览通过 |
| Docker Linux 专项 | 43 passed，覆盖网关、进程限制及平台专用行为 |
| Windows Docker 启动器 | 最后定向回归 17 passed；普通用户实际启动通过 |
| Android 完整合成链路 | 隔离 task_worker → Android Chrome → 原响应下载 → API 附件，13,607,818 字节，SHA-256 一致，关键请求各一次 |
| Android 隔离与期限 | 内外层阻断、允许 broker 路径、2 GiB 数据卷写满、取消及后继会话、210 秒 guest 原生租约到期通过 |
| Linux APK 构建 | 非 root、断网、3 GiB cgroup 下完成签名构建；核验 Manifest、DEX、ZIP、中文资源及字体 |
| 本机服务入口 | 本机 LAN 地址、匿名接口 401、错误 Host 400、静态文件一致性和能力检查通过 |

Docker 迁移使用已关机源盘的独立 qcow2 副本，逻辑内容比对与源盘前后摘要一致。修复了 worker 线程额度、Linux TIME_WAIT 端口重用和 QMP 关机确认；实际停机、重启已验证。

## 限制与未完成项

- 第二台真实 LAN 设备、手机安装运行和 Mac 部署仍未验收。
- 不支持通用验证码求解、硬件证明绕过、blob 下载或人工原 Chrome 会话续接。
- Worker/SharedWorker/ServiceWorker/worklet 超出当前支持范围时拒绝并保留覆盖缺口；不能推断所有动态页面均可处理。
- 取得已下发文件不代表验证码或设备验证通过；失败、受阻、超限和覆盖不足不能写成“没有 APK”。
- 局部网页快照不是完整离线业务，生成 WebView APK 不是目标原包；构建成功不等于手机可用。
- Chrome 启动、网络隔离、磁盘和租约须逐环境验收；历史成功、配置存在或 Compose healthy 都不能替代实时证明。

## 运行记录与复核入口

私有收据位于 `.runtime/android-worker/`、`.runtime/docker-worker/`、`.runtime/android-docker-api/`、`.runtime/live-download-20261029/` 及 `.runtime/service/`，不随源码交付。详细旧记录可查 Git 历史。

部署见 [Windows Docker](deploy/android-docker/README.md) 和 [LAN 入口](deploy/android-docker/WINDOWS_LAN.md)；接口见 [API](API.md)，工程验收要求见 [任务书](TASKBOOK.md)。
