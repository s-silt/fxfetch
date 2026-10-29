# 实现状态与验收

更新基准：2026-10-29 的既有记录。本文整理历史结果，不代表本次重新运行测试；实时可用性以 `/api/capabilities` 和实际任务结果为准。

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

## 已有验证

以下为不同范围的历史验收，数量不能相加为同一次测试结果。

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
