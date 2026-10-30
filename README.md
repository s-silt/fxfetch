<h1 align="center">fxfetch</h1>

<p align="center">
  网址与二维码取包工具<br>
  <sub>从已授权的下载入口获取 APK / IPA，保存网页材料与采集记录。<br>原包、网页生成包和离线分析报告分别交付，保留结果与覆盖缺口。</sub>
</p>

<p align="center">
  Python 3.11+ &nbsp;·&nbsp; 本地网页服务 &nbsp;·&nbsp;
  <a href="deploy/docker/README.md">部署说明</a> &nbsp;·&nbsp;
  <a href="API.md">HTTP API</a>
</p>

在主机运行服务，通过浏览器粘贴网址或上传二维码图片，发起采集、选择下载候选并保存结果。基础 HTTP 采集可以独立运行；Android Chrome、WebView 打包和 fxapk 离线分析按需配置。

| 核心能力 | 说明 |
| --- | --- |
| **网址与扫码** | 识别网址和图片二维码；多码由操作者选择，输入与预览不访问目标 |
| **原包采集** | 优先 APK；仅在 Android 链路确认 `not_found` 后回退 IPA，明确的 IPA 入口可直接分流 |
| **动态页面** | 有界 HTTP 优先，必要时尝试一次已配置的 Android Chrome；保留失败原因和覆盖缺口 |
| **材料与原件** | 保存已取得的网页、完整原包、可获取的 TLS 证书及来源记录，封存独立 ZIP |
| **网页打包** | 未取得原包时，由操作者单独点击生成 WebView APK，可包含已保存的局部离线内容 |
| **离线分析** | 将任务数据包中的网页材料交给独立安装的 fxapk，单独下载报告与来源回执 |

```text
网址 / 二维码图片
        │ 离线预览与选择
        ▼
   操作者提交采集
        │
   HTTP → 必要时 Android Chrome
        │
        ├── 原 APK / IPA（校验失败的完整原文件单独标记）
        ├── 任务数据包 ZIP → 手动离线分析 → 报告 ZIP
        └── 已保存网页 → 手动打包 → WebView APK
```

采集结果、归档状态、分析状态和构建状态分别记录。分析或打包成功不会将原采集的 `blocked` / `failed` 改为成功；取得 APK 也不证明其来源可信或运行安全。

## 开始使用

基础服务需要 Python 3.11+；Windows 锁定依赖以 CPython 3.12 / x64 为基线。HTTP 采集可独立运行，Android Chrome、APK 打包和 fxapk 分析需要各自的运行环境。网页能力检查显示当前可用项，不会自动安装组件。

| 场景 | 文档入口 |
| --- | --- |
| 独立 HTTP 服务 | [Docker 部署](deploy/docker/README.md) |
| Android Chrome 采集 | [Windows Docker 与 Android worker](deploy/android-docker/README.md) |
| 局域网访问 | [LAN 配置](deploy/android-docker/WINDOWS_LAN.md) |
| 接口集成与离线分析 | [API 约定](API.md) |
| 查看实测范围 | [实现状态与验收](IMPLEMENTATION.md) |

## 产物与结果

| 产物 | 含义与限制 |
| --- | --- |
| 原 APK / IPA | `downloaded` 表示传输和包结构检查通过并记录 SHA-256，不代表签名可信或软件安全 |
| 校验失败的原文件 | 完整接收但包校验失败，允许单独下载，任务仍保留失败状态 |
| 任务数据包 | 已保存原件、网页材料和有界观察的 ZIP；完整性校验不能证明整站采集完成或主体归属 |
| WebView APK | 从受控模板生成，使用自身签名；不是网站原包，局部离线页面不等于完整离线业务 |
| 离线分析报告 | 经来源核对的 JSON 报告与回执；原数据包需另行保留，静态线索不代表已验证有效 |

`not_found` 仅适用于本次声明范围已完成且无未决候选、阻挡或必要覆盖缺口。`blocked` 表示访问受阻，`failed` 表示任务未完成，两者都不能解释为“没有 APK”。

## 默认行为与边界

- **提交才访问目标。** 输入、扫码、预览、轮询和下载已有产物不触发新采集；CLI 默认离线分类，显式加 `--authorized-active` 才采集。不登录目标业务、不提交设备标识、不安装下载的应用。
- **证书先验证。** 新网页任务默认仅在实际证书校验错误后有界继续，可选择严格模式；核心与 CLI 默认严格。超时、普通 TLS 失败及地址拒绝不因此放行，实际降级与证书缺口单独记录。
- **DNS 使用固定端点。** 默认 AliDNS / DNSPod；管理员可通过 `FXFETCH_DNS_PROVIDERS` 选择支持的服务商。安全拒绝不自动换服务商绕过，解析服务证书始终严格验证，连接前公网检查保持生效。
- **任务按会话隔离。** 刷新清空本会话记录并停止未完成任务，后台原始文件保留；重启不自动重放入口。普通 HTTP 不加密传输，LAN 部署按专门配置执行。
- **材料按私有数据处理。** 数据包可能包含完整来源 URL、查询参数、页面内容及敏感线索；分享前自行审查。运行目录、账号、密钥、签名和真实材料不进入源码仓库。

Android Chrome 依赖已准备并验收的 worker，不会在采集时自动下载浏览器。第二台设备 LAN、手机安装运行及 Mac 部署仍未验收。合成测试和历史记录不能保证任意真实站点下载成功；各次实测范围与限制见 [IMPLEMENTATION.md](IMPLEMENTATION.md)。

## 开发与文档

开发约定见 [AGENTS.md](AGENTS.md)，范围见 [TASKBOOK.md](TASKBOOK.md)。代码变更使用合成输入运行 Ruff、Pyright 和 pytest；中文 Windows 环境使用 Python UTF-8 模式。真实案件材料、账号和密钥不得入库。

| 文档 | 用途 |
| --- | --- |
| [API.md](API.md) | 会话、任务、附件与接口字段 |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | 已实现能力、逐次验收与未完成事项 |
| [BROWSER_ISOLATION.md](BROWSER_ISOLATION.md) | 浏览器隔离与启用前提 |
| [RESEARCH.md](RESEARCH.md) · [TASKBOOK.md](TASKBOOK.md) | 选型依据与任务边界 |
| [SOURCE_RELEASE.md](SOURCE_RELEASE.md) | 源码交付范围与校验说明 |

本项目尚未选定开源许可证；仓库公开不等于已授予开源许可。
