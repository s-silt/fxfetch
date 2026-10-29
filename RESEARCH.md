# 选型依据

调研快照：2026-10-28。以下是已有源码与官方文档核验的结论，不代表本次重新核验第三方状态；集成状态见 [IMPLEMENTATION.md](IMPLEMENTATION.md)。

## 采用的方案

| 用途 | 方案 | 原因与边界 |
| --- | --- | --- |
| 网页服务 | [FastAPI](https://github.com/fastapi/fastapi) + Uvicorn、SQLite、原生前端 | 轻量部署；应用自行实现上传限额、持久任务与会话隔离 |
| 浏览器 | [Playwright Python](https://github.com/microsoft/playwright-python) + [CDP](https://github.com/ChromeDevTools/devtools-protocol) | 控制已安装 Chrome，补充逐跳事件和响应流；任务期间不自动安装浏览器 |
| 图片扫码 | [ZXing-C++](https://github.com/zxing-cpp/zxing-cpp) + [Pillow](https://github.com/python-pillow/Pillow) | 后端本地解码、多码与坐标；受限进程控制时间和内存 |
| Android 环境 | 官方 Ubuntu、[Redroid](https://github.com/remote-android/redroid-doc)、Google SDK 来源的固定 Chrome | 独立 worker，由项目实现会话、连接前守卫和硬磁盘限额 |
| 网页 APK | [Android WebView](https://developer.android.com/develop/ui/views/layout/webapps/webview)、自有 Java 模板、预置 SDK | 输出普通签名 APK，避免为简单网址壳引入完整框架 |

## 关键设计依据

- [Playwright Chrome channel](https://playwright.dev/python/docs/browsers#google-chrome--microsoft-edge)可使用已安装 Chrome；版本兼容仍需实测。
- [下载生命周期](https://playwright.dev/python/docs/downloads)要求关闭上下文前保存文件。`save_as` 和 [路由拦截](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route)不能替代磁盘硬限额与连接前防护。
- [CDP Fetch](https://github.com/ChromeDevTools/devtools-protocol/blob/ebca9061ecc4c77b7d6b5b8f7b8afe19dc3ab9ed/pdl/domains/Fetch.pdl)支持响应流接管；必须正确结束原请求，不重放一次性下载。
- [FastAPI UploadFile](https://fastapi.tiangolo.com/tutorial/request-files/)的暂存机制不是上传配额；在 multipart 解析前限制总量，再限制图片字节、像素和解码资源。
- [ZXing Python 绑定](https://github.com/zxing-cpp/zxing-cpp/blob/b59e3b397b1c593f59f3be0c5671214da1546752/wrappers/python/zxing.cpp)支持多码，应用自行限制候选展示，不假定库提供数量硬限额。
- [WebResourceResponse](https://developer.android.com/reference/android/webkit/WebResourceResponse)区分 MIME、编码和数据流；本地文本统一 UTF-8，二进制字体不指定文本编码。
- [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)用于有限域名 HTTP 配置；模板保留 TLS 校验，不提供任意 JS 到原生权限桥。

## 未采用或仅供比较

| 项目 | 决定 |
| --- | --- |
| html5-qrcode | 首版使用统一的后端解码，不增加摄像头与安全上下文要求 |
| DrissionPage | 调研快照的自定义许可含用途限制，不作为默认依赖或复制来源 |
| Patchright | 保留驱动比较候选；协议兼容、取证与防护须另行回归 |
| nodriver、curl_cffi | 不增加另一套浏览器 API 或 TLS 指纹轮换客户端 |
| FlareSolverr | 可参考挑战等待；快照中的固定状态 200 和空 headers 不能作为真实 HTTP 证据 |
| Bubblewrap / TWA | 依赖网站 Digital Asset Links 验证，不适合任意网址的默认封装 |
| Capacitor | 简单网址壳不需要整套框架和原生桥 |
| Damru、Mobilebridge、emulator-android | 只参考环境或控制面思路，不导入设备指纹修改、安装脚本或整套管理系统 |

可复核依据：[DrissionPage 许可](https://github.com/g1879/DrissionPage/blob/7761b855300a2dc4efc32c000be8150b60d21b97/LICENSE)、[FlareSolverr 源码](https://github.com/FlareSolverr/FlareSolverr/blob/cc2224b21e31c09a713eb25690a8e8dcdf50d8d8/src/flaresolverr_service.py)、[TWA 验证](https://developer.chrome.com/docs/android/trusted-web-activity/quick-start)、[Capacitor 配置](https://github.com/ionic-team/capacitor/blob/463225f31d9edade1098ccbadef766deb1aafbe8/cli/src/declarations.ts)、[Damru](https://github.com/akwin1234/damru)、[Mobilebridge](https://github.com/VulpineOS/mobilebridge)。

许可结论仅针对调研快照。发布时核对锁定版本及原生依赖声明；完整旧提交列表可查 Git 历史，不作为安装版本建议。

## fxapk 对接边界

fxapk 的离线 APK 分析可提取生成包的入口、Manifest 和 WebView 结构；它不会自动获得未保存的 HTML、JS、HAR 或目标原生应用结构。网页材料分析属于独立 web 路线。

仅通过已核验的 CLI 子进程对接，APK 分析显式使用 `--offline`，不导入私有模块；IPA 内容分析合同未验证。生成 APK 不附带取证资产、不继承浏览器 Cookie，不把模板特征当成目标原包特征。

## 验证原则

桌面 Chrome 合成捕获、Android worker 隔离、网页任务到附件、手机安装和第二台 LAN 设备分别验收。任何一项通过都不能替代其他项，也不能推导真实站点成功率或通用验证码能力。
