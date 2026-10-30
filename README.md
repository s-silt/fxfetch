<h1 align="center">fxfetch</h1>

<p align="center">
  面向防红入口的 APK / IPA 采集工具<br>
  <sub>追踪跳转、识别下载入口、获取原包，保留采集材料供复核。</sub>
</p>

粘贴网址或上传二维码图片，通过本地网页服务发起采集。针对防红服务器常见的多层跳转、设备分流和下载入口隐藏，结合 HTTP 解析与 Android Chrome，尽量沿页面实际提供的链路找到原始安装包。

## 能做什么

- **应对防红入口**：跟随重定向，识别页面、部分脚本及内嵌配置中已下发的下载地址；需要动态处理时接续 Android Chrome。遇验证页仍可尝试已明确提供的包链接。
- **下载原包**：支持网址与二维码，优先 APK，按结果分流 IPA；校验文件完整性并记录 SHA-256。
- **保留材料**：单独下载原包、网页材料和证书记录，封存来源与失败原因，可交给 fxapk 离线分析。
- **网页打包**：未取得原包时，可手动生成 WebView APK，并附带已保存的局部离线页面。

## 能力边界

不保证突破所有防红或访问控制，不支持通用验证码求解、硬件证明绕过或目标业务登录。下载失败不等于没有安装包；取得文件也不代表验证已通过或文件安全。生成的 WebView APK 不是网站原包。

仅在授权范围内采集；输入和扫码不访问目标，提交后才开始。材料可能含敏感信息，分享前需审查。Android Chrome、打包和离线分析需要另行配置；手机运行、第二台设备 LAN 和 Mac 部署尚未验收。

## 文档

[部署](deploy/docker/README.md) · [Android Chrome](deploy/android-docker/README.md) · [局域网](deploy/android-docker/WINDOWS_LAN.md) · [API](API.md) · [实测范围](IMPLEMENTATION.md) · [开发约定](AGENTS.md)

Python 3.11+。项目尚未选定开源许可证。
