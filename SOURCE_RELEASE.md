# 源码交付与复核

本页说明源码包的内容、来源和迁移边界。项目介绍见 [README](README.md)，部署入口和逐次实测范围分别见部署文档与 [IMPLEMENTATION.md](IMPLEMENTATION.md)。

## 交付内容

| 包含 | 不包含 |
| --- | --- |
| Python 后端、网页静态资源、Android WebView 模板 | Python、JDK、Android SDK、字体与浏览器安装包 |
| 合成测试、依赖锁、Windows 启动脚本 | 虚拟机磁盘、Redroid / Ubuntu / VirtualBox 镜像 |
| Docker 配置、Android worker 环境工具、示例配置 | 服务口令、私有配置、签名、SSH 密钥、数据库及真实采集材料 |

源码包不携带运行环境或服务状态。复制源码不能替代 worker 环境验收，也不会自动启用 Android Chrome、APK 打包或 fxapk 分析。

## 本次来源

本次同步采用 **2026-10-30 14:13 的追加交付包**，其外部清单包含 269 个文件。ZIP 的 SHA-256 为：

```text
aaa8b8cfa9bb6bfc7939b20f94c2561aff0b5195cb8de1c60a0969b5c90fd8f8
```

导入前已逐项核对清单与文件哈希。该摘要仅对应原始交付 ZIP；仓库还保留上游局部导航对象修复，并加入复审修复与文档整理，因此不能用原 ZIP 摘要验证整棵 Git 工作树。仓库版本以 Git 提交为准。

追加更新允许管理员选择固定 DNS 服务商，并修复入口导航未结束时提前按空闲收尾的问题；此前的 DNS 诊断、证书错误后有界继续、原件数据包及离线分析能力一并保留。配置选择不放宽公网检查，解析服务证书保持严格验证，安全拒绝不自动候补。

交付方记录的 Windows、Linux、Android 和真实入口结果是各自环境下的历史验收。本次仓库集成的检查单独记录在 [IMPLEMENTATION.md](IMPLEMENTATION.md)，不把历史结果当作重新执行。真实入口未取得原 APK 的记录保持未完成口径。

## 迁移边界

Git 历史、仓库既有修复与许可文件应保留。`.gitignore`、`.dockerignore` 和部署目录的 `.env.example` 随源码交付；运行目录、真实 `.env`、下载文件、浏览器数据、密钥和签名不入库。

Windows 与 Docker 使用各自依赖锁。迁移已有服务还涉及签名、数据库和 worker 环境，不能只复制源码或 Windows 配置即视为部署完成。环境要求见 [Docker 部署](deploy/docker/README.md) 与 [Android Docker](deploy/android-docker/README.md)。

## 验证边界

合成回归验证声明的输入与路径，不保证任意真实站点、验证码、设备校验或完整离线业务都成功。手机安装运行、第二台设备 LAN 和 Mac 部署仍未验收。包结构或材料哈希校验通过不证明来源可信、软件安全或采集完整。

项目尚未选定开源许可证，源码交付不替代仓库所有者的许可决定。
