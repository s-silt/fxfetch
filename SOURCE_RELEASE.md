# 源码交付说明

本目录是 fxfetch 的源码快照，可放入现有 GitHub 仓库。包含后端、轻量网页、Android WebView 模板、合成测试、依赖锁、Windows 启动脚本、Docker 配置及 Android worker 环境工具。

快照日期为 2026-10-30，保留已合并的上游 `386419ca26cf547e5d78bf2c0c5df3299d584330` 与既有本机功能：二维码、受控 Chrome 接续、离线网页分析、原包与证书数据包、校验失败原文件下载，以及 WebView 打包。原件校验失败继续保留失败状态，APK 结构完整不代表来源可信。

本次补齐 DNS 拒绝记录及查询名称/CNAME/类型绑定；不安全答案仍停止连接，解析服务证书始终严格验证。网页区别解析、连接、传输和预算失败，正常关闭不再误报公网拒绝，迟到解析不显示为可用结果。有界 DNS 诊断随数据包保留，不声称保存 DNS 响应原件。此前的下载入口识别、轻量布局和默认先校验证书、仅实际证书错误才继续的策略保留。

最终 Windows **1444 项通过、16 项条件跳过**，Linux 断网集成 **692 项通过、1 项条件跳过**；Ruff/Pyright 通过。更新后的 Docker Android Chrome 145实际完成一次合成页面到APK下载，ZIP中原APK与证书DER逐字节核对，worker正常归还。当前真实DNS复测仍观察到不安全答案，未强制放行，也未确认真实网站APK下载成功。Docker API和交付源码同步，具体范围及历史验收见 [IMPLEMENTATION](IMPLEMENTATION.md) 最新章节；没有代为提交或推送。

## 推送前

将本目录内容复制到自己的 Git 检出目录，保留该仓库的 `.git` 和已有许可证，检查差异后自行提交、推送。此快照没有 Git 历史，也没有代为提交或推送。当前项目未单独选定开源许可证，本次交付不替代仓库所有者的许可决定。

`.gitignore`、`.dockerignore` 以及两个 Docker 部署目录中的 `.env.example` 需要一并保留。不要把运行机器的 `.runtime`、`.tools`、`.venv`、真实 `.env`、签名或 SSH 密钥、数据库、下载文件、浏览器数据、镜像、案件材料与源码一起上传。根目录外的 ZIP 校验文件及文件清单用于核对交付，不是应用配置。

## 换机运行

按 [README](README.md) 创建虚拟环境、安装依赖并初始化服务口令。Windows 依赖快照为 `requirements.lock`；Docker 使用自己的运行时锁文件和 [部署说明](deploy/docker/README.md)。源码不包含 Python/JDK/Android SDK、字体、Chrome APK、VirtualBox/Ubuntu/Redroid 镜像或持久签名。

普通 HTTP 采集与网页服务可以独立部署。生成 APK 需要另行配置工具链、签名和可选字体；Android Chrome 需要另行准备专用环境及验收基线。当前仅实施本机 Windows Docker，具体见 [Android Docker](deploy/android-docker/README.md)，不使用 PVE；Docker 内的 QEMU/KVM 仍需硬件能力验证。不能仅复制 Windows 运行配置到 Mac 或 Docker 并视为已经接入 Android。API37 官方镜像的下载和离线分区提取工具位于 `scripts/android-worker/`；它们不是无人值守的一键安装器，也不会自动启用采集。

## 验证范围

实际测试结果与限制见 [IMPLEMENTATION](IMPLEMENTATION.md)。自动化回归只使用合成输入；用户单独授权的真实网址复测与独立 Android、隔离任务进程、API 附件和前端截图的验收范围分别记录。真实网址及下载材料不包含在源码包内。历史通过记录不保证每次虚拟机启动、任意真实网站、物理手机验证、验证码或完整离线业务都能成功。任务失败或覆盖不足不能解释为没有 APK。
