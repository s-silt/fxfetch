# 源码交付说明

本目录是 fxfetch 的源码快照，可放入现有 GitHub 仓库。包含后端、轻量网页、Android WebView 模板、合成测试、依赖锁、Windows 启动脚本、Docker 配置及 Android worker 环境工具。

本次快照日期为 2026-10-30，已合并上游 `386419ca26cf547e5d78bf2c0c5df3299d584330`。保留本机网页离线分析、可选 Docker 分析依赖层、数据包终态、私有目录权限、Windows 元数据替换和分析轮询恢复修复，以及二维码去重与优先级、受限 Chrome 接续、内联脚本明确文件链接提取。容器配置统一使用 `FXFETCH_FXAPK`，已有可选镜像与部署说明同步迁移。合并后全量 1086 项通过；具体范围和限制见 [IMPLEMENTATION](IMPLEMENTATION.md) 的最新验收。

后续补充校验失败原文件的独立下载入口及旧 HTTP 记录兼容，保持任务失败结论；网页打包按钮移至任务结果附近。此修订全量 1118 项通过，Docker 和交付源码同步更新，实际范围见实现状态记录。

## 推送前

将本目录内容复制到自己的 Git 检出目录，保留该仓库的 `.git` 和已有许可证，检查差异后自行提交、推送。此快照没有 Git 历史，也没有代为提交或推送。当前项目未单独选定开源许可证，本次交付不替代仓库所有者的许可决定。

`.gitignore`、`.dockerignore` 以及两个 Docker 部署目录中的 `.env.example` 需要一并保留。不要把运行机器的 `.runtime`、`.tools`、`.venv`、真实 `.env`、签名或 SSH 密钥、数据库、下载文件、浏览器数据、镜像、案件材料与源码一起上传。根目录外的 ZIP 校验文件及文件清单用于核对交付，不是应用配置。

## 换机运行

按 [README](README.md) 创建虚拟环境、安装依赖并初始化服务口令。Windows 依赖快照为 `requirements.lock`；Docker 使用自己的运行时锁文件和 [部署说明](deploy/docker/README.md)。源码不包含 Python/JDK/Android SDK、字体、Chrome APK、VirtualBox/Ubuntu/Redroid 镜像或持久签名。

普通 HTTP 采集与网页服务可以独立部署。生成 APK 需要另行配置工具链、签名和可选字体；Android Chrome 需要另行准备专用环境及验收基线。当前仅实施本机 Windows Docker，具体见 [Android Docker](deploy/android-docker/README.md)，不使用 PVE；Docker 内的 QEMU/KVM 仍需硬件能力验证。不能仅复制 Windows 运行配置到 Mac 或 Docker 并视为已经接入 Android。API37 官方镜像的下载和离线分区提取工具位于 `scripts/android-worker/`；它们不是无人值守的一键安装器，也不会自动启用采集。

## 验证范围

实际测试结果与限制见 [IMPLEMENTATION](IMPLEMENTATION.md)。自动化回归只使用合成输入；用户单独授权的真实网址复测与独立 Android、隔离任务进程、API 附件和前端截图的验收范围分别记录。真实网址及下载材料不包含在源码包内。历史通过记录不保证每次虚拟机启动、任意真实网站、物理手机验证、验证码或完整离线业务都能成功。任务失败或覆盖不足不能解释为没有 APK。
