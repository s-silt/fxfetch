# AGENTS.md — fxfetch 执行约定（给 AI agent）

实施前先读 [TASKBOOK.md](TASKBOOK.md)。本文件只讲边界，不讲设计。

## 1. 授权

- **默认零流量。** CLI 不带 `--authorized-active` 时只打印将要访问的主机、解析到的 IP 与计划步骤，一个请求都不发。
- **agent 不得自行加 `--authorized-active`**，也不得在测试、示例或脚本里把它写成默认值。真正发请求由操作者决定。
- GUI 的「下载」按钮是操作者的授权动作；按钮之外的任何路径（启动时预取、剪贴板监听、自动重试扩大目标）都不得发起请求。
- 失败不触发无限重试，不擅自扩大目标范围（不枚举同站其他路径、不抓同域其他资源）。

## 2. 不做的事

- 自动化只做「一个正常移动端用户点下去会发生什么」：执行页面 JS、点按钮、拖滑块、对字符验证码做**有限次**本地识别（每个挑战默认至多 3 次，见 TASKBOOK §4.3）。不爆破、不扫描、不枚举，失败即转人工或报 `blocked`。
- 不向任何地址提交设备标识（UDID、IMEI、推送 token）换取签名包。
- 不登录对方后台、不提交表单数据、不与业务系统交互。
- 不执行下载到的任何文件，不在宿主上打开它。
- 不把真实案件材料（域名、IP、令牌、密钥、页面源码、报告）写进仓库、测试夹具、示例或提交信息。

## 3. 事实口径

结果状态必须四分，任何一种都不得被呈现成另一种：

| 状态 | 含义 |
| --- | --- |
| `downloaded` | 取到了包，有哈希 |
| `not_found` | 走完链路，确实没有可下载的包 |
| `blocked` | 被挑战页 / 验证码 / 访问控制挡住，**内容未知** |
| `failed` | 网络错误、超时、被 SSRF 防护拒绝 |

`blocked` 写成「未发现下载包」是伪造结论，一票否决。同理：被大小上限截断的下载不得标 `downloaded`。

## 4. 开发

```bash
python -m pip install -e ".[dev]"      # Python >= 3.11
python -m ruff check src tests
python -m pyright src
python -m pytest -q
```

- Python type hints；pytest，不用 unittest；不裸 except、不吞 log。
- 依赖版本与 fxapk 的 `requirements.lock` 对齐，不引入需要下载浏览器二进制的框架（见 TASKBOOK §3.3）。
- 测试不得访问外网：网络用例一律打本地靶场（`tests/range/`）。
- 「提交」止于 commit，「推送」止于 push，「发 PR」止于 PR。未经指示不主动提交。
