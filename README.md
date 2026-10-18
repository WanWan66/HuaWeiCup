# SecretRadar｜云凭据泄露检测原型

华为杯参赛方向的 AI 辅助开发项目。对明确授权的来源进行凭据模式检测、增量扫描和持续轮询，保存脱敏告警，提供本地查看页面。

## 目录

- `workspace/secretradar/`：来源适配器、检测、调度、存储、API 和页面。
- `workspace/tests/`：已有测试。
- `workspace/scripts/`：安装、启动、评测及本地受控实验脚本。
- `reports/`：第二轮受控评测记录和能力边界。
- `notes/third_party_licenses/`：第三方许可证原文。
- [发布范围](PUBLICATION.md)、[第三方归属](LICENSES_AND_ATTRIBUTIONS.md)、[AI 使用记录](notes/AI_USAGE_ROUND2.md)。

## Windows 快速启动

需要 Python 3.11 或更新版本和 Git；开发记录使用 Windows、Python 3.13.9。以下命令在 PowerShell 中执行：

```powershell
git clone https://github.com/WanWan66/HuaWeiCup.git
cd HuaWeiCup/workspace
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/setup.ps1
$env:SECRETRADAR_HMAC_KEY = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start.ps1 -Demo
```

浏览器访问 **http://127.0.0.1:8765/**。演示使用虚构数据；页面启动后需要保持终端运行。

HMAC key 只通过环境提供。上述命令适合首次演示；重启已有数据库必须使用原来的 key。演示 key 丢失时，应指定新数据库或先将旧演示数据库另行备份。不要把真实 key 或 Token 写入 Git。

## 扫描和持续监控

默认 `config.example.json` 的来源列表为空；按 [详细操作说明](workspace/README.md) 配置获授权的来源。

```powershell
.\.venv\Scripts\python.exe -m secretradar scan --config config.example.json --db runtime/scan.db
.\.venv\Scripts\python.exe -m secretradar watch --config config.example.json --db runtime/watch.db --interval 300 --timeout 30 --event-log runtime/alerts.jsonl --stop-file runtime/WATCH_STOP
```

`config.authorized.round2.json` 是此前授权仓库的配置示例；仓库在这里主要用于保存项目。上传源码不等于已经启动持续监控，也不等于完成了公网采集验证。

## 当前验证范围

- 本地 Git、OCI 归档及受控 HTTP 协议场景已在先前开发中验证。
- GitHub 和 MediaWiki 适配器已完成本地协议联调；项目采集器的真实公网端到端验证仍未完成。
- 第二轮保存的测试记录为 105 项通过；本次源码发布未重新运行测试。
- 评测样本为虚构合成数据，结果不能代表真实仓库中的检测精度；历史真实泄露发现数为 0。
- 不执行发现凭据的有效性验证。数据库和事件记录只保存脱敏信息。

需要自行复核已有结果时，从 `workspace` 运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/round2_review.ps1
```

具体能力和限制见 [支持来源](reports/ROUND2_SUPPORTED_SOURCES.md)、[支持凭据类型](reports/ROUND2_SUPPORTED_SECRET_TYPES.md)、[检测评测](reports/ROUND2_DETECTION_EVALUATION.md)。

本项目自身的开放许可尚未指定；第三方组件适用各自许可证。
