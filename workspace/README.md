# SecretRadar 第二轮开发审查原型

本项目为 AI 辅助实现，供参赛学生独立审查、学习、调试和验证。没有代签独立完成声明、没有报名、没有正式提交。官方 AI 辅助允许范围尚需本人向组委会确认。

Windows 11 / Python 3.13.9 / Git 2.55.0 已实测；Linux 未登录和部署。依赖仍使用 requirements-lock.txt。初次安装运行 scripts/setup.ps1；以下命令均从 workspace 执行。

## HMAC key 与启动

必须通过独立环境变量提供至少32 UTF-8 bytes的稳定 key，绝不写入Git/.env/日志。首次受控演示可在 PowerShell 7 会话中生成：
~~~powershell
$env:SECRETRADAR_HMAC_KEY=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start.ps1 -Demo
~~~
访问 http://127.0.0.1:8765/ 。重启已有数据库必须继续使用同一个key；重新生成会被拒绝。演示key丢失时使用一个新数据库文件；真实环境应从独立密钥管理环境持续注入，项目不保存key。

## 单次扫描与持续监控

config.example.json 始终默认 deny-all。config.authorized.round2.json 仅包括用户明确授权的 WanWan66/HuaWeiCup 仓库；该仓库API在本轮返回未认证限流，不要不断手动重试。
~~~powershell
.\.venv\Scripts\python.exe -m secretradar scan --config config.authorized.round2.json --db runtime/authorized.db
.\.venv\Scripts\python.exe -m secretradar watch --config config.authorized.round2.json --db runtime/authorized.db --interval 300 --timeout 30 --event-log runtime/alerts.jsonl --stop-file runtime/WATCH_STOP
~~~
每源可用 interval_seconds / timeout_seconds 覆盖命令参数。最多四源并行，但同一数据库下同源有跨进程锁。每次扫描独立子进程，超时会终止本次工作进程树。调度为“完成一次扫描后等待间隔”，有效周期包含工作进程启动、采集和持久化时间。
Ctrl+C 或创建上述 stop-file 可停止；再次启动前须本人移除旧stop-file。watch支持 --max-polls N 用于有限轮数演示，不安装系统服务。
checkpoint、下次允许重试时间和告警持久化到SQLite；进程重启恢复，失败指数退避并尊重服务器Retry-After/限流Reset。

如本人选择配置 GitHub Token，只通过 SECRETRADAR_GITHUB_TOKEN 环境注入并限制为本仓库只读权限。Token只用于固定 api.github.com 主机，不发送给受控回环服务，不进入日志或数据库。不得把Token发到聊天中。
未配置授权Wiki站点；不要擅自扫描其他人站点。显式HTTP回环api_base/local_protocol仅用于本地协议联调，不允许替换成陌生公网主机。

## 告警、复核与定位

info级私钥标记/无秘密上下文熵候选不生成泄露告警，只计候选数。完整外壳私钥也只是结构候选，未验证有效性。AK/SK仅同配置节、最多32行/8192字符，且双方只有一个唯一值时配对；歧义时保留单项，不做笛卡尔组合；跨文件不支持。

同源/匿名路径/类型/HMAC指纹去重；重复完整扫描增加观察次数和事件，不创建重复告警。first_job_id/last_job_id/occurrences/rule_version记录证据。事件文件是完整脱敏JSONL快照，event_id稳定，重复导出不增加新事件；未实现外部webhook，通知送达时间N/A。
~~~powershell
.\.venv\Scripts\python.exe -m secretradar alert-state --db runtime/authorized.db --alert-id 1 --state acknowledged
.\.venv\Scripts\python.exe -m secretradar events --db runtime/authorized.db --event-log runtime/alerts.jsonl
~~~
支持 open / acknowledged / resolved 人工状态；旧版无规则信息的历史记录迁移为 needs_review。删除源文件不会自动认定历史泄露已解决。
规则改变或旧规则未知时，已有checkpoint要求本人显式完整回扫：
~~~powershell
.\.venv\Scripts\python.exe -m secretradar scan --config config.authorized.round2.json --db runtime/authorized.db --full
~~~
Git full为当前HEAD可达的有界历史；GitHub full为默认分支当前快照，不能声称已扫描远端全部历史。

路径和provenance只存HMAC。授权本地Git操作员可按完整path_id定位当前文件，普通网页不提供该能力：
~~~powershell
.\.venv\Scripts\python.exe -m secretradar locate --config authorized-local-git.json --db runtime/authorized.db --source owned_git --path-id <64位path_id> --operator-local
~~~
默认只返回是否匹配，不打印原路径；显式加 --open-editor 时在Windows固定Notepad中打开匹配文件。此打开动作未实测，只验证了内存映射和边界；历史已删除文件、远端源/OCI定位未实现。

## 测试与可复现评测

~~~powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=runtime/round2-tests --junitxml=../reports/ROUND2_REPRO_TESTS.xml
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/round2_review.ps1
# 可选重新测量规模和持续轮询，需要先注入HMAC key：
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/round2_review.ps1 -RunExperiments
~~~
留出集首次结果不可覆盖；--verify-recorded 只重新计算并核对已封存结果，不调规则、不改报告。合成开发/留出各320份、每组20模板，每模板16变体，并非640种真实场景。
历史修改删除由单独Git/HTTP集成场景覆盖，不混入静态留出精度。真实发现数量为0；所有精度和时效来自受控数据。
规模适配器controlled_directory只用于带 SYNTHETIC_ONLY 标记的本地合成目录，测文件读取/检测/SQLite，不代表Git/GitHub平台吞吐量。

时间字段分别为内容创建、受控可访问、首次观察、扫描完成、告警生成和SQLite主事务提交确认；真实公开时间缺失为N/A。外部通知尚未实现。
完整结果见 ../reports/ROUND2_FINAL_REPORT.md，具体来源和类型等级见 ROUND2_SUPPORTED_SOURCES.md / ROUND2_SUPPORTED_SECRET_TYPES.md。

## Linux 复现目标（未实测）
~~~sh
cd /path/to/HuaWeiCup/workspace
python3 -m venv .venv
.venv/bin/python -m pip install --cache-dir .cache/pip -r requirements-lock.txt
# 从独立环境注入稳定SECRETRADAR_HMAC_KEY后：
.venv/bin/python -m secretradar watch --config authorized.json --db runtime/watch.db --interval 60 --timeout 30 --event-log runtime/alerts.jsonl
~~~
本轮SSH TCP可达，但在密钥交换前关闭，不能归因为认证失败。未sudo、未部署、未改现有Agent/Ollama服务，未调用模型。

公开源码副本未包含本机历史审查包生成脚本及环境诊断日志。使用 scripts/round2_review.ps1 复现功能验证；发布范围见 ../PUBLICATION.md。
