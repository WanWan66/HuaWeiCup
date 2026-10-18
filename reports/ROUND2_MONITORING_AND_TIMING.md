# 持续监控与受控时效实测

watch是真实可执行调度器，每源配置间隔/超时，最多四源并行。同数据库同源有跨进程OS锁，结果与checkpoint主事务一起提交。
工作子进程硬超时：Windows清理本次Popen启动的进程树，Linux使用本次新建进程组；用唯一worker_run_id关联任务，避免venv启动器PID差异。
新增验收曾发现只杀启动器的错误，已修复；回归等待迟到响应并确认checkpoint不推进。最终测试见ROUND2_TESTS.xml，不把此前失败算PASS。
失败指数退避、限流Reset/Retry-After、下次重试时间持久化；Ctrl+C或stop-file停止。无需管理员权限/系统服务。
多源、重启恢复、重复告警、停止、硬超时和重试有实际测试。事件为脱敏本地SQLite事件与JSONL快照；event_id稳定，不使用外部webhook。

启动（先注入稳定HMAC key，从workspace运行）：
~~~powershell
.\.venv\Scripts\python.exe -m secretradar watch --config authorized.json --db runtime/watch.db --interval 60 --timeout 30 --event-log runtime/alerts.jsonl --stop-file runtime/WATCH_STOP
~~~

## 时间定义
- content_created_at：控制器开始构造测试内容的时间。
- accessible_at：回环服务在锁内发布到可访问状态的边界时间；不是公网公开时间。
- first_seen_at：采集批次返回的时间。
- scan_completed_at：该文档检测器返回的时间。
- alerted_at：创建告警/准备INSERT时间。
- persisted_at：SQLite主事务成功返回后记录的确认时间，不伪称精确磁盘介质flush时刻。
- 外部通知送达：N/A，未实现。
- published_at：真实可信发布时间缺失时为null。Git commit/文件mtime均未冒充公开时间。

## LOCAL_CONTROLLED：可访问到本地告警提交确认
| 配置等待间隔 | 注入次数 | 完成轮询 | 平均ms | 中位ms | P95ms（nearest rank） |
|---|---:|---:|---:|---:|---:|
| 0.25 s | 10 | 10 | 638.302 | 618.672 | 850.500 |
| 1.0 s | 10 | 10 | 1129.977 | 1152.565 | 1387.498 |

共20次发布均等到下一次自动轮询生成新告警；两组各重启额外3轮，无重复新告警，未留下running任务。原始逐阶段时间、job id和轮次见ROUND2_TIMING.json。
调度为完成一次后等待interval；实际周期还含新工作进程启动、HTTP、SQLite与操作系统调度，不保证严格固定起始周期。两档样本少、未隔离全部系统背景活动，P95只是10次最近秩样本统计。
REMOTE_AUTHORIZED时效：N/A。未获授权公开测试文件发布，且仓库API限流。不得将本地秒级结果宣传为公网分钟级发现证据。
