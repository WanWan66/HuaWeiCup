# SecretRadar第二轮执行报告

## 一、整体状态
PARTIAL。GATE A保全/复测完成，B检测修复/冻结留出完成，C协议本地联调完成但公网BLOCKED，D持续监控完成，E本地受控时效和100/1000/10000规模完成，F材料与审查包完成。
第一轮55项通过、旧14份指标、原面板/Git/OCI等不是本轮新成果，原证据与ZIP留在原位置并另备份。

## 二、实际新增功能
私钥标记与完整外壳候选区分；高熵上下文分级；有界歧义抑制配对；引号/JSON/跨行/编码回归。
640行/490唯一正文的冻结合成开发和留出数据、前后按类评测。
GitHub可达新提交增量回溯和更细HTTP错误/限流处理；GitHub/Wiki实际回环HTTP联调。
watch多源间隔、子进程超时、退避、停止、重启、同源互斥；本地持久化事件与脱敏JSONL。
任务关联、重复观察、生命周期、规则版本/受控回扫及操作员内存定位。--open-editor未实际打开，列为未实测。

## 三、测试情况
开始前原55项实测通过。最终 105 项，105通过，0失败，0跳过；新增 50 项。
旧14样本中两个错误正样本已更正，原样反例另加负测试；原第一轮快照/标签/结果保留，不能说旧错误标签未经修改仍正确。
测试期间抓到Windows venv启动器与实际worker PID差异，导致硬超时残留running任务；已修复并加入迟到响应检查。最终日志notes/round2-tests.log、ROUND2_TESTS.xml。
复现：workspace中 powershell -NoProfile -ExecutionPolicy Bypass -File scripts/round2_review.ps1。

## 四、在线渠道
REAL_REMOTE_TESTED=0，真实泄露发现0；不能评价真实检出能力。
明确授权仓库WanWan66/HuaWeiCup；具体repo及commits端点均HTTP403、remaining=0，有GitHub request id，属未认证配额耗尽证据，不是代理拒绝或仓库不存在结论。
GitHub/MediaWiki两类平台均只有协议模拟验证，另通过真实回环HTTP本地集成；不是真正平台部署。Wiki无授权公网URL。没有其他未授权来源，没有推送/发布权限。
最少补充：本机只读Token或配额恢复；授权Wiki API地址/范围；若需公网计时还需单独明确合成文件发布授权。

## 五、检测准确性
首次冻结留出320行，245唯一正文。TP=176、FP=0、FN=0、Precision=1.0000、Recall=1.0000、F1=1.0000。
修复前留出TP80/FP240/FN96；开发集前后和每类型结果见ROUND2_DETECTION_EVALUATION.md。
全部为无效合成数据，共享合成语法、非真实世界盲测。规则首次留出后未改变，已有结果可只读复现核对；不据此宣称真实100%。

## 六、持续监控
准确命令（workspace，先注入稳定HMAC key）：
~~~powershell
.\.venv\Scripts\python.exe -m secretradar watch --config authorized.json --db runtime/watch.db --interval 60 --timeout 30 --event-log runtime/alerts.jsonl --stop-file runtime/WATCH_STOP
~~~
控制实验两档各完成 10 / 10 轮，每档10次自动新告警，总20次；另各重启3轮，新增告警0，无running残留。
多源、重启、停止、硬超时及失败退避另通过pytest；没有安装系统服务，未使用外部Webhook。

## 七、检测时效
content_created_at→accessible_at→first_seen_at→scan_completed_at→alerted_at→persisted_at定义与逐条证据见ROUND2_MONITORING_AND_TIMING.md / ROUND2_TIMING.json。
LOCAL_CONTROLLED：0.25秒间隔，10次，平均638.302ms、中位618.672ms、P95850.500ms；1.0秒间隔，10次，平均1129.977ms、中位1152.565ms、P951387.498ms。
REMOTE_AUTHORIZED=N/A；外部通知送达=N/A；Git commit/文件mtime未充当公网公开时间。
轮询采用完成后等待，子进程启动等使实际周期长于配置值；没有虚构公网分钟级发现结论。

## 八、性能
真实本地合成文件读取/检测/SQLite，三次重复中位数：

| 文件数 | bytes | 秒 | 文件/s | CPU单核等效 | RSS bytes | 告警 | 增量跳过 | DB增长bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 31390 | 0.1805 | 554.00 | 90.68% | 30056448 | 10 | 100 | 40960 |
| 1000 | 314890 | 1.8862 | 530.15 | 91.19% | 33034240 | 100 | 1000 | 372736 |
| 10000 | 3158890 | 14.6467 | 682.75 | 97.92% | 43520000 | 1000 | 10000 | 3698688 |
上述每行字段顺序：文件数、bytes、秒、文件/s、CPU单核等效%、RSS bytes、告警数、增量跳过数、DB增长bytes。清晰表格及原始值见ROUND2_PERFORMANCE.md/json。
这是controlled_directory适配器，不代表Git/GitHub平台吞吐或生产稳定性。代码执行版本见PROVENANCE.json。

## 九、剩余缺口
按官方题目五维证据缺口判断：1)公开渠道真实成功接入与真实发现证据；2)可信公开时间与REMOTE_AUTHORIZED测量；3)独立真实/更复杂合法数据、多云格式和长期稳定性。
没有官方数值权重，不虚构评分或获奖概率。Wiki API侧增量、外部通知、Linux、生产权限体系仍缺。

## 十、正式交付准备状态
已具备源码、启动/测试脚本、独立合成标签与冻结证据、监控/时效/规模报告、技术参考、依赖许可证、AI记录、限制说明。
仍需学生本人确认赛事AI辅助允许范围，独立理解/调试/撰写正式PDF，核验原创声明、身份信息匿名化、官方文件命名/大小及上传步骤；本轮未报名或提交。
官方报名截止10月18日23:59，作品截止10月22日，详见COMPETITION_REQUIREMENTS_MATRIX.md链接。请本人确认报名及培养单位资格审核状态。

## 十一、最终审核包
Windows绝对项目根：<LOCAL_PROJECT>
导出路径：<LOCAL_PROJECT>\exports\SecretRadar_round2_review_bundle.zip
ZIP CRC、SHA-256、成员清单与敏感输出检查的实际结果、文件大小和最终Git SHA见exports/ROUND2_BUILD_MANIFEST.json。
归档内ROUND2_BUNDLE_MANIFEST.json包含最终Git SHA和逐成员SHA-256；外部manifest记录ZIP自身哈希，避免循环。
排除.env、所有数据库、runtime/虚拟环境/缓存、模型、Git内部数据与原任务书；第一轮原ZIP/Git bundle留在本地，不重复塞入新包。
本轮未新增第三方依赖，版本和许可证见LICENSES_AND_ATTRIBUTIONS.md及notes/third_party_licenses；未调用任何本地模型。
Linux：TCP22可达，kex_exchange_identification阶段远端关闭，尚未认证。默认身份文件type -1不是本次关闭原因的证明；未部署、未sudo、未改服务。
