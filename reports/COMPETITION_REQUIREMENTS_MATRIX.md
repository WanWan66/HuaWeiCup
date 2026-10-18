# 题目3官方要求对照与参赛可行性

依据：[官方邀请函](https://cpipc.acge.org.cn/cw/contestNews/detail/2c90800c8093eef401809d33b36f0652/2c9080199ed8b78d019ed96ceea21560?page=1)、[题目3所在官方赛题附件](https://cpipc.acge.org.cn/sysFile/downFile.do?fileId=404b13ab51f64f52adb72bbcef926cfc)。
官方附件的题目3文档SHA-256：05bd94c02d08e1dcf009247946b3e34100f2782b2f2509379f11a650e11a489f。只读提取证据见notes/round2_official/SOURCE.json；附件文字不在本审查包再全文分发。
官方列出以下五类评价维度，但未在取得的题目文字中给出数值门槛或权重，不能虚构分值。

| 官方评价维度（概括） | 实现位置 | 测试方法 | 实际证据 | 完成等级 | 不足 |
|---|---|---|---|---|---|
| 公开渠道的类别与数量 | sources/local.py、remote.py、registry.py | 本地Git/OCI、GitHub/Wiki回环HTTP、授权仓库请求 | ROUND2_SUPPORTED_SOURCES、PROTOCOL_EVIDENCE、REMOTE_PROBE | PARTIAL；公网REAL_REMOTE_TESTED=0 | 受控来源不算公开渠道成功接入；Wiki缺授权、GitHub限流 |
| 凭据类别与数量 | detectors/rules.py | 冻结开发/留出及边界回归 | ROUND2_DETECTION_EVALUATION | LOCAL_INTEGRATION_TESTED（合成） | 六组覆盖，云厂商/业务账号/编码覆盖不足 |
| 新来源和规则扩展能力 | Source协议、registry、version、--full | 多源worker、规则变更拒绝增量并显式回扫 | pytest与对应代码 | LOCAL_INTEGRATION_TESTED | 无第三方扩展独立开发验证 |
| 实际发现数量 | pipeline/scan、storage | 合成注入与持久化事件 | 控制实验20次，规模最多1000合成告警 | 实际第三方真实泄露发现0 | 测试数绝不冒充真实发现数，无成功公网采集 |
| 发现时间与公开时间关系 | watch、Document时间字段 | 两档间隔各10次发布到持久化测量 | ROUND2_TIMING | LOCAL_CONTROLLED | REMOTE_AUTHORIZED=N/A，不能证明公网时效 |

可行性：本轮具备可审查代码、真实持续运行、可复现合成评测与规模证据，但公开渠道/真实发现/远程时效三个证据缺口直接影响题目核心评价；不提前宣称获奖能力。
官方邀请函还规定报名截止2026-10-18 23:59、作品截止2026-10-22。本人需确认报名和资格审核已完成；这不是自动报名或提交授权。
正式材料要求PDF与可执行程序、独立完成及身份信息要求以官方通知/模板为准。赛事AI辅助范围未明确确认，不能代签原创声明。
