# 第二轮来源与授权验证

公网成功采集来源0；真实泄露发现数量0（无成功公网采集，不能评价实际发现能力）。
网络层已收到GitHub HTTP响应，但被限流的请求不算完整 REAL_REMOTE_TESTED。
用户明确授权的唯一在线仓库为 WanWan66/HuaWeiCup，只读，不含推送/新建公网文件权限。默认 config.example.json 继续deny-all，另有独立授权配置。

| 来源 | 验证状态 | 真实证据 | 剩余限制 |
|---|---|---|---|
| 本地Git | IMPLEMENTED / LOCAL_INTEGRATION_TESTED | 真实Git提交、追加、历史删除、幂等、授权根路径检查 | 历史200提交/500文档有界；不含远程托管成功数 |
| GitHub | IMPLEMENTED / MOCK_TESTED / LOCAL_INTEGRATION_TESTED；公网BLOCKED | 实际回环HTTP及跨轮新增后删除提交检测；用户仓库API两端点限流 | REAL_REMOTE_TESTED=否；初次仅默认分支快照，增量至多100提交，超限失败不推进checkpoint |
| MediaWiki | IMPLEMENTED / MOCK_TESTED / LOCAL_INTEGRATION_TESTED；公网BLOCKED | 实际回环HTTP、新页面及内容去重 | 未获授权公网站点；当前主命名空间有界快照读取，非API侧recentchanges增量 |
| OCI archive | IMPLEMENTED / LOCAL_INTEGRATION_TESTED | 真实archive、digest、路径安全、重复扫描 | 不是在线Registry；历史层扫描，不是合并文件系统 |
| ControlledHTTP | IMPLEMENTED / LOCAL_INTEGRATION_TESTED | 真正watch子进程和20次可访问→持久化计时 | 只允许显式回环，不是新的公网渠道 |
| ControlledDirectory | IMPLEMENTED / LOCAL_INTEGRATION_TESTED | 100/1000/10000实际合成文件 | 仅规模夹具，不算公开渠道 |

GitHub/Wiki的本地服务是受控协议模拟器，不是真正GitHub平台或MediaWiki安装；真实HTTP仅验证传输/解析/增量链路。
两类均具备MOCK_TESTED和LOCAL_INTEGRATION_TESTED证据，不能称为公网真实接入。
没有“只有Mock仍未本地联调”的这两类来源；公网接入阻碍分别为API配额和缺少授权站点。
具体授权仓库与提交端点均HTTP403，X-RateLimit-Remaining=0，且有GitHub请求ID，证据 ROUND2_REMOTE_PROBE.json。没有代理拒绝信号，不能据此判断仓库不存在或私有。
HTTP分别处理代理拒绝、401认证、404不存在或未授权、422参数、429/403限流、5xx服务异常。遵循Retry-After和Reset；不换IP或绕过限流。
Token仅允许独立环境注入，且只发往api.github.com；不给回环协议服务发送Token。没有真实凭据上传或有效性验证。

最少后续信息：本人在本机配置该仓库只读Token或等待合法配额恢复；授权Wiki API URL及允许命名空间。若要REMOTE_AUTHORIZED时效实验，还需本人明确允许发布不可用合成测试文件，当前没有此权限。
