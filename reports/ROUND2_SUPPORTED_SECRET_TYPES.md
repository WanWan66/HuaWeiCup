# 第二轮凭据类型

测试均为合成真值；LOCAL_INTEGRATION_TESTED不是有效性验证。顶层按云凭据、SSH、数据库、API、OAuth、敏感上下文熵候选六组统计，不把AK/SK/Pair或DB URI/口令分别堆成独立厂商类型。

| 类型 | 等级与验证 | 限制 |
|---|---|---|
| AK/SK、单项云AK/单项SK | LOCAL_INTEGRATION_TESTED；开发/留出、歧义及远距离回归 | AWS样式；多云厂商专属规则不足；不跨文件 |
| SSH私钥完整外壳候选 | LOCAL_INTEGRATION_TESTED；OPENSSH/RSA合成外壳 | 不验证私钥；EC/DSA/PKCS8变体尚无逐项完整测试 |
| 数据库URI/口令 | LOCAL_INTEGRATION_TESTED；PostgreSQL、MySQL及URL编码 | 其他协议仅规则实现，未逐项验证 |
| API Token/Key | LOCAL_INTEGRATION_TESTED；赋值、引号、JSON、多候选 | 不覆盖所有厂商前缀 |
| OAuth Client Secret | LOCAL_INTEGRATION_TESTED；跨行/大小写/占位符 | 不验证OAuth应用 |
| 敏感赋值上下文高熵 | LOCAL_INTEGRATION_TESTED；独立合成留出 | 是疑似凭据上下文，不是可靠通用秘密识别 |

私钥头标记、裸高熵/构建ID等是info候选；不生成泄露告警，也不算真实发现。
系统账号密码的通用专用识别、多云厂商、任意编码/二进制、跨文件配对未完整支持。
