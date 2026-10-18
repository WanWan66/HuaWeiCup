# 第三方组件与 AI 归属

本项目 sources/detectors/pipeline/storage/api/dashboard/evaluation 是此轮 AI 辅助新编写的项目实现，不是学生独立完成声明。
项目代码自身许可证由用户/权利人后续决定，本轮未代替用户作开放许可授权。

| Python 发行包 | 实测版本 | 许可证元数据/发行包许可证 |
|---|---|---|
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| fastapi | 0.115.12 | MIT |
| h11 | 0.16.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| iniconfig | 2.3.1 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pip | 25.2 | MIT |
| pluggy | 1.7.0 | MIT |
| pydantic | 2.14.1 | MIT |
| pydantic_core | 2.50.1 | MIT |
| pytest | 8.3.5 | MIT |
| starlette | 0.46.2 | BSD-3-Clause |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| uvicorn | 0.34.2 | BSD-3-Clause |

完整机器可读元数据见 reports/dependencies.json；从发行包复制的许可证原文位于 notes/third_party_licenses/（42 个文件）。
pip 只用于安装；Python 3.13.9 为 PSF License，标准库 sqlite3 使用 SQLite 3.50.4（public domain）。
Git git version 2.55.0.windows.5 为 GPL-2.0 项目，仅外部 CLI 调用，不分发 Git 程序。
未集成 Gitleaks/TruffleHog，未使用大模型权重，无 Qwen/Ollama 调用；模型名称和模型输入脱敏状态均为 N/A。
FastAPI / Uvicorn 提供 HTTP 服务，pytest 提供测试，其余为这些组件的传递依赖。没有 Jinja2，模板用 Python 标准库安全转义。
依赖兼容性 pip check 实际通过；未执行安全漏洞数据库审计，不能据此宣称无已知漏洞。
