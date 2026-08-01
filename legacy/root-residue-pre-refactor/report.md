# 安全评估报告：Phase 0/1 本地靶场演练

- **目标**: ['http://127.0.0.1:8899']
- **scope**: in_scope=['localhost', '127.0.0.1'] · localhost允许=True
- **模式**: dry-run（只读） · 并行度=4
- **执行**: Hermes 编排 + Excavator 工具层（2026-07-08T09:53:34Z）· LoopGuard={'executed': 14, 'blocked': 0, 'unique': 14}

## 1. 执行摘要
对 1 个授权目标完成 授权→侦察→测绘→识别→验证→报告 全流程，验证发现 10 条。

| 严重度 | 数量 |
|--------|------|
| P1 | 0 |
| P2 | 4 |
| P3 | 3 |
| P4 | 2 |
| P5 | 1 |

## 2. scope 与方法
PTES 阶段化；多资产并行侦察、多专家并行识别；最小 PoC（只读）；scope 由 hermes.scope 校验，
危险命令由 hooks/guardrail.py 兜底；LoopGuard 防打转与任务预算护栏。

## 3. 发现清单
1. [缺失安全响应头: content-security-policy, x-frame-options, x-content-type-options, strict-transport-security, referrer-policy](findings/missing-sec-headers-127-0-0-1-8899.md) — Security Misconfiguration / server_security_misconfiguration.security_headers
2. [Server 头泄露组件版本: AcmePortal/2.3.1](findings/verbose-server-127-0-0-1-8899.md) — Information Disclosure / server_security_misconfiguration.information_disclosure
3. [参数 q 反射未转义，反射型 XSS](findings/reflected-xss-q-127-0-0-1-8899.md) — XSS / cross_site_scripting_xss.reflected.non_self
4. [API 端点无需鉴权即可访问](findings/api-noauth-127-0-0-1-8899-api-profile.md) — Broken Authentication / broken_authentication_and_session_management.authentication_bypass
5. [API 错误响应泄露内部信息（SQL/堆栈）](findings/api-errleak-127-0-0-1-8899.md) — Information Disclosure / server_security_misconfiguration.information_disclosure.detailed_error_messages
6. [参数 id 存在 IDOR/BOLA：无鉴权即可越权访问他人对象](findings/idor-id-127-0-0-1-8899.md) — Broken Access Control / broken_access_control.idor
7. [敏感文件/路径暴露: /.env](findings/exposed-env-127-0-0-1-8899.md) — Sensitive Data Exposure / sensitive_data_exposure.disclosure_of_secrets
8. [敏感文件/路径暴露: /.git/config](findings/exposed-git-config-127-0-0-1-8899.md) — Sensitive Data Exposure / sensitive_data_exposure.disclosure_of_secrets
9. [敏感文件/路径暴露: /backup.zip](findings/exposed-backup-zip-127-0-0-1-8899.md) — Sensitive Data Exposure / sensitive_data_exposure.disclosure_of_secrets
10. [敏感文件/路径暴露: /admin](findings/exposed-admin-127-0-0-1-8899.md) — Sensitive Data Exposure / server_security_misconfiguration.exposed_sensitive_path

## 4. 合规声明
在授权 scope（本地自建靶场）内进行，遵循最小 PoC、禁 DoS/外泄/持久化。证据已脱敏。

## 5. 附录
- 审计日志：`audit.log` · 状态：`state/state.json` · 知识：`knowledge/`
