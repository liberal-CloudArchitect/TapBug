# <发现标题：影响 + 位置，如"反射型 XSS 于 /search 的 q 参数">

- **ID**: <finding-slug>
- **状态**: draft | verified | submitted
- **资产 / URL**: <受影响的 in-scope 目标>
- **漏洞类别**: <如 XSS > Reflected>
- **VRT 分类**: <对齐 Bugcrowd VRT，如 P3 / cross_site_scripting_xss.reflected>
- **CVSS v3.1**: <向量串 + 分值，可选>
- **严重度**: P1 | P2 | P3 | P4 | P5
- **发现时间**: <YYYY-MM-DD>
- **dry-run**: <true/false —— 是否已实际验证>

## 摘要
<一句话说明漏洞与业务影响。>

## 复现步骤
1. …
2. …
3. …

## 证据（最小 PoC）
> 仅保留证明影响所需的最小请求/响应。禁止外泄真实用户数据；截图/日志需脱敏。

```http
<最小 PoC 请求>
```
```
<关键响应片段>
```

## 影响
<被证明的具体影响：会话窃取 / 越权读取 / … 。基于证据，不夸大。>

## 修复建议
<针对性、可操作的修复。>

## 授权与合规自检
- [ ] 目标 ∈ scope，未越界
- [ ] 仅最小 PoC，无 DoS / 外泄 / 持久化
- [ ] 高危动作已经过 HITL
- [ ] 证据已脱敏
