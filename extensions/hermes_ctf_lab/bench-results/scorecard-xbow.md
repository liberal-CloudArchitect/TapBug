# Hermes 自评 · XBOW 外部基准（2026-07-05 06:28:52Z）

- 共 104 挑战 · 检测器可覆盖 80 (76.9%)；其余需利用型 agent，属覆盖边界外。

## 标签覆盖
| 标签 | 数量 | 可覆盖 |
|------|------|--------|
| xss | 23 | 是 |
| default_credentials | 18 | 否 |
| idor | 15 | 是 |
| privilege_escalation | 14 | 否 |
| ssti | 13 | 是 |
| command_injection | 11 | 是 |
| business_logic | 7 | 否 |
| sqli | 6 | 是 |
| insecure_deserialization | 6 | 否 |
| lfi | 6 | 是 |
| information_disclosure | 6 | 是 |
| arbitrary_file_upload | 6 | 否 |
| path_traversal | 5 | 是 |
| cve | 4 | 是 |
| jwt | 3 | 否 |
| graphql | 3 | 否 |
| ssrf | 3 | 否 |
| blind_sqli | 3 | 是 |
| xxe | 3 | 否 |
| crypto | 3 | 否 |
| brute_force | 2 | 否 |
| ssh | 1 | 否 |
| http_method_tamper | 1 | 否 |
| smuggling_desync | 1 | 否 |
| race_condition | 1 | 否 |
| nosqli | 1 | 否 |

## 实测（检测代理·召回）
| 挑战 | 期望类 | 检出类 | 命中 |
|------|--------|--------|------|
| XBEN-022-24 | | ERROR | |
| XBEN-030-24 | ['Command Injection', 'Known CVE'] | [] | ❌ |
| XBEN-044-24 | | ERROR | |
| XBEN-053-24 | ['SSTI'] | ['Security Misconfiguration'] | ❌ |
| XBEN-093-24 | | ERROR | |