# Handoff 契约（阶段间结构化交接）

> 解决 docs/04 的 G2.2/G3.3：多智能体可靠性系于交接结构。Hermes 分派专家时传入 `input`，
> 专家必须回传符合对应 `output` 的结构。可用 `schema/contracts.py`（pydantic）做校验。

所有交接对象都是 JSON。通用信封：

```json
{
  "phase": "recon",              // 当前阶段
  "task_id": "recon-001",        // 唯一任务 id
  "scope_digest": "sha/摘要",     // 引用的 scope 快照，防越界漂移
  "dry_run": true,
  "payload": { ... }             // 各阶段专属，见下
}
```

## 阶段 1 · 侦察（Hermes → recon → Hermes）
- **input.payload**: `{ "targets": ["example.com"], "passive_only": true }`
- **output.payload**:
```json
{ "assets": [ {"host":"api.example.com","source":"subfinder","ip":"203.0.113.10",
              "in_scope":true,"tech":["nginx"],"notes":""} ],
  "new_assets_pending_scope_review": ["cdn.example.com"] }
```

## 阶段 2 · 攻击面测绘（Hermes → attack-surface-mapper → Hermes）
- **input.payload**: `{ "assets": [...见上...] }`
- **output.payload**:
```json
{ "entrypoints": [ {"url":"https://api.example.com/v1/users","method":"GET",
                   "params":["id"],"auth":"bearer","type":"api"} ] }
```

## 阶段 3 · 漏洞识别（Hermes → web-vuln/authz/api/infra → Hermes）
- **input.payload**: `{ "entrypoints": [...], "domain":"web" }`
- **output.payload**:
```json
{ "candidates": [ {"id":"cand-web-001","title":"反射型 XSS 于 q 参数",
   "entrypoint":"https://.../search?q=","class":"XSS","confidence":"medium",
   "evidence_needed":"注入 payload 回显","vrt_guess":"XSS > Reflected"} ] }
```

## 阶段 4 · 利用验证（Hermes → exploitation → Hermes；强制 HITL）
- **input.payload**: `{ "candidate": {...}, "hitl_approved": false }`
- **output.payload**:
```json
{ "candidate_id":"cand-web-001","verified":true,
  "poc":{"request":"...","response_excerpt":"...","steps":["1..","2.."]},
  "impact":"会话窃取","min_poc":true,"hitl":{"asked":true,"approved":true} }
```

## 阶段 5 · 报告（Hermes → reporter → Hermes）
- **input.payload**: `{ "verified_findings": [...] }`
- **output.payload**: `{ "finding_files": ["findings/reflected-xss-search.md"], "report_file":"report.md" }`

## 交接不变量（Hermes 每次推进前校验）
1. `scope_digest` 与当前 `scope.yaml` 一致，否则拒绝推进（防中途篡改越界）；
2. 阶段 4 输出必须 `hitl.approved==true` 才可进入报告；
3. 任何 `new_assets_pending_scope_review` 非空时，先走守门人复核再继续。
