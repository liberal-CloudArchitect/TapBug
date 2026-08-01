# audit.log 行格式

`audit.log` 为 **append-only**，每行一条 JSON（JSONL）。并行 subagent 各自追加，不覆盖。

```json
{"ts":"2026-07-05T10:00:00Z","actor":"hermes|recon|exploitation|gatekeeper",
 "phase":"recon","action":"dispatch|tool_call|finding|hitl|deny",
 "target":"api.example.com","detail":"subfinder -d example.com",
 "decision":"allow|ask|deny|approved|rejected","task_id":"recon-001"}
```

字段：
- `ts` UTC ISO8601；`actor` 谁做的；`phase` 阶段；`action` 动作类型；
- `target` 作用对象；`detail` 具体命令/内容；`decision` 护栏或 HITL 结论；`task_id` 关联任务。

用 `hermes/audit.py` 的 `log()` 写入，保证格式一致。
