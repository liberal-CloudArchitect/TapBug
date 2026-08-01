# Pre-refactor root residue (archived 2026-08-01)

这些文件是**重构前扫描/CTF 原型**在源码工作区根目录直接读写的运行数据，正是
[`docs/06-项目现状审计与重构方案.md`](../../docs/06-项目现状审计与重构方案.md) §106 指出的
「运行数据污染源码工作区」问题：旧原型每次 run 覆盖根目录 `state/state.json`、`report.md`，
向 `audit.log` 和 `knowledge/` 追加写入。

当前受治理运行时**不再写根目录**，所有 run 产物写入 run-scoped 的 `runs/<id>/`。
主包代码（`src/hermes`）不引用这些根路径（`learning.py` 的 `knowledge/...` 是 run 内相对
artifact 路径，经 `context.write_text` 写入 `runs/<id>/knowledge/`，与此处无关）。

因此这些文件仅作历史留存，**不代表当前产品输出**，审计时不应据此判断当前能力。

## 内容

| 路径 | 说明 |
|---|---|
| `audit.log` | 旧原型审计日志（含 exploitation 类动作），~320KB |
| `report.md` | 旧「Phase 0/1 本地靶场演练」报告 |
| `state/` | 旧 dry-run 状态结构（`state.json` + `state.example.json`） |
| `findings/` | 旧 SSTI VRT 草稿 |
| `knowledge/` | 旧原型知识沉淀（run markdown 日志 + `skills/` + `store/`） |

## 还原

如需恢复到根目录（逆操作）：

```bash
cd /Volumes/Samsung/TapBug/Hermes-安全检查团队
mv legacy/root-residue-pre-refactor/{audit.log,report.md,state,findings,knowledge} .
```
