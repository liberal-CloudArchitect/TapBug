"""知识复利子系统（轻量 RAG）—— 原子能力 A8。

跨任务累积 payload/敏感路径/误报模式/经验，并在后续任务中检索复用，形成"越用越强"的复利。
存储：knowledge/store/*.json（每条一个文件，可人读可回写）。
检索：无外部向量库，用关键词/标签 token 重叠打分（离线、零依赖）。

用法：
    from hermes import knowledge
    knowledge.configure(enabled=True)      # 编排开始时按 --no-knowledge 配置
    knowledge.extra_paths()                # infra 专家复用"过往学到的"敏感路径
    knowledge.get_kb().retrieve(tokens)    # 按上下文检索相关经验
    knowledge.get_kb().upsert({...})       # 回写新知识
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "knowledge" / "store"

_state = {"enabled": True, "kb": None}


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_.]+", (text or "").lower()))


class KnowledgeBase:
    def __init__(self, entries: list[dict]):
        self.entries = entries

    @classmethod
    def load(cls) -> "KnowledgeBase":
        entries = []
        if STORE.exists():
            for f in sorted(STORE.glob("*.json")):
                try:
                    entries.append(json.loads(f.read_text()))
                except Exception:  # noqa: BLE001
                    pass
        return cls(entries)

    def extra_paths(self) -> list[str]:
        """过往学到的敏感路径 —— infra 专家在默认字典之外复用。"""
        paths = []
        for e in self.entries:
            if e.get("kind") == "path":
                paths += e.get("paths", [])
        return sorted(set(paths))

    def payloads(self, vuln_class: str) -> list[str]:
        out = []
        for e in self.entries:
            if e.get("kind") == "payload" and e.get("vuln_class") == vuln_class:
                out += e.get("payloads", [])
        return out

    def retrieve(self, tokens, k: int = 3) -> list[dict]:
        q = {t.lower() for t in tokens}
        scored = []
        for e in self.entries:
            text = " ".join([e.get("kind", ""), " ".join(e.get("tags", [])),
                             e.get("note", ""), " ".join(e.get("paths", [])),
                             e.get("vuln_class", "")])
            score = len(q & _tokens(text))
            if score:
                scored.append((score, e))
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:k]]

    def upsert(self, entry: dict) -> dict:
        STORE.mkdir(parents=True, exist_ok=True)
        eid = entry.get("id") or f"kb-{int(time.time() * 1000)}"
        entry["id"] = eid
        entry.setdefault("created", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        (STORE / f"{eid}.json").write_text(json.dumps(entry, ensure_ascii=False, indent=2))
        self.entries = [e for e in self.entries if e.get("id") != eid] + [entry]
        return entry


def configure(enabled: bool = True) -> None:
    _state["enabled"] = enabled
    _state["kb"] = None


def get_kb() -> KnowledgeBase:
    if _state["kb"] is None:
        _state["kb"] = KnowledgeBase.load() if _state["enabled"] else KnowledgeBase([])
    return _state["kb"]


def extra_paths() -> list[str]:
    return get_kb().extra_paths() if _state["enabled"] else []


def enabled() -> bool:
    return _state["enabled"]


# ---------- 利用型跨任务记忆（越用越强，跨会话持久化到 knowledge/store）----------
def exploit_recall(subkind: str) -> list[str]:
    """取回某类学到的利用要素，按成功次数（count）降序，越常成功越优先。"""
    if not _state["enabled"]:
        return []
    for e in get_kb().entries:
        if e.get("kind") == "exploit" and e.get("subkind") == subkind:
            counts = e.get("counts", {})
            vals = e.get("values", [])
            return sorted(vals, key=lambda v: -counts.get(v, 0)) if counts else list(vals)
    return []


def exploit_remember(subkind: str, value: str) -> None:
    """把一条成功的利用要素写回记忆并累加成功次数；落盘到 knowledge/store（跨会话持久）。"""
    if not _state["enabled"] or not value:
        return
    kb = get_kb()
    eid = f"exploit-{subkind}"
    cur = next((e for e in kb.entries if e.get("id") == eid), None)
    counts = dict(cur.get("counts", {})) if cur else {}
    counts[value] = counts.get(value, 0) + 1
    values = sorted(counts, key=lambda v: -counts[v])[:100]
    kb.upsert({"id": eid, "kind": "exploit", "subkind": subkind, "counts": counts,
               "values": values, "note": f"跨任务复用的 {subkind}（按成功次数排序）"})


# ---------- 失败记忆（只学成功不够；记住走过的死路，避免跨会话重蹈）----------
def remember_failure(signature: str, note: str) -> None:
    """记一条失败复盘：signature=题面特征关键词串，note=一句"为何失败/别再试什么"。"""
    if not _state["enabled"] or not note:
        return
    kb = get_kb()
    eid = "exploit-failures"
    cur = next((e for e in kb.entries if e.get("id") == eid), None)
    items = list(cur.get("items", [])) if cur else []
    entry = {"sig": (signature or "")[:400], "note": note.strip()[:400]}
    if entry not in items:
        items.append(entry)
    items = items[-200:]                       # 有界，防无限增长
    kb.upsert({"id": eid, "kind": "failure", "items": items,
               "note": "过往失败复盘（避免重蹈死路）"})


def recall_failures(context: str, k: int = 4) -> list[str]:
    """按当前题面上下文，取回最相关的失败复盘（token 重叠），供合成提示"勿重复"。"""
    if not _state["enabled"]:
        return []
    q = _tokens(context)
    if not q:
        return []
    cur = next((e for e in get_kb().entries if e.get("id") == "exploit-failures"), None)
    if not cur:
        return []
    scored = []
    for it in cur.get("items", []):
        score = len(q & _tokens(it.get("sig", "") + " " + it.get("note", "")))
        if score:
            scored.append((score, it.get("note", "")))
    scored.sort(key=lambda x: -x[0])
    return [n for _, n in scored[:k]]
