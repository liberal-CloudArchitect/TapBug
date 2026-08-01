"""技能库 —— 自扩展 agent 的"越用越强"能力沉淀（原子能力 A9）。

把合成成功的 bespoke wheel **泛化**成"参数化、带描述+签名"的可复用技能，落盘 knowledge/skills/*.json。
新题按攻击面**语义检索**命中的技能，先在沙箱试跑（skill-first）；命中直接夺旗（复用学到的能力、更快）。
success/fail 计数排序，坏技能自然沉底/淘汰。

技能结构：
    {id, name, description, vuln_class, signature:[关键词], code:"def solve(base_url, session): ...",
     success_count, fail_count, provenance:{from, reviewed}, created}

⚠️ 仅授权 CTF/靶场使用：由 `enabled()`（= synth.enabled() = CTF_MODE + allow_active）门控；
recon-only / 真实 Bugcrowd 下**不加载、不试跑**。技能带 provenance 便于审计。
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "knowledge" / "skills"


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]{2,}", (text or "").lower()))


# 代码里对匹配无意义的高频词，索引时剔除，避免所有技能都因通用词命中
_STOP = {"def", "solve", "base_url", "session", "http", "return", "none", "for", "in",
         "if", "else", "try", "except", "import", "self", "the", "and", "get", "post",
         "text", "json", "data", "url", "path", "res", "resp", "response", "req", "true", "false"}


def enabled() -> bool:
    """仅 CTF/授权靶场 + 允许主动 时启用（与 synth 同门控）。"""
    try:
        from hermes_ctf_lab import synth
        return synth.enabled()
    except Exception:  # noqa: BLE001
        return False


def _skill_tokens(skill: dict) -> set[str]:
    """一个技能的可检索 token：名称/描述/漏洞类/签名 + 代码关键词（去停用词）。"""
    base = " ".join([skill.get("name", ""), skill.get("description", ""),
                     skill.get("vuln_class", ""), " ".join(skill.get("signature", []))])
    toks = _tokens(base) | (_tokens(skill.get("code", "")) - _STOP)
    return toks


def load_skills() -> list[dict]:
    out = []
    if SKILLS_DIR.exists():
        for f in sorted(SKILLS_DIR.glob("*.json")):
            try:
                out.append(json.loads(f.read_text()))
            except Exception:  # noqa: BLE001
                pass
    return out


def _save(skill: dict) -> dict:
    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    (SKILLS_DIR / f"{skill['id']}.json").write_text(
        json.dumps(skill, ensure_ascii=False, indent=2))
    return skill


def add_skill(code: str, *, name: str = "", description: str = "", vuln_class: str = "",
              signature=None, provenance=None) -> dict | None:
    """新增/更新一个技能。以代码指纹去重：相同代码则合并元数据、不重复建条目。"""
    code = (code or "").strip()
    if not code or "def solve" not in code:
        return None
    fp = hashlib.sha1(code.encode("utf-8", "ignore")).hexdigest()[:16]
    eid = f"skill-{vuln_class or 'x'}-{fp}"
    existing = {s["id"]: s for s in load_skills()}
    cur = existing.get(eid)
    skill = cur or {"id": eid, "success_count": 0, "fail_count": 0,
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    skill.update({
        "name": name or skill.get("name") or (vuln_class or "synthesized") + "-skill",
        "description": description or skill.get("description", ""),
        "vuln_class": vuln_class or skill.get("vuln_class", ""),
        "signature": sorted(set((signature or []) + skill.get("signature", []))),
        "code": code,
        "provenance": provenance or skill.get("provenance", {"from": "synth", "reviewed": False}),
    })
    return _save(skill)


def match(context: str, k: int = 3, min_score: int = 2) -> list[dict]:
    """按攻击面上下文语义检索最相关的技能（token 重叠打分，success_count 打破平手）。"""
    if not enabled():
        return []
    q = _tokens(context)
    if not q:
        return []
    scored = []
    for s in load_skills():
        score = len(q & _skill_tokens(s))
        if score >= min_score:
            # 成功多的略微加权、失败多的降权
            rank = score + 0.3 * s.get("success_count", 0) - 0.2 * s.get("fail_count", 0)
            scored.append((rank, s))
    scored.sort(key=lambda x: -x[0])
    return [s for _, s in scored[:k]]


def record_result(skill_id: str, success: bool) -> None:
    """回写一次试跑结果；坏技能靠 fail_count 自然沉底。"""
    for s in load_skills():
        if s.get("id") == skill_id:
            key = "success_count" if success else "fail_count"
            s[key] = s.get(key, 0) + 1
            _save(s)
            return
