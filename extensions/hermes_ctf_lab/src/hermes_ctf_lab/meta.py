"""统一 Meta 推理循环 + 共享工作记忆（原子能力 G6）。

把 `ctf.agent_hunt` 的**固定级联**（skill→原语→planner→synth）升级成**优先级驱动、共享工作记忆**的
meta 循环：先做**一次**共享侦察 + 题型指纹 → 每轮按指纹给策略打分、选最相关的先跑 → 结果（新观察/
中间产物/失败）回写共享工作记忆供后续策略复用 → 命中即止。相比级联：按题型自适应、少做重复侦察、
跨策略传递中间态；**不降低**任何既有夺旗能力（默认优先级 = 原级联顺序）。

选择机制（混合）：默认启发式指纹打分定序；仅在"顶部打平"或"连续无进展(stuck)"时用一次 LLM 裁决
（有界 ≤LLM_BUDGET 次、`_llm_available()` 才启用，否则退纯启发式）。

⚠️ 仅授权 CTF/靶场：入口 `ctf.agent_hunt` 受 `ctf.enabled()` 门控，各策略自带 skills/synth 门控；
recon-only/真实 Bugcrowd 不进入。
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse

from hermes import tools
from hermes_ctf_lab import outcome

FLAG_RE = re.compile(os.environ.get("HERMES_FLAG_REGEX", r"(?:flag|FLAG|HTB|CTF|xben)\{[^}\s]{1,200}\}"))

# 题型指纹标签（从源码/响应/URL/字段推断），用于给策略与原语探针按相关度定序。
INJECTION_TAGS = {"ssti", "cmdi", "ssrf", "xxe", "graphql", "nosql", "deser", "jwt", "upload", "proto"}
URL_PARAMS = {"url", "uri", "link", "fetch", "host", "path", "dest", "target", "u", "src", "image", "load"}


def _flag_in(text) -> str | None:
    if not isinstance(text, str):
        return None
    m = FLAG_RE.search(text)
    return m.group(0) if m else (text if text.strip().startswith(("flag", "HTB", "CTF")) else None)


class WorkingMemory:
    """贯穿全流程的共享状态：一次侦察、题型指纹、跨策略中间产物、已试/失败记录。"""

    def __init__(self, entrypoints, session=None, source_text="", budget=6):
        self.entrypoints = entrypoints or []
        self.session = session
        self.source = source_text or ""
        self.hosts = list({f"{urlparse(e['url']).scheme}://{urlparse(e['url']).netloc}"
                           for e in self.entrypoints})
        self.observations: dict[str, dict] = {}     # url -> {status, body}
        self.fingerprint: set[str] = set()
        self.artifacts: dict[str, str] = {}          # 跨策略中间产物：token/jwt/secret/泄露串
        self.tried: set[str] = set()
        self.failures: list[str] = []
        self.research_notes = ""
        self.budget = budget
        self.recon_requests = 0                       # 共享侦察请求计数（验证"侦察只做一次"）
        self.findings: list[dict] = []                # G7：非夺旗的 confirmed/partial 结局

    # ---------- 一次性共享侦察 + 指纹 ----------
    def recon_once(self):
        if self.observations:
            return
        urls = []
        for h in self.hosts[:2]:
            urls.append(h.rstrip("/") + "/")
        for e in self.entrypoints:
            urls.append(e["url"])
        for u in list(dict.fromkeys(urls)):           # 去重保序
            try:
                r = tools.get(u, session=self.session)
                self.recon_requests += 1
                self.observations[u] = {"status": r.status_code, "body": r.text[:1500]}
            except Exception:  # noqa: BLE001
                self.observations[u] = {"error": True}
        self._fingerprint()
        self._harvest_artifacts()

    def bodies(self) -> str:
        return " ".join(str(o.get("body", "")) for o in self.observations.values())

    def ctx(self) -> str:
        """技能语义检索/研究线索用的上下文：源码 + URL/字段 + 观察正文。"""
        eps = " ".join((e.get("url", "") + " " + " ".join(e.get("fields") or []))
                       for e in self.entrypoints)
        return (self.source + " " + eps + " " + self.bodies())[:3500]

    def obs_list(self) -> list[dict]:
        """给 Synthesizer 的 observations 形态（含 artifacts/research 作为额外条目）。"""
        out = [{"url": u, **v} for u, v in self.observations.items()]
        if self.artifacts:
            out.append({"url": "(artifacts)", "body": json.dumps(self.artifacts, ensure_ascii=False)[:800]})
        if self.research_notes:
            out.append({"url": "(research)", "body": self.research_notes[:800]})
        return out

    def _fingerprint(self):
        text = (self.source + " " + self.bodies()).lower()
        urls = " ".join(e.get("url", "").lower() for e in self.entrypoints)
        fields = set()
        for e in self.entrypoints:
            fields |= set(map(str.lower, e.get("fields") or []))
        fp = self.fingerprint
        if "graphql" in urls or "graphql" in text or "graphiql" in urls:
            fp.add("graphql")
        if (self.session is not None and any(c.value.count(".") == 2 for c in self.session.cookies.jar)) \
                or "eyj" in text or "jwt" in text:
            fp.add("jwt")
        if "upload" in urls or "file" in fields or "multipart/form-data" in text:
            fp.add("upload")
        if any(k in urls for k in ("login", "auth", "signin")) or \
                ({"username", "user", "email"} & fields and {"password", "pass", "pwd"} & fields):
            fp.add("login")
        if any(k in text for k in ("mongo", "$where", "$ne", "nosql")):
            fp.add("nosql")
        if "{{" in text or any(k in text for k in ("jinja", "twig", "freemarker", "velocity", "mako", "erb")):
            fp.add("ssti")
        if any(k in text for k in ("system(", "os.popen", "subprocess", "exec(", "shell_exec")) or \
                any(k in urls for k in ("ping", "exec", "cmd", "run")):
            fp.add("cmdi")
        if any(p in URL_PARAMS for e in self.entrypoints for p in map(str.lower, e.get("params") or [])) or \
                any(k in text for k in ("requests.get", "urllib", "curl", "file_get_contents")):
            fp.add("ssrf")
        if any(k in text for k in ("pickle", "unserialize", "__reduce__", "marshal", "yaml.load")):
            fp.add("deser")
        if any(k in urls for k in ("redeem", "buy", "coupon", "transfer", "purchase", "vote", "claim", "order", "checkout")):
            fp.add("race")
        if any(k in urls for k in ("admin", "flag", "private", "internal", "manage", "dashboard")):
            fp.add("admin")
        if any(k in urls for k in ("register", "signup", "create", "update", "profile", "account")):
            fp.add("massassign")
        if any(k in urls for k in ("config", "merge", "setting", "import")):
            fp.add("proto")
        if any((e.get("method") == "POST") for e in self.entrypoints) and \
                any(k in text for k in ("<?xml", "xml", "<!doctype", "entity")):
            fp.add("xxe")
        if not (fp & INJECTION_TAGS) and (len(self.entrypoints) >= 2 or "/api" in urls):
            fp.add("logic")

    def _harvest_artifacts(self):
        """从响应正文里捞明显的中间产物（token/JWT/长十六进制），供后续策略（尤其 synth）复用。"""
        blob = self.bodies()
        for m in re.findall(r'"(?:token|secret|key|auth|session)"\s*:\s*"([^"]{6,120})"', blob, re.I):
            self.artifacts.setdefault("token", m)
        for m in re.findall(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", blob):
            self.artifacts.setdefault("jwt", m)
        for m in re.findall(r"\b[0-9a-f]{16,64}\b", blob):
            self.artifacts.setdefault("hex", m)
            break

    def note_failure(self, name, detail=""):
        self.failures.append(f"{name}: {detail}"[:200])

    # ---------- G7：结局分层 ----------
    def add_outcome(self, o):
        if o and o.get("status") not in (None, outcome.MISS):
            self.findings.append(o)

    def best_finding(self):
        best = None
        for o in self.findings:
            best = outcome.better(best, o)
        return best

    def has_confirmed(self) -> bool:
        return any(o.get("status") == outcome.CONFIRMED for o in self.findings)


# ============================ 策略（包装既有能力）============================
class _Strategy:
    name = "base"

    def score(self, wm) -> float:
        return 0.0

    def run(self, wm):
        return None

    def _hit(self, res, via, default_vuln="cmdi"):
        return {"captured": True, "flag": res["flag"], "via": via,
                "method": f"agent/{res.get('reasoner')}·{res.get('vuln', default_vuln)}",
                "payload": res.get("payload")}


class SkillStrategy(_Strategy):
    """复用学到的技能（skill-first）：语义检索 top-K → 合成沙箱试跑 → 命中夺旗。"""
    name = "skill"

    def score(self, wm):
        try:
            from hermes_ctf_lab import skills
            return 10.0 if (skills.enabled() and skills.match(wm.ctx())) else 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    def run(self, wm):
        from hermes_ctf_lab import skills, synth
        import httpx
        base = wm.hosts[0] if wm.hosts else ""
        throwaway = None if wm.session is not None else httpx.Client(follow_redirects=True, timeout=15)
        sess = wm.session if wm.session is not None else throwaway
        tgt = synth._target_of(base)          # 让用 tcp() 的技能（如 LockTalk 原始 HTTP 绕过）能重放
        try:
            for sk in skills.match(wm.ctx(), k=3):
                try:
                    result, _ = synth.run_code(sk.get("code", ""), sess, base, tcp_target=tgt)
                except Exception:  # noqa: BLE001
                    result = None
                flag = _flag_in(result)
                skills.record_result(sk["id"], bool(flag))
                if flag:
                    return {"captured": True, "flag": flag, "via": f"agent-skill:{sk['id']}",
                            "method": f"skill/{sk.get('name', 'reuse')}"}
            return None
        finally:
            if throwaway is not None:
                throwaway.close()


class PrimitiveStrategy(_Strategy):
    """14 原语的**指纹定序**探针集：指纹命中的漏洞类优先跑（保持相对默认顺序），覆盖不减。"""
    name = "primitive"

    def score(self, wm):
        return 6.0 + (2.0 if (wm.fingerprint & INJECTION_TAGS) else 0.0)

    def run(self, wm):
        from hermes_ctf_lab.exploit_agent import ExploitAgent
        from hermes.tools import injectable, probe_params
        agent = ExploitAgent(session=wm.session, source_text=wm.source)
        hosts, eps = wm.hosts, wm.entrypoints
        admin_eps = [e["url"] for e in eps
                     if any(k in e["url"].lower() for k in ("admin", "flag", "secret", "dashboard", "api"))] \
            or [h + "/admin" for h in hosts[:1]]

        def rec(r, via, endpoint, need_flag=False):
            """G7：分类每个原语结果入共享工作记忆（confirmed/partial 都记），达命中条件才返回夺旗。"""
            r = r or {}
            wm.add_outcome(outcome.classify(r, "primitive", endpoint))
            ok = r.get("success") and (bool(r.get("flag")) if need_flag else True)
            return self._hit(r, via) if ok else None

        def p_deser():
            for base in hosts[:2]:
                for ck in ("session", "data", "auth", "user"):
                    hit = rec(agent.solve_deser(base + "/", cookie=ck, goal="flag"),
                              f"agent-deser:{base}:{ck}", base + "/")
                    if hit:
                        return hit

        def p_jwt():
            if wm.session is not None and any(c.value.count(".") == 2 for c in wm.session.cookies.jar):
                for aurl in admin_eps[:3]:
                    hit = rec(agent.solve_jwt(aurl, goal="flag"), f"agent-jwt:{aurl}", aurl)
                    if hit:
                        return hit

        def p_graphql():
            for e in eps:
                u = e["url"]
                if "graphql" in u.lower() or "graphiql" in u.lower():
                    hit = rec(agent.solve_graphql(u, goal="flag"), f"agent-graphql:{u}", u)
                    if hit:
                        return hit

        def p_method():
            for e in eps:
                u = e["url"]
                if any(k in u.lower() for k in ("admin", "flag", "private", "internal", "manage")):
                    hit = rec(agent.solve_method_tamper(u, goal="flag"), f"agent-methodtamper:{u}", u)
                    if hit:
                        return hit

        def p_race():
            for e in eps:
                u = e["url"]
                if e.get("method") == "POST" and any(k in u.lower() for k in
                        ("redeem", "buy", "coupon", "transfer", "purchase", "vote", "claim", "order", "checkout")):
                    hit = rec(agent.solve_race(u, method="POST", goal="flag"), f"agent-race:{u}", u)
                    if hit:
                        return hit

        def p_upload():
            for e in eps:
                u = e["url"]; base = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                if "upload" in u.lower() or (e.get("method") == "POST" and "file" in (e.get("fields") or [])):
                    hit = rec(agent.solve_upload(u, base, goal="flag"), f"agent-upload:{u}", u)
                    if hit:
                        return hit

        def p_authbypass():
            for e in eps:
                u = e["url"]; base = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                lf = set(map(str.lower, e.get("fields") or []))
                if e.get("method") == "POST" and (any(k in u.lower() for k in ("login", "auth", "signin"))
                        or ({"username", "user", "email"} & lf and {"password", "pass", "pwd"} & lf)):
                    hit = rec(agent.solve_nosqli(u, goal="flag", success_url=base + "/admin"),
                              f"agent-nosqli:{u}", u)
                    if hit:
                        return hit
                    hit = rec(agent.solve_xpath(u, goal="flag", success_url=base + "/admin"),
                              f"agent-xpath:{u}", u)
                    if hit:
                        return hit

        def p_massassign():
            for e in eps:
                u = e["url"]; base = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                if e.get("method") == "POST" and any(k in u.lower() for k in
                        ("register", "signup", "create", "update", "profile", "account")):
                    for chk in (base + "/flag", base + "/admin", base + "/me"):
                        hit = rec(agent.solve_mass_assignment(u, check_url=chk, goal="flag"),
                                  f"agent-massassign:{u}", u)
                        if hit:
                            return hit

        def p_proto():
            for e in eps:
                u = e["url"]; base = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                if e.get("method") == "POST" and any(k in u.lower() for k in
                        ("config", "merge", "setting", "import", "profile", "update")):
                    for chk in (base + "/flag", base + "/admin"):
                        hit = rec(agent.solve_proto_pollution(u, chk, goal="flag"), f"agent-proto:{u}", u)
                        if hit:
                            return hit

        def p_xxe():
            for e in eps:
                if e.get("method") == "POST":
                    hit = rec(agent.solve_xxe(e["url"], goal="flag"), f"agent-xxe:{e['url']}", e["url"])
                    if hit:
                        return hit

        def p_inject():
            tried = 0
            for e in eps:
                if tried >= 10:
                    break
                u = e["url"]
                for p in (injectable(e) or probe_params(e))[:4]:
                    if tried >= 10:
                        break
                    tried += 1
                    if p.lower() in URL_PARAMS:
                        hit = rec(agent.solve_ssrf(e, p, goal="flag"), f"agent-ssrf:{u}:{p}", u)
                        if hit:
                            return hit
                    hit = rec(agent.solve_ssti(e, p, goal="flag"), f"agent-ssti:{u}:{p}", u, need_flag=True)
                    if hit:
                        return hit
                    hit = rec(agent.solve_cmdi(e, p, goal="flag"), f"agent-cmdi:{u}:{p}", u, need_flag=True)
                    if hit:
                        return hit

        # (标签集, 探针)；标签命中指纹者优先，保持相对默认顺序 = 原级联顺序
        probes = [({"deser"}, p_deser), ({"jwt"}, p_jwt), ({"graphql"}, p_graphql),
                  ({"admin"}, p_method), ({"race"}, p_race), ({"upload"}, p_upload),
                  ({"login", "nosql"}, p_authbypass), ({"massassign"}, p_massassign),
                  ({"proto"}, p_proto), ({"xxe"}, p_xxe), ({"ssti", "cmdi", "ssrf"}, p_inject)]
        ordered = sorted(range(len(probes)),
                         key=lambda i: (0 if probes[i][0] & wm.fingerprint else 1, i))
        for i in ordered:
            try:
                hit = probes[i][1]()
            except Exception:  # noqa: BLE001
                hit = None
            if hit:
                return hit
        return None


class PlannerStrategy(_Strategy):
    """LLM 多步规划（并行探索 → ReAct 读-抽取-回放 + 回溯）。"""
    name = "planner"

    def score(self, wm):
        from hermes_ctf_lab.exploit_agent import _llm_available
        if not _llm_available() or not wm.entrypoints:
            return 0.0
        return 4.0 + (2.0 if ("logic" in wm.fingerprint or len(wm.entrypoints) >= 3) else 0.0)

    def run(self, wm):
        from hermes_ctf_lab.exploit_agent import ChainPlanner
        pr = ChainPlanner(session=wm.session, source_text=wm.source, max_steps=10).solve(
            wm.hosts[0] if wm.hosts else "", [e["url"] for e in wm.entrypoints])
        if pr.get("success"):
            return {"captured": True, "flag": pr["flag"], "via": pr.get("via", "agent-planner"),
                    "method": f"planner/{pr.get('reasoner')}"}
        wm.add_outcome(outcome.classify(pr, "planner", wm.hosts[0] if wm.hosts else ""))
        wm.note_failure("planner", str(pr.get("reason", "")))
        return None


class SynthStrategy(_Strategy):
    """动态合成利用（现写 wheel + 泛化促进为技能 + 子进程隔离），恒可用的兜底。"""
    name = "synth"

    def score(self, wm):
        from hermes_ctf_lab import synth
        from hermes_ctf_lab.exploit_agent import _llm_available
        if not (synth.enabled() and _llm_available() and wm.entrypoints):
            return 0.0
        return 3.0 + (1.0 if wm.source else 0.0)

    def run(self, wm):
        from hermes_ctf_lab import synth
        syn = synth.Synthesizer(session=wm.session, source_text=wm.source)
        if wm.research_notes:
            syn.research_notes = wm.research_notes            # 复用共享研究，避免重复联网
        syn.learn_failure = not wm.has_confirmed()           # G7：已有确认则不把本轮当死胡同学习
        sr = syn.solve(wm.hosts[0] if wm.hosts else "", observations=wm.obs_list())
        if sr.get("success"):
            return {"captured": True, "flag": sr["flag"], "via": "agent-synth",
                    "method": f"synth/{sr.get('reasoner')}·{sr.get('iters', sr.get('steps', '?'))}iters"}
        wm.add_outcome(outcome.classify(sr, "synth", wm.hosts[0] if wm.hosts else ""))
        wm.note_failure("synth", str(sr.get("reason", "")))
        return None


# ============================ Meta 求解器（混合选择）============================
class MetaSolver:
    LLM_BUDGET = 2
    STRATEGIES = [SkillStrategy, PrimitiveStrategy, PlannerStrategy, SynthStrategy]

    def __init__(self, wm):
        self.wm = wm
        self.strategies = [S() for S in self.STRATEGIES]
        self.llm_budget = self.LLM_BUDGET

    def solve(self) -> dict:
        wm = self.wm
        wm.recon_once()                                       # 共享侦察，全程只做一次
        research_done = False
        for _ in range(wm.budget):
            cand = [(s.score(wm), s) for s in self.strategies if s.name not in wm.tried]
            cand = [(sc, s) for sc, s in cand if sc > 0]
            if not cand:
                break
            cand.sort(key=lambda x: -x[0])
            pick = self._select(cand)
            wm.tried.add(pick.name)
            try:
                res = pick.run(wm)
            except Exception as e:  # noqa: BLE001
                wm.note_failure(pick.name, str(e)); res = None
            if res and res.get("captured"):
                res.setdefault("status", outcome.CAPTURED)
                res.setdefault("confidence", outcome.confidence_for(outcome.CAPTURED))
                res["meta"] = self._meta()
                return res
            # stuck：技能/原语都没中 → 补一次共享研究，让后续 planner/synth 更强
            if not research_done and len(wm.tried) >= 2:
                self._research(wm); research_done = True
        return self._final()

    def _final(self) -> dict:
        """未夺旗收尾：区分 confirmed（确定性证明、值得换法/出报告）vs partial vs 彻底 miss。"""
        best = self.wm.best_finding()
        out = {"captured": False, "status": (best or {}).get("status", outcome.MISS),
               "confidence": (best or {}).get("confidence", 0.0),
               "findings": self.wm.findings, "meta": self._meta()}
        if best:
            out["evidence"] = best.get("evidence"); out["vuln"] = best.get("vuln")
        if best and best.get("status") == outcome.CONFIRMED:      # 确认即出 VRT 草稿供人工核实
            p = self._draft(best)
            if p:
                out["vrt_draft"] = p
        return out

    def _draft(self, finding) -> str | None:
        try:
            from hermes import report
            md = report.draft_report(finding, target=finding.get("endpoint", ""), llm=False)
            os.makedirs("findings", exist_ok=True)
            slug = re.sub(r"[^a-z0-9]+", "-", str(finding.get("vuln", "vuln")).lower()).strip("-")[:40] or "vuln"
            path = os.path.join("findings", f"{slug}-confirmed-vrt-draft.md")
            with open(path, "w") as f:
                f.write(md)
            return path
        except Exception:  # noqa: BLE001
            return None

    def _meta(self):
        return {"tried": sorted(self.wm.tried), "fingerprint": sorted(self.wm.fingerprint),
                "recon_requests": self.wm.recon_requests}

    def _select(self, cand):
        # 顶部明显领先或无 LLM 预算 → 直接选；打平 → 一次 LLM 裁决
        if len(cand) == 1 or (cand[0][0] - cand[1][0]) >= 1.0 or self.llm_budget <= 0:
            return cand[0][1]
        return self._llm_pick([s for _, s in cand[:3]]) or cand[0][1]

    def _llm_pick(self, strategies):
        from hermes.exploit_agent import _llm_available, make_reasoner
        if not _llm_available():
            return None
        self.llm_budget -= 1
        try:
            rz = make_reasoner()
            if not hasattr(rz, "_complete"):
                return None
            names = [s.name for s in strategies]
            prompt = (
                "你在解一个授权 CTF web 题，从候选策略里选**下一个最该试**的，只回一个名字。\n"
                "候选(skill=复用学到技能/primitive=14漏洞原语/planner=多步规划/synth=现写利用): %s\n"
                "题型指纹: %s\n观察摘要: %s\n研究要点: %s\n名字:"
                % (names, sorted(self.wm.fingerprint), self.wm.bodies()[:600], self.wm.research_notes[:300]))
            ans = rz._complete(prompt).strip().lower()
            for s in strategies:
                if s.name in ans:
                    return s
        except Exception:  # noqa: BLE001
            return None
        return None

    def _research(self, wm):
        try:
            from hermes_ctf_lab import research
        except Exception:  # noqa: BLE001
            return
        if not research.enabled():
            return
        tags = [t for t in wm.fingerprint if t not in ("logic", "admin", "login")]
        notes = []
        for t in tags[:2]:
            r = research.research(f"{t} exploit technique payload")
            if r:
                notes.append(f"[{t}]\n{r}")
        if notes:
            wm.research_notes = ("\n".join(notes))[:1500]
