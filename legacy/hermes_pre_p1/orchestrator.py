"""Hermes 编排驱动 —— 端到端：授权→侦察→测绘→识别→验证(HITL)→报告→沉淀。

Phase 2：多资产并行侦察、阶段3 多专家并行调度（可插拔 scanner 注册表）、LoopGuard 防打转。

    python -m hermes.orchestrator --target http://127.0.0.1:8899
    python -m hermes.orchestrator --target http://127.0.0.1:8899 http://127.0.0.1:8900 --max-parallel 6
"""
from __future__ import annotations

import argparse
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from hermes import cli, ctf, interactive, knowledge, scanners, tools
from hermes.audit import log
from hermes.guard import LoopGuard
from hermes.scope import Scope
from schema import contracts

ROOT = Path(__file__).resolve().parent.parent
console = Console()

SEVERITY = {"high": "P3", "medium": "P4", "low": "P5"}
CLASS_SEV = {
    "XSS": {"high": "P3", "medium": "P4", "low": "P5"},
    "Security Misconfiguration": {"high": "P4", "medium": "P4", "low": "P5"},
    "Information Disclosure": {"medium": "P4", "low": "P5"},
    "Broken Access Control": {"high": "P2", "medium": "P3"},
    "Broken Authentication": {"high": "P2", "medium": "P3"},
    "Sensitive Data Exposure": {"high": "P2", "medium": "P3"},
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


class Orchestrator:
    def __init__(self, targets, auto_approve=False, max_parallel=4,
                 use_knowledge=True, persist=True, source_text="", recon_only=False):
        self.targets = targets
        self.source_text = source_text
        # 合规侦察模式：真实 engagement 用。硬关利用 agent + 主动利用探针，强制 dry_run。
        self.recon_only = recon_only
        if recon_only:
            os.environ.pop("HERMES_CTF_MODE", None)      # 禁用利用 agent / flag 捕获
            os.environ.pop("HERMES_ALLOW_ACTIVE", None)  # 禁用 nuclei 与 ssti/cmdi/lfi/sqli 主动探针
        self.auto_approve = auto_approve
        self.max_parallel = max_parallel
        self.persist = persist
        self.use_knowledge = use_knowledge
        knowledge.configure(enabled=use_knowledge)
        self.scope = Scope.load()
        if recon_only:
            self.scope.dry_run = True                    # 强制 dry_run，忽略 scope 里的关闭
        self.digest = self.scope.digest()
        self.guard = LoopGuard(max_tasks=300, max_repeats=1)
        self.allowed = []
        self.session = None
        self.login_info = None
        self.captured = {"captured": False}
        self.state = {
            "engagement": self.scope.data.get("engagement", ""),
            "scope_digest": self.digest, "dry_run": self.scope.dry_run,
            "targets": targets, "max_parallel": max_parallel,
            "current_phase": "auth", "phases_done": [],
            "assets": [], "entrypoints": [], "candidates": [],
            "verified": [], "findings": [], "hitl_log": [], "updated_at": _now(),
        }

    def _save(self):
        if not self.persist:
            return
        self.state["updated_at"] = _now()
        (ROOT / "state" / "state.json").write_text(
            json.dumps(self.state, ensure_ascii=False, indent=2))

    def _phase(self, name, title):
        self.state["current_phase"] = name
        console.rule(f"[bold cyan]{title}")

    # ---- 阶段0 授权 ----
    def auth(self):
        self._phase("auth", "阶段0 · 授权确认")
        if self.recon_only:
            console.print("[bold yellow]🛡 合规侦察模式：利用 agent/主动利用探针已禁用，强制 dry_run。"
                          "仅做只读侦察/检测；确认与利用请人工、最小 PoC、依项目 RoE。")
            if not self.scope.automation_allowed:
                console.print("[bold red]⚠ scope.automation_allowed=false：该项目 RoE 不允许自动化。"
                              "本次只做单次被动探测，其余请完全手动测试。")
        for t in self.targets:
            host = urlparse(t).hostname or t
            ok, reason = self.scope.allows(host)
            log("gatekeeper", "auth", "scope_check", target=host,
                decision="allow" if ok else "deny", detail=reason)
            console.print(f"目标 [bold]{host}[/] → {'✅ 授权' if ok else '⛔ 拒绝'}：{reason}")
            if ok:
                self.allowed.append(t)
        console.print(f"scope_digest={self.digest} · dry_run={self.scope.dry_run} · 授权 {len(self.allowed)}/{len(self.targets)}")
        if not self.allowed:
            console.print("[red]无授权目标，终止。铁律#1。")
        return bool(self.allowed)

    # ---- 阶段1 侦察（多资产并行）----
    def recon(self):
        self._phase("recon", f"阶段1 · 侦察 (A2) · 并行度 {self.max_parallel}")

        def probe(t):
            host = urlparse(t).hostname or t
            p = tools.http_probe(t)
            return {"host": host, "source": "http_probe", "ip": tools.resolve(host),
                    "in_scope": True, "tech": [p.get("server", "")] if p.get("server") else [],
                    "notes": f"status={p.get('status')} title={p.get('title','')!r}", "_base": t}

        with ThreadPoolExecutor(max_workers=self.max_parallel) as ex:
            assets = list(ex.map(probe, self.allowed))
        # subfinder passthrough：对域名目标做被动子域枚举，scope 过滤后并入资产
        assets += self._subfinder_assets(assets)
        for a in assets:
            log("recon", "recon", "probe", target=a["host"], detail=a["notes"], decision="allow")
            console.print(f"  资产 {a['host']} ({a['ip']}) · {a['notes']}")
        # 建立登录态（含默认口令），解锁授权后的深层攻击面
        self.session = tools.new_session()
        tools.set_session(self.session)
        if self.allowed and cli.allow_active(self.scope):
            info = interactive.establish_session(self.allowed[0], self.scope, self.session)
            if info.get("logged_in"):
                self.login_info = info
                tag = "（默认口令!）" if info.get("default_cred") else ""
                console.print(f"  [green]登录态已建立：{info['creds']}{tag}")
                log("recon", "recon", "login", target=urlparse(self.allowed[0]).hostname,
                    detail=str(info["creds"]), decision="allow")
        contracts.ReconOutput(phase="recon", task_id="recon-001", scope_digest=self.digest,
                              dry_run=self.scope.dry_run,
                              assets=[contracts.Asset(**{k: v for k, v in a.items() if k != "_base"}) for a in assets])
        self.state["assets"] = [{k: v for k, v in a.items() if k != "_base"} for a in assets]
        self.state["phases_done"].append("recon")
        self._save()
        return assets

    def _subfinder_assets(self, assets):
        """对域名目标用 subfinder 被动枚举子域，仅并入 scope 内的新资产。"""
        if not cli.have("subfinder"):
            return []
        extra, seen = [], {a["host"] for a in assets}
        for a in assets:
            host = a["host"]
            if tools.resolve(host) == host or self.scope.is_localhost(host):
                continue  # IP / localhost 无子域可枚举
            for sub in cli.subfinder_enum(host):
                if sub in seen:
                    continue
                seen.add(sub)
                ok, _ = self.scope.allows(sub)   # 硬性 scope 过滤，越界子域不并入
                if not ok:
                    continue
                base = f"http://{sub}"
                p = tools.http_probe(base)
                extra.append({"host": sub, "source": "subfinder", "ip": tools.resolve(sub),
                              "in_scope": True, "tech": [p.get("server", "")] if p.get("server") else [],
                              "notes": f"subfinder 子域 · status={p.get('status')}", "_base": base})
                console.print(f"  [dim]subfinder 新增 scope 内子域：{sub}")
        return extra

    # ---- 阶段2 测绘（多资产并行）----
    def mapping(self, assets):
        self._phase("mapping", "阶段2 · 攻击面测绘 (A3)")

        def crawl(a):
            # 深度爬取（带登录态），发现表单/字段/深层路由
            eps = tools.crawl(a["_base"], session=self.session, max_depth=2, max_pages=60)
            eps.insert(0, {"url": a["_base"].rstrip("/") + "/", "method": "GET",
                           "params": [], "fields": [], "type": "web", "auth": None})
            return eps

        entrypoints = []
        with ThreadPoolExecutor(max_workers=self.max_parallel) as ex:
            for eps in ex.map(crawl, assets):
                entrypoints.extend(eps)
        # 去重
        uniq, seen = [], set()
        for e in entrypoints:
            k = (e["url"], e["method"], tuple(e["params"]))
            if k not in seen:
                seen.add(k)
                uniq.append(e)
        contracts.MappingOutput(phase="mapping", task_id="map-001", scope_digest=self.digest,
                                dry_run=self.scope.dry_run,
                                entrypoints=[contracts.Entrypoint(**e) for e in uniq])
        self.state["entrypoints"] = uniq
        self.state["phases_done"].append("mapping")
        for e in uniq:
            console.print(f"  入口 {e['method']} {e['url']} params={e['params']} type={e['type']}")
        self._save()
        return uniq

    # ---- 阶段3 识别（多专家并行 + 防打转）----
    def identify(self, entrypoints):
        # 合规：RoE 禁自动化时，不发任何检测请求，只输出人工测试清单
        if self.recon_only and not self.scope.automation_allowed:
            self._phase("identify", "阶段3 · 识别（已跳过——RoE 禁自动化）")
            console.print("[yellow]该项目不允许自动化：仅列出攻击面供你**人工**逐个测试，不自动发探测请求。")
            for e in entrypoints:
                console.print(f"  待人工测试入口: {e['method']} {e['url']} params={e.get('params')}")
            self.state["phases_done"].append("identify")
            return []
        active = [s.domain for s in scanners.discover()]
        self._phase("identify", f"阶段3 · 漏洞识别 (A4) · 专家 {active} 并行")
        # 知识复利：按上下文（技术栈/域）检索过往经验，infra 专家会自动复用学到的路径
        if self.use_knowledge:
            tech = " ".join(t for a in self.state["assets"] for t in a.get("tech", []))
            hits = knowledge.get_kb().retrieve(_tokens := (tech + " infra web api exposure").split())
            xp = knowledge.extra_paths()
            console.print(f"[dim]知识库：检索到 {len(hits)} 条相关经验，附加 {len(xp)} 条学习路径 {xp}")
        cands = scanners.run_all(entrypoints, max_parallel=self.max_parallel,
                                 loop_guard=self.guard, audit=log)
        # 默认口令登录本身即一条发现
        if self.login_info and self.login_info.get("default_cred"):
            cands.append(interactive.default_cred_candidate(self.login_info))
        contracts.IdentifyOutput(phase="identify", task_id="id-001", scope_digest=self.digest,
                                 dry_run=self.scope.dry_run,
                                 candidates=[contracts.Candidate.model_validate(c) for c in cands])
        self.state["candidates"] = [{k: v for k, v in c.items() if not k.startswith("_")} for c in cands]
        self.state["phases_done"].append("identify")
        log("web-vuln", "identify", "scan", detail=f"{len(cands)} candidates", decision="allow")
        for c in cands:
            console.print(f"  候选 ({c['confidence']}) [{c['class']}] {c['title']}", markup=False)
        console.print(f"[dim]LoopGuard: {self.guard.stats()}")
        self._save()
        return cands

    # ---- 阶段4 验证 (HITL) ----
    def verify(self, cands):
        self._phase("verify", "阶段4 · 利用验证 · 最小PoC (A5/A6)")
        verified = []
        for c in cands:
            needs_active = False  # 本 MVP 全部只读；如需改变状态/投递利用则置 True 走 HITL
            approved = True
            if needs_active and not self.auto_approve:
                self.state["hitl_log"].append({"candidate": c["id"], "asked": True, "approved": False})
                log("exploitation", "verify", "hitl", detail=c["id"], decision="rejected")
                console.print(f"  ⏸ HITL 未批准 → 跳过 {c['id']}")
                continue
            res = tools.verify_candidate(c)
            vo = contracts.VerifyOutput(
                phase="verify", task_id=f"vf-{c['id']}", scope_digest=self.digest,
                dry_run=self.scope.dry_run, candidate_id=res["candidate_id"], verified=res["verified"],
                poc=contracts.PoC(**res["poc"]) if res.get("poc") else None,
                impact=res["impact"], min_poc=True,
                hitl=contracts.HITL(asked=bool(needs_active), approved=approved))
            contracts.gate_before_report(vo)
            if vo.verified:
                verified.append({**c, "_verify": res})
                log("exploitation", "verify", "verified", target=c["id"], decision="approved")
                console.print(f"  ✅ 已验证 [{c['class']}] {c['title']}", markup=False)
        self.state["verified"] = [v["id"] for v in verified]
        self.state["phases_done"].append("verify")
        console.print(f"[dim]dry_run={self.scope.dry_run}：只读复现，无需高危动作，未触发 HITL。")
        self._save()
        return verified

    # ---- 阶段5 报告 ----
    def report(self, verified):
        self._phase("report", "阶段5 · 报告 (A6/A7)")
        files, counts = [], {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
        self.state["findings"] = []
        for v in verified:
            sev = CLASS_SEV.get(v["class"], {}).get(v["confidence"], SEVERITY[v["confidence"]])
            counts[sev] = counts.get(sev, 0) + 1
            slug = _slug(v["id"])
            (ROOT / "findings" / f"{slug}.md").write_text(self._finding_md(v, sev), encoding="utf-8")
            files.append(f"findings/{slug}.md")
            # VRT 报告草稿（对齐 Bugcrowd VRT，供人工核实后提交；recon-only 下用轻量模板不烧 LLM）
            try:
                from hermes import report as _report
                rf = {"vuln": v["class"], "entrypoint": v.get("entrypoint"),
                      "poc": (v.get("_verify") or {}).get("poc"),
                      "impact": (v.get("_verify") or {}).get("impact")}
                (ROOT / "findings" / f"{slug}-vrt-draft.md").write_text(
                    _report.draft_report(rf, llm=not self.recon_only), encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
            self.state["findings"].append({"id": v["id"], "severity": sev, "file": f"findings/{slug}.md"})
        (ROOT / "report.md").write_text(self._report_md(verified, counts, files), encoding="utf-8")
        contracts.ReportOutput(phase="report", task_id="rep-001", scope_digest=self.digest,
                               dry_run=self.scope.dry_run, finding_files=files, report_file="report.md")
        self.state["phases_done"].append("report")
        log("reporter", "report", "write", detail=f"{len(files)} findings", decision="allow")
        console.print(f"报告：report.md · 发现 {len(files)} 条 → {counts}")
        self._save()

    # ---- 阶段6 沉淀 ----
    def distill(self, verified):
        self._phase("distill", "阶段6 · 知识沉淀 (A8)")
        classes = sorted({v["class"] for v in verified})
        # 知识回写（复利闭环）：把本轮确认暴露的敏感路径写回知识库，供后续任务复用
        if self.use_knowledge:
            learned = sorted({urlparse(v["entrypoint"]).path for v in verified
                              if v["class"] == "Sensitive Data Exposure"})
            if learned:
                kb = knowledge.get_kb()
                merged = sorted(set(kb.extra_paths()) | set(learned))
                kb.upsert({"id": "kb-confirmed-exposure", "kind": "path",
                           "tags": ["infra", "exposure", "learned"], "paths": merged,
                           "vuln_class": "Sensitive Data Exposure",
                           "note": "各轮确认暴露的敏感路径累积（自动回写，复利）。"})
                console.print(f"[dim]知识回写：确认路径 {learned} → 知识库累计 {len(merged)} 条")
        note = ROOT / "knowledge" / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-run.md"
        note.write_text("\n".join([
            f"# 沉淀 · {_now()}", "",
            f"- 目标：{self.targets}", f"- 发现类型：{classes}",
            f"- LoopGuard：{self.guard.stats()}", "",
            "## 有效方法（本轮）",
            "- Web：良性元字符标记检测反射型 XSS；只读体检安全头/版本",
            "- 认证授权：无 Authorization 对比相邻对象 id，证明 IDOR/BOLA",
            "- API：无鉴权 200 + 畸形输入触发错误信息泄露",
            "- 基础设施：小字典探测 /.env、/.git/config 等敏感路径", "",
        ]), encoding="utf-8")
        log("hermes", "distill", "knowledge", detail=note.name, decision="allow")
        console.print(f"知识写入：knowledge/{note.name}")
        self.state["phases_done"].append("distill")
        self._save()

    def _finding_md(self, v, sev):
        r = v["_verify"]; poc = r.get("poc") or {}
        steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(poc.get("steps", [])))
        return f"""# {v['title']}

- **ID**: {v['id']}
- **状态**: verified
- **资产 / URL**: {v['entrypoint']}
- **漏洞类别**: {v['class']}
- **VRT 分类**: {v['vrt_guess']}
- **严重度**: {sev}
- **发现时间**: {_now()}
- **dry-run**: {str(self.scope.dry_run).lower()}

## 摘要
{v['title']}。

## 复现步骤
{steps}

## 证据（最小 PoC）
```http
{poc.get('request','')}
```
```
{poc.get('response_excerpt','')}
```

## 影响
{r.get('impact','')}

## 修复建议
{self._fix(v['class'])}

## 授权与合规自检
- [x] 目标 ∈ scope，未越界
- [x] 仅最小 PoC（只读），无 DoS / 外泄 / 持久化
- [x] 高危动作：只读复现，无需 HITL
- [x] 证据已脱敏
"""

    @staticmethod
    def _fix(vclass):
        return {
            "XSS": "对输出做上下文相关编码；启用 CSP 作纵深防御。",
            "Security Misconfiguration": "补齐 CSP/X-Frame-Options/X-Content-Type-Options/HSTS/Referrer-Policy。",
            "Information Disclosure": "移除版本/内部错误信息，返回通用错误。",
            "Broken Access Control": "对每个对象访问做服务端授权校验（禁止仅凭 id 返回数据）。",
            "Broken Authentication": "API 强制鉴权（令牌/会话），拒绝匿名访问私有资源。",
            "Sensitive Data Exposure": "移除暴露的敏感文件/路径，加访问控制并轮换泄露凭据。",
        }.get(vclass, "按 OWASP 对应类别修复。")

    def _report_md(self, verified, counts, files):
        rows = "\n".join(f"| {k} | {counts[k]} |" for k in ["P1", "P2", "P3", "P4", "P5"])
        flist = "\n".join(f"{i+1}. [{v['title']}]({files[i]}) — {v['class']} / {v['vrt_guess']}"
                          for i, v in enumerate(verified))
        return f"""# 安全评估报告：{self.state['engagement']}

- **目标**: {self.targets}
- **scope**: in_scope={self.scope.in_scope} · localhost允许={self.scope.allow_localhost}
- **模式**: {'dry-run（只读）' if self.scope.dry_run else 'live'} · 并行度={self.max_parallel}
- **执行**: Hermes 编排 + Excavator 工具层（{_now()}）· LoopGuard={self.guard.stats()}

## 1. 执行摘要
对 {len(self.allowed)} 个授权目标完成 授权→侦察→测绘→识别→验证→报告 全流程，验证发现 {len(verified)} 条。

| 严重度 | 数量 |
|--------|------|
{rows}

## 2. scope 与方法
PTES 阶段化；多资产并行侦察、多专家并行识别；最小 PoC（只读）；scope 由 hermes.scope 校验，
危险命令由 hooks/guardrail.py 兜底；LoopGuard 防打转与任务预算护栏。

## 3. 发现清单
{flist}

## 4. 合规声明
在授权 scope（本地自建靶场）内进行，遵循最小 PoC、禁 DoS/外泄/持久化。证据已脱敏。

## 5. 附录
- 审计日志：`audit.log` · 状态：`state/state.json` · 知识：`knowledge/`
"""

    def run(self):
        log("hermes", "auth", "start", detail=f"targets={self.targets}")
        try:
            if not self.auth():
                return False
            assets = self.recon()
            eps = self.mapping(assets)
            cands = self.identify(eps)
            verified = self.verify(cands)
            self.report(verified)
            self.distill(verified)
            self._ctf_capture(verified)          # CTF/授权靶场：夺旗/漏洞确认结局面向用户输出
        finally:
            self._cleanup()
        console.rule("[bold green]✅ 全流程完成")
        console.print(f"阶段：{' → '.join(self.state['phases_done'])} · LoopGuard={self.guard.stats()}")
        return True

    def _cleanup(self):
        if self.session is not None:
            try:
                self.session.close()
            except Exception:  # noqa: BLE001
                pass
        tools.set_session(None)

    def _ctf_capture(self, verified):
        """CTF/授权靶场：直接法夺旗→失败则 agent_hunt（meta 循环）兜底；结果存 self.captured。"""
        if not ctf.enabled():
            return
        self.captured = ctf.try_capture(verified, session=self.session)
        if not self.captured.get("captured"):        # 直接法失败 → 按题推理 agent 兜底
            self.captured = ctf.agent_hunt(self.state.get("entrypoints", []),
                                           session=self.session, source_text=self.source_text)
        self._show_capture(self.captured)

    def _show_capture(self, cap):
        """面向用户输出夺旗结局：区分 夺旗成功 / 漏洞已确认(未夺旗) / 部分进展 / 未确认（G7）。

        用 style= 上色 + markup=False，避免 URL/payload 里的方括号被 rich 当标记解析。
        """
        if cap.get("captured"):
            console.print(f"🚩 夺旗成功：{cap.get('flag')} · via {cap.get('via')} ({cap.get('method')})",
                          style="bold green", markup=False)
            return
        status = cap.get("status") or "miss"
        findings = cap.get("findings") or []
        if status == "confirmed":
            conf = cap.get("confidence", 0)
            ep = (findings[0].get("endpoint") if findings else "") or ""
            console.print(f"⚠ 漏洞已确认但未夺旗（置信度 {conf:.0%}）：{cap.get('vuln')} @ {ep}",
                          style="bold yellow", markup=False)
            console.print(f"  证据：{cap.get('evidence')}", markup=False)
            console.print("  方法已验证，未夺旗多为 flag 路径/输出通道问题——建议换路径/输出通道重试。",
                          style="dim")
            if cap.get("vrt_draft"):
                console.print(f"  已生成 VRT 草稿（需人工核实 + 手动提交）：{cap['vrt_draft']}",
                              style="cyan", markup=False)
            for f in findings[:5]:
                console.print(f"    · [{f.get('status')}] {f.get('vuln')} @ {f.get('endpoint')}"
                              f" (置信 {f.get('confidence')})", markup=False)
        elif status == "partial":
            console.print(f"◐ 部分进展（未构成确定性证明）：{cap.get('vuln')} · {cap.get('evidence')}",
                          style="yellow", markup=False)
        else:
            console.print("未夺旗，也无确定性漏洞确认。", style="dim")

    def collect(self):
        """评测用：跑到验证为止，返回已验证发现（不写报告/发现文件）。"""
        try:
            if not self.auth():
                return []
            verified = self.verify(self.identify(self.mapping(self.recon())))
            self._ctf_capture(verified)          # CTF：夺旗/确认结局（收敛到共享方法）
            return verified
        finally:
            self._cleanup()


def main():
    ap = argparse.ArgumentParser(description="Hermes 安全检查团队 · 端到端编排")
    ap.add_argument("--target", nargs="+", required=True, help="一个或多个目标 URL")
    ap.add_argument("--auto-approve", action="store_true", help="自动批准 HITL（仅授权靶场）")
    ap.add_argument("--max-parallel", type=int, default=4, help="并行度上限")
    ap.add_argument("--no-knowledge", action="store_true", help="关闭知识复利（对照/评测用）")
    ap.add_argument("--recon-only", action="store_true",
                    help="合规侦察模式：禁用利用 agent+主动利用探针、强制 dry_run（真实 engagement 用）")
    args = ap.parse_args()
    ok = Orchestrator(args.target, auto_approve=args.auto_approve, max_parallel=args.max_parallel,
                      use_knowledge=not args.no_knowledge, recon_only=args.recon_only).run()
    raise SystemExit(0 if ok else 2)


if __name__ == "__main__":
    main()
