"""Handoff 契约的 pydantic 校验（解决 docs/04 G2.2）。

用途：Hermes 在阶段推进前，用这些模型校验专家 subagent 的结构化回传，
不合规即拒绝推进 —— 让多智能体交接从"约定"变成"可强制的规格"。

    from schema.contracts import ReconOutput
    ReconOutput.model_validate_json(subagent_reply_json)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Phase = Literal["auth", "recon", "mapping", "identify", "verify", "report", "distill"]


class Envelope(BaseModel):
    phase: Phase
    task_id: str
    scope_digest: str
    dry_run: bool = True


# ---- 阶段 1 侦察 ----
class Asset(BaseModel):
    host: str
    source: str = ""
    ip: str | None = None
    in_scope: bool
    tech: list[str] = Field(default_factory=list)
    notes: str = ""


class ReconOutput(Envelope):
    assets: list[Asset]
    new_assets_pending_scope_review: list[str] = Field(default_factory=list)


# ---- 阶段 2 测绘 ----
class Entrypoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    auth: str | None = None
    type: Literal["web", "api", "infra"] = "web"


class MappingOutput(Envelope):
    entrypoints: list[Entrypoint]


# ---- 阶段 3 识别 ----
class Candidate(BaseModel):
    id: str
    title: str
    entrypoint: str
    vuln_class: str = Field(alias="class")
    confidence: Literal["low", "medium", "high"] = "low"
    evidence_needed: str = ""
    vrt_guess: str = ""

    model_config = {"populate_by_name": True}


class IdentifyOutput(Envelope):
    candidates: list[Candidate]


# ---- 阶段 4 验证 ----
class PoC(BaseModel):
    request: str
    response_excerpt: str = ""
    steps: list[str] = Field(default_factory=list)


class HITL(BaseModel):
    asked: bool = False
    approved: bool = False


class VerifyOutput(Envelope):
    candidate_id: str
    verified: bool
    poc: PoC | None = None
    impact: str = ""
    min_poc: bool = True
    hitl: HITL


# ---- 阶段 5 报告 ----
class ReportOutput(Envelope):
    finding_files: list[str]
    report_file: str


def gate_before_report(v: VerifyOutput) -> None:
    """交接不变量：未经 HITL 批准的利用结果不得进入报告。"""
    if v.verified and not v.hitl.approved:
        raise ValueError("阶段4 结果未经 HITL 批准，禁止进入报告阶段（铁律#3）。")
