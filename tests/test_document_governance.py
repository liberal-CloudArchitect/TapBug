"""Regression checks for the authority and traceability documentation surface."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REQUIREMENT_IDS = (
    "GOV-01",
    "GOV-02",
    "GOV-03",
    "GOV-04",
    "GOV-05",
    "GOV-06",
    "AGT-01",
    "AGT-02",
    "AGT-03",
    "AGT-04",
    "AGT-05",
    "CAP-01",
    "CAP-02",
    "CAP-03",
    "CAP-04",
    "CAP-05",
    "CAP-06",
    "CAP-07",
    "DET-01",
    "DET-02",
    "DET-03",
    "DET-04",
    "DET-05",
    "NFR-01",
    "NFR-02",
    "NFR-03",
    "NFR-04",
    "NFR-05",
    "NFR-06",
    "NFR-07",
    "NFR-08",
)


def _read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def _row_ids(document: str) -> list[str]:
    return re.findall(r"^\| ((?:GOV|AGT|CAP|DET|NFR)-\d{2}) \|", document, re.MULTILINE)


def test_prd_is_the_single_current_contract_and_records_requirement_history() -> None:
    prd = _read("08-当前权威产品需求文档.md")

    for required in (
        "文档状态：现行、规范性",
        "v1：多专家安全评估",
        "v2：合规、审批和证据治理",
        "v3：未知问题学习和受治理 Wheel",
        "批准后的最小主动 PoC",
        "HermesAcpProvider",
        "extensions/hermes_ctf_lab",
        "Wheel 是 v3 后续扩展",
        "VRT 格式对齐",
        "内部 `validated`",
        "平台可实际提交",
    ):
        assert required in prd


def test_traceability_matrix_has_one_primary_and_one_evidence_row_per_requirement() -> None:
    matrix = _read("09-需求追踪矩阵.md")
    primary, remainder = matrix.split("## 2.1 逐项证据路径与外部条件", maxsplit=1)
    evidence, _stage_summary = remainder.split("## 3. 阶段验收总览", maxsplit=1)

    assert set(_row_ids(primary)) == set(REQUIREMENT_IDS)
    assert len(_row_ids(primary)) == len(REQUIREMENT_IDS)
    assert set(_row_ids(evidence)) == set(REQUIREMENT_IDS)
    assert len(_row_ids(evidence)) == len(REQUIREMENT_IDS)
    assert "权威证据路径" in evidence
    assert "外部条件 / 未外推边界" in evidence


def test_historical_baselines_have_explicit_closure_tables() -> None:
    review = _read("04-文档评审与差距分析.md")
    audit = _read("06-项目现状审计与重构方案.md")

    assert "历史审计基线，非现行产品契约" in review
    assert "历史问题关闭表" in review
    assert "历史审计与重构基线，非当前实现状态报告" in audit
    assert "历史审计问题关闭表" in audit


def test_engagement_guide_preserves_local_only_boundary_and_delivery_levels() -> None:
    guide = _read("05-真实engagement合规使用手册.md")
    prd = _read("08-当前权威产品需求文档.md")

    assert "PRD 1.6" in guide
    assert "不支持对真实 Bugcrowd/HackerOne 资产自动执行检测" in guide
    assert "固定 `passive_parser` 已通过真实 ACP/Docker" in guide
    assert "交付等级不得混用" in prd
