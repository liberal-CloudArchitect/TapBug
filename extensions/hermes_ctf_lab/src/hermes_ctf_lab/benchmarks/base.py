"""基准用例统一抽象与打分。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class BenchCase:
    name: str
    truth: set                                   # 预期检出集合（id 或 漏洞类）
    setup: Callable[[], str | None]              # 起靶，返回 target URL 或 None
    teardown: Callable[[], None]                 # 拆靶
    normalize: Callable[[list], set]             # verified findings -> 检出集
    mode: str = "full"                           # full=算 precision/recall；recall=仅召回（ground truth 不完整）
    meta: dict = field(default_factory=dict)
    env: dict = field(default_factory=dict)      # 运行该用例时临时施加的环境变量（如放开主动工具）


def score_case(truth: set, detected: set, mode: str = "full") -> dict:
    tp = detected & truth
    fp = detected - truth
    fn = truth - detected
    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / len(truth) if truth else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    out = {"detected": detected, "tp": tp, "fp": fp, "fn": fn,
           "precision": precision, "recall": recall, "f1": f1, "mode": mode}
    if mode == "recall":
        # ground truth 不完整（如 XBOW 只声明目标漏洞）→ precision 无意义，只看是否命中目标
        out["hit"] = bool(tp)
    return out
