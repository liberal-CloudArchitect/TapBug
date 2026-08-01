"""外部/本地基准适配层 —— 让不同来源的题库统一接入自评框架。

- local：自建 vulnerable/secure 靶场（完整 precision/recall）
- xbow：XBOW validation-benchmarks（104 个 CTF，flag 型 → 用"检测代理"召回指标）
- cybench：Cybench 任务（flag 型，需其自有 harness → 提供加载器与映射，标注覆盖边界）

统一数据结构 BenchCase：setup() 起靶返回 URL，detected(verified) 归一化检出集，与 truth 比对。
"""
from hermes_ctf_lab.benchmarks.base import BenchCase, score_case

__all__ = ["BenchCase", "score_case"]
