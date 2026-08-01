"""联网知识获取 —— 遇到不懂的技法/CVE 就"查资料再造轮子"（原子能力 A10）。

自扩展 agent 不该只吃模型训练里的静态知识：当题面出现未知库/框架/`CVE-xxxx-xxxx` 时，
本模块**自包含地联网检索**（keyless DuckDuckGo HTML 端点 + 抓取要点），再用 LLM 蒸馏成
几条"利用要点"注入合成提示。无需任何 API key；无网络/检索失败时**优雅降级**（返回空串）。

⚠️ 仅授权 CTF/靶场使用：由 `enabled()`（= synth.enabled() = CTF_MODE + allow_active）门控。
**只发公开技法/库名/CVE 查询**——调用方负责不把目标响应正文/敏感数据/URL 放进 query。
结果按 query 进程内缓存，避免同一线索重复联网。
"""
from __future__ import annotations

import re

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
_CACHE: dict[str, str] = {}


def enabled() -> bool:
    """与 synth 同门控：仅 CTF/授权靶场 + 允许主动。"""
    try:
        from hermes_ctf_lab import synth
        return synth.enabled()
    except Exception:  # noqa: BLE001
        return False


def _strip_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = re.sub(r"&[a-z]+;", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _ddg(query: str, timeout: float = 12.0) -> str:
    """keyless 检索：DuckDuckGo HTML 端点。返回标题+摘要拼接文本（失败返回空串）。"""
    import httpx
    try:
        r = httpx.post("https://html.duckduckgo.com/html/", data={"q": query},
                       headers={"User-Agent": _UA}, timeout=timeout,
                       follow_redirects=True)
        if r.status_code >= 400:
            return ""
        html = r.text
    except Exception:  # noqa: BLE001
        return ""
    titles = re.findall(r'class="result__a"[^>]*>(.*?)</a>', html, re.S)
    snips = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', html, re.S)
    out = []
    for t, s in zip(titles[:5], snips[:5]):
        line = (_strip_html(t) + " — " + _strip_html(s)).strip(" —")
        if line:
            out.append(line)
    return "\n".join(out)[:2000]


def _distill(query: str, raw: str) -> str:
    """用 LLM 把检索摘要蒸馏成 3-5 条"可操作的利用要点"；无 LLM 则回退截断原文。"""
    try:
        from hermes_ctf_lab.exploit_agent import make_reasoner
        rz = make_reasoner()
        if not hasattr(rz, "_complete"):
            return raw[:600]
        prompt = (
            "下面是关于某漏洞利用技法/CVE 的公开检索摘要。请提炼成 3-5 条**可操作的利用要点**"
            "（用到的 gadget/payload 形态/前置条件/绕过点），中文，一行一条，不要客套。\n\n"
            f"检索主题: {query}\n检索摘要:\n{raw[:1800]}\n\n利用要点:")
        return rz._complete(prompt).strip()[:900]
    except Exception:  # noqa: BLE001
        return raw[:600]


def research(query: str) -> str:
    """对一个公开技法/CVE 主题联网检索并蒸馏出利用要点。门控关闭/无网络时返回空串。"""
    query = (query or "").strip()
    if not enabled() or not query:
        return ""
    if query in _CACHE:
        return _CACHE[query]
    raw = _ddg(query)
    notes = _distill(query, raw) if raw else ""
    _CACHE[query] = notes
    return notes
