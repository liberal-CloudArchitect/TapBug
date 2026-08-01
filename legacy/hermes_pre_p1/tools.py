"""Excavator 工具层 · 底层原语 —— 供各 scanner 与编排器复用。

纯 Python（httpx + bs4），零外部 CLI 依赖；读优先、最小影响。
支持：持久会话（登录态/cookie）、深度爬取（表单+字段）、GET/POST 注入、由 _check 驱动的通用验证。
高层检测逻辑在 hermes/scanners/*.py（可插拔）。
"""
from __future__ import annotations

import re
import socket
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx
from bs4 import BeautifulSoup

# 无已知参数时，对 actiony 端点补探的常见参数名（覆盖大量真实靶场的参数命名）
COMMON_PARAMS = ["name", "cmd", "command", "service", "service_name", "host", "ip",
                 "url", "file", "path", "page", "q", "id", "input", "data", "search",
                 "target", "tmpl", "template", "msg", "text", "user"]

UA = "Hermes-Excavator/0.4 (+authorized-security-testing)"
SEC_HEADERS = [
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "strict-transport-security", "referrer-policy",
]
XSS_MARKER = "hxss7q1z"
XSS_PROBE = f'{XSS_MARKER}"><svg'

# ---------- 会话（登录态复用） ----------
_SESSION: httpx.Client | None = None


def new_session(timeout=8.0) -> httpx.Client:
    return httpx.Client(headers={"User-Agent": UA}, timeout=timeout, follow_redirects=True)


def set_session(c: httpx.Client | None) -> None:
    global _SESSION
    _SESSION = c


def get_session() -> httpx.Client | None:
    return _SESSION


def _oneoff(timeout=8.0):
    return httpx.Client(headers={"User-Agent": UA}, timeout=timeout, follow_redirects=True)


def send(method, url, *, params=None, data=None, content=None, headers=None, session=None):
    kw = {"params": params, "headers": headers or {}}
    if content is not None:      # 原始请求体（如 XML/JSON 文本）
        kw["content"] = content
    else:
        kw["data"] = data
    c = session or _SESSION
    if c is not None:
        return c.request(method, url, **kw)
    with _oneoff() as c2:
        return c2.request(method, url, **kw)


def get(url, headers=None, session=None):
    return send("GET", url, headers=headers, session=session)


def upload(url, field, filename, content, session=None, ctype="text/plain"):
    """multipart 文件上传（任意文件上传利用用）。"""
    files = {field: (filename, content, ctype)}
    c = session or _SESSION
    return (c.post(url, files=files) if c is not None else _oneoff().post(url, files=files))


def post(url, data=None, headers=None, session=None):
    return send("POST", url, data=data, headers=headers, session=session)


# ---------- 侦察原语 ----------
def http_probe(url: str) -> dict:
    out = {"url": url, "alive": False}
    try:
        r = get(url)
        out.update(alive=True, status=r.status_code, server=r.headers.get("server", ""))
        soup = BeautifulSoup(r.text, "html.parser")
        out["title"] = (soup.title.string.strip() if soup.title and soup.title.string else "")
        present = {h.lower() for h in r.headers.keys()}
        out["missing_security_headers"] = [h for h in SEC_HEADERS if h not in present]
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _form_entry(page_url, form) -> dict:
    action = urljoin(page_url, form.get("action") or page_url)
    method = (form.get("method") or "GET").upper()
    inputs = form.find_all(["input", "textarea", "select"])
    fields = [i.get("name") for i in inputs if i.get("name")]
    pwd_field = next((i.get("name") for i in inputs
                      if (i.get("type") or "").lower() == "password" and i.get("name")), None)
    user_field = next((i.get("name") for i in inputs
                       if i.get("name") and i.get("name") != pwd_field
                       and (i.get("type") or "text").lower() in ("text", "email", "")), None)
    return {"url": action.split("?")[0], "method": method,
            "params": fields if method == "GET" else [], "fields": fields,
            "type": "web", "auth": None, "is_login": bool(pwd_field),
            "pwd_field": pwd_field, "user_field": user_field}


_FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.open)\(\s*['"]([^'"]+)['"]""")
_JSONKEY_RE = re.compile(r"""JSON\.stringify\(\s*\{([^}]*)\}""")
_KEY_RE = re.compile(r"""['"]?(\w+)['"]?\s*:""")


def _js_entries(page_url, html_text, origin) -> list[dict]:
    """从内联 JS 里挖出 fetch/axios/XHR 端点（表单发现不到的 JS-only API）。"""
    eps = []
    is_json = "application/json" in html_text or "JSON.stringify" in html_text
    is_post = re.search(r"method\s*:\s*['\"]POST['\"]", html_text, re.I) is not None
    keys = []
    for km in _JSONKEY_RE.finditer(html_text):
        keys += _KEY_RE.findall(km.group(1))
    for m in _FETCH_RE.finditer(html_text):
        full = urljoin(page_url, m.group(1))
        p = urlparse(full)
        if p.netloc != origin.netloc or not p.path:
            continue
        method = "POST" if (is_post or keys) else "GET"
        eps.append({"url": full.split("?")[0], "method": method,
                    "params": list(parse_qs(p.query)) if method == "GET" else [],
                    "fields": list(dict.fromkeys(keys)) if method == "POST" else [],
                    "type": "api", "auth": None, "is_login": False,
                    "ctype": "json" if (is_json and method == "POST") else None})
    return eps


def discover_endpoints(base_url: str, max_links: int = 40) -> list[dict]:
    """浅层入口发现（兼容旧调用）；深度爬取见 crawl()。"""
    return crawl(base_url, max_depth=1, max_pages=max_links)


def crawl(base_url: str, session=None, max_depth: int = 2, max_pages: int = 60) -> list[dict]:
    """同源 BFS 深度爬取，收集链接入口与表单（含字段名与 method）。会带上当前会话（登录态）。"""
    origin = urlparse(base_url)
    start = base_url.rstrip("/") + "/"
    queue, seen_urls = [(start, 0)], set()
    entrypoints, seen_ep, seen_js = [], set(), set()

    def add(ep):
        k = (ep["url"], ep["method"], tuple(ep.get("fields") or ep.get("params") or []))
        if k not in seen_ep:
            seen_ep.add(k)
            entrypoints.append(ep)

    while queue and len(seen_urls) < max_pages:
        url, depth = queue.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        try:
            r = get(url, session=session)
        except Exception:  # noqa: BLE001
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for f in soup.find_all("form"):
            add(_form_entry(url, f))
        for ep in _js_entries(url, r.text, origin):
            add(ep)
        # 抓同源外部 JS（<script src=...>）里的 API 端点——专家会读 JS
        for sc in soup.find_all("script"):
            src = sc.get("src")
            if not src or len(seen_js) >= 8:
                continue
            js_url = urljoin(url, src)
            if urlparse(js_url).netloc != origin.netloc or js_url in seen_js:
                continue
            seen_js.add(js_url)
            try:
                for ep in _js_entries(url, get(js_url, session=session).text, origin):
                    add(ep)
            except Exception:  # noqa: BLE001
                pass
        for a in soup.find_all("a"):
            h = a.get("href")
            if not h or h.startswith(("mailto:", "javascript:", "#")):
                continue
            full = urljoin(url, h).split("#")[0]
            p = urlparse(full)
            if p.netloc != origin.netloc:
                continue
            params = list(parse_qs(p.query).keys())
            etype = "api" if "/api" in p.path or "json" in p.path else "web"
            add({"url": full.split("?")[0], "method": "GET", "params": params,
                 "fields": [], "type": etype, "auth": None, "is_login": False})
            nxt = full.split("?")[0]
            if depth < max_depth and nxt not in seen_urls:
                queue.append((nxt, depth + 1))
    return entrypoints


# ---------- 注入（GET 查询 / POST 表单，均带会话） ----------
def injectable(ep: dict) -> list[str]:
    if (ep.get("method") or "GET").upper() == "POST":
        return ep.get("fields") or []
    return ep.get("params") or ep.get("fields") or []


def probe_params(ep: dict) -> list[str]:
    """要探测的参数：已发现的优先；若为空且端点像"动作端点"，补一小批常见参数名（有界）。"""
    ps = injectable(ep)
    if ps:
        return ps
    path = urlparse(ep["url"]).path
    actiony = (ep.get("method") or "GET").upper() == "POST" or ep.get("type") == "api" \
        or (path not in ("", "/") and path.count("/") >= 1)
    return COMMON_PARAMS[:12] if actiony else []


def inject(ep: dict, param: str, payload: str, session=None, filler="test"):
    """把 payload 注入 ep 的某参数，返回 (response, request_dict)。支持 GET 查询 / POST 表单 / POST JSON。"""
    method = (ep.get("method") or "GET").upper()
    url = ep["url"].split("?")[0]
    fields = ep.get("fields") or [param]
    if method == "POST" and ep.get("ctype") == "json":
        body = {f: filler for f in fields}
        body[param] = payload
        req = {"method": "POST", "url": url, "json": body}
        c = session or _SESSION
        r = (c.post(url, json=body) if c is not None else _oneoff().post(url, json=body))
    elif method == "POST":
        data = {f: filler for f in fields}
        data[param] = payload
        req = {"method": "POST", "url": url, "data": data}
        r = post(url, data=data, session=session)
    else:
        q = {k: v[0] for k, v in parse_qs(urlparse(ep["url"]).query).items()}
        q[param] = payload
        req = {"method": "GET", "url": url, "params": q}
        r = send("GET", url, params=q, session=session)
    return r, req


# ---------- 候选构造 ----------
def make_candidate(slug, entrypoint, title, vclass, confidence, vrt, *,
                   check: dict, impact: str, steps: list[str] | None = None) -> dict:
    return {"id": slug, "title": title, "entrypoint": entrypoint, "class": vclass,
            "confidence": confidence, "evidence_needed": "只读复现", "vrt_guess": vrt,
            "_check": check, "_impact": impact, "_steps": steps or [f"GET {entrypoint}"]}


# ---------- 通用验证（由 _check 驱动） ----------
def verify_candidate(cand: dict) -> dict:
    url = cand["entrypoint"]
    check = cand.get("_check") or {}
    res = {"candidate_id": cand["id"], "verified": False, "poc": None,
           "impact": cand.get("_impact", ""), "min_poc": True}
    try:
        kind = check.get("kind")
        ok, excerpt, req = False, "", f"GET {url}"
        if kind == "reproduce":
            rq = check["request"]
            if rq.get("json") is not None:
                c = _SESSION
                r = (c.post(rq["url"], json=rq["json"]) if c is not None else _oneoff().post(rq["url"], json=rq["json"]))
                body_desc = f"json={rq['json']}"
            else:
                r = send(rq["method"], rq["url"], params=rq.get("params"), data=rq.get("data"))
                body_desc = f"data={rq.get('data')}" if rq.get("data") else f"params={rq.get('params')}"
            needle = check["needle"]
            ok = needle in r.text
            excerpt = _excerpt(r.text, needle)
            req = f"{rq['method']} {rq['url']} {body_desc}"
        elif kind == "body":
            r = get(url); needle = check["needle"]
            ok = needle in r.text; excerpt = _excerpt(r.text, needle)
        elif kind == "header_missing":
            r = get(url); present = {h.lower() for h in r.headers.keys()}
            missing = [h for h in check["headers"] if h not in present]
            ok = bool(missing); excerpt = "缺失: " + ", ".join(missing)
        elif kind == "header_present":
            r = get(url); val = r.headers.get(check["header"], "")
            ok = bool(val); excerpt = f"{check['header']}: {val}"
        elif kind == "status":
            r = get(url); ok = r.status_code == check.get("code", 200)
            excerpt = f"HTTP {r.status_code} · {_excerpt(r.text, '')}"
        elif kind == "idor":
            ra, rb = get(check["url_a"]), get(check["url_b"])
            ok = ra.text != rb.text and rb.status_code == 200
            excerpt = f"id_a -> {ra.text[:80]}\nid_b -> {rb.text[:80]}"
            req = f"GET {check['url_a']}  /  GET {check['url_b']}  (无 Authorization)"
        elif kind == "prevalidated":
            ok = True
            excerpt = check.get("evidence", "")
            req = "(由外部工具确认，见证据)"
        if ok:
            res.update(verified=True,
                       poc={"request": req, "response_excerpt": excerpt, "steps": cand.get("_steps", [])})
    except Exception as e:  # noqa: BLE001
        res["error"] = str(e)
    return res


# ---------- helpers ----------
def with_param(url, name, value):
    base = url.split("?")[0]
    flat = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    flat[name] = value
    return f"{base}?{urlencode(flat)}"


def _excerpt(text, needle, span=80):
    if needle and needle in text:
        i = text.index(needle)
        return text[max(0, i - span): i + len(needle) + span]
    return text[:160]
