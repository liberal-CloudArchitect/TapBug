"""认证授权专家 scanner —— IDOR / BOLA（越权对象访问，只读对比）。"""
from __future__ import annotations

from urllib.parse import urlparse

from hermes import tools
from hermes.scanners import Scanner

ID_PARAMS = {"id", "uid", "user", "user_id", "account", "pid", "oid", "doc"}


def _host(url):
    return urlparse(url).netloc or url


def scan(ep: dict) -> list:
    params = ep.get("params") or []
    idp = next((p for p in params if p.lower() in ID_PARAMS), None)
    if not idp:
        return []
    url = ep["url"]
    url_a = tools.with_param(url, idp, "1")
    url_b = tools.with_param(url, idp, "2")
    try:
        ra, rb = tools.get(url_a), tools.get(url_b)
    except Exception:  # noqa: BLE001
        return []
    # 无 Authorization 即可取到不同对象的数据 => IDOR/BOLA
    if rb.status_code == 200 and ra.text != rb.text and len(rb.text) > 2:
        return [tools.make_candidate(
            f"idor-{idp}-{_host(url)}", url_a,
            f"参数 {idp} 存在 IDOR/BOLA：无鉴权即可越权访问他人对象",
            "Broken Access Control", "high",
            "broken_access_control.idor",
            check={"kind": "idor", "url_a": url_a, "url_b": url_b},
            impact="任意遍历他人私有数据（如邮箱/角色），横向越权",
            steps=[f"GET {url_a}（无 Authorization）", f"再 GET {url_b}",
                   "两次返回不同用户的私有数据，证明无访问控制"])]
    return []


SCANNER = Scanner(domain="authz",
                  applies=lambda ep: ep.get("type") == "api" and bool(ep.get("params")),
                  scan=scan)
