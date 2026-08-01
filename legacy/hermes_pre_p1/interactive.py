"""交互式利用支撑 —— 登录态建立（含默认口令）与表单驱动，让探针能到达深处/授权后的漏洞。

授权范围内使用；登录仅用于以合法测试身份到达攻击面。默认口令尝试属授权测试标准动作。
"""
from __future__ import annotations

from urllib.parse import urlparse

from hermes import tools

# 常见默认/弱口令（授权测试；命中即"默认口令"发现）
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "password"), ("root", "root"), ("root", "toor"),
    ("test", "test"), ("guest", "guest"), ("user", "user"), ("admin", "123456"),
]

LOGGED_IN_HINTS = ("logout", "log out", "sign out", "dashboard", "welcome",
                   "my account", "profile", "登出", "注销", "退出")


def find_login(base, session, max_pages=25):
    for ep in tools.crawl(base, session=session, max_depth=2, max_pages=max_pages):
        if ep.get("is_login") and ep.get("pwd_field"):
            return ep
    return None


def _looks_logged_in(text: str, login_ep) -> bool:
    low = text.lower()
    if any(h in low for h in LOGGED_IN_HINTS):
        return True
    # 登录框消失也是成功信号
    return login_ep["pwd_field"] and f'type="password"' not in low and "password" not in low


def try_login(login_ep, user, pw, session) -> bool:
    data = {f: "" for f in login_ep.get("fields", [])}
    if login_ep.get("user_field"):
        data[login_ep["user_field"]] = user
    else:  # 猜测用户名字段
        for f in login_ep["fields"]:
            if f != login_ep.get("pwd_field") and any(k in f.lower() for k in ("user", "name", "email", "login")):
                data[f] = user
                break
    data[login_ep["pwd_field"]] = pw
    try:
        r = tools.send(login_ep.get("method", "POST"), login_ep["url"], data=data, session=session)
    except Exception:  # noqa: BLE001
        return False
    return _looks_logged_in(r.text, login_ep) and r.status_code < 400


def establish_session(base, scope, session) -> dict:
    """尝试建立登录态。返回 {logged_in, creds, default_cred, login_url}。"""
    login_ep = find_login(base, session)
    if not login_ep:
        return {"logged_in": False, "reason": "未发现登录表单"}
    # 优先 scope 提供的凭据，再试默认口令
    creds = []
    for c in (scope.data.get("credentials") or []):
        if isinstance(c, dict) and c.get("user"):
            creds.append((c["user"], c.get("pass", "")))
    creds += DEFAULT_CREDS
    for user, pw in creds:
        if try_login(login_ep, user, pw, session):
            is_default = (user, pw) in DEFAULT_CREDS
            return {"logged_in": True, "creds": (user, pw), "default_cred": is_default,
                    "login_url": login_ep["url"], "host": urlparse(base).netloc}
    return {"logged_in": False, "reason": "凭据均失败", "login_url": login_ep["url"]}


def default_cred_candidate(info: dict) -> dict:
    user, pw = info["creds"]
    host = info.get("host", "")
    return tools.make_candidate(
        f"default-creds-{host}", info["login_url"],
        f"默认/弱口令可登录：{user}/{pw}", "Broken Authentication", "high",
        "broken_authentication_and_session_management.weak_login_function.default_or_weak_credentials",
        check={"kind": "status", "code": 200},
        impact="使用默认/弱口令即可获得已认证访问",
        steps=[f"POST {info['login_url']} user={user} pass={pw}", "登录成功（出现已登录标志）"])
