#!/usr/bin/env python3
"""Hermes 交互式利用靶场 —— 漏洞藏在"默认口令登录 + 深层路径 + POST 表单"之后。

⚠️ 仅本地、教学、只监听 127.0.0.1。设计意图：验证交互式能力（登录态/深爬/表单驱动/POST 注入）。
浅层 GET-only 管线**够不到**这些漏洞；只有登录后深爬并向 POST 表单注入才能命中：
  - 默认口令：admin/admin（/login）
  - 需登录 + POST：/admin/ping (host 字段) 命令注入；/admin/render (tmpl 字段) SSTI

    python labs/interactive_lab.py 8903
"""
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8903
COOKIE = "sid=hermes-ok"

HOME = '<h1>Acme Portal</h1><ul><li><a href="/login">login</a></li>' \
       '<li><a href="/dashboard">dashboard</a></li></ul>'
LOGIN_FORM = ('<h2>Login</h2><form action="/login" method="post">'
              '<input name="username"><input name="password" type="password">'
              '<button>go</button></form>')
DASH = ('<h2>Dashboard</h2><p>logout</p>'
        '<ul><li><a href="/admin/tools">admin tools</a></li></ul>')
TOOLS = ('<h2>Admin Tools</h2><p>logout</p>'
         '<form action="/admin/ping" method="post"><input name="host"><button>ping</button></form>'
         '<form action="/admin/render" method="post"><input name="tmpl"><button>render</button></form>')

SSTI = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


class H(BaseHTTPRequestHandler):
    server_version = "AcmePortal"
    sys_version = ""

    def _authed(self):
        return COOKIE in (self.headers.get("Cookie") or "")

    def _send(self, body, code=200, ctype="text/html; charset=utf-8", cookie=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", COOKIE + "; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def _redirect(self, loc):
        self.send_response(302); self.send_header("Location", loc); self.end_headers()

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return parse_qs(self.rfile.read(n).decode("utf-8", "ignore")) if n else {}

    def do_GET(self):
        if self.path == "/":
            self._send(HOME)
        elif self.path == "/login":
            self._send(LOGIN_FORM)
        elif self.path == "/dashboard":
            self._send(DASH) if self._authed() else self._redirect("/login")
        elif self.path == "/admin/tools":
            self._send(TOOLS) if self._authed() else self._redirect("/login")
        else:
            self._send("<h1>404</h1>", 404)

    def do_POST(self):
        b = self._body()
        if self.path == "/login":
            u = (b.get("username", [""])[0]); p = (b.get("password", [""])[0])
            if u == "admin" and p == "admin":   # 默认口令
                self._send('<p>Welcome admin. <a href="/dashboard">dashboard</a> logout</p>', cookie=True)
            else:
                self._send(LOGIN_FORM + "<p>invalid</p>", 401)
        elif self.path == "/admin/ping":
            if not self._authed():
                self._send("unauthorized", 401); return
            host = b.get("host", [""])[0]
            out = f"PING {host}"
            m = re.search(r"echo\s+([A-Za-z0-9_]+)", host)
            if m and re.search(r"[;|`&]|\$\(", host):    # 命令注入
                out += f"\n{m.group(1)}"
            self._send(out, ctype="text/plain")
        elif self.path == "/admin/render":
            if not self._authed():
                self._send("unauthorized", 401); return
            tmpl = b.get("tmpl", [""])[0]
            rendered = SSTI.sub(lambda mm: str(int(mm.group(1)) * int(mm.group(2))), tmpl)  # SSTI
            self._send(f"<p>{rendered}</p>")
        else:
            self._send("404", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
