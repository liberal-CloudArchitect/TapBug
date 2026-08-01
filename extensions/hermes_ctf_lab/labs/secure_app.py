#!/usr/bin/env python3
"""Hermes 基准负样本靶场 —— 安全实现版（用于测误报率/precision）。

与 vulnerable_app 相同入口，但做对了：
  - 输出 HTML 转义（无 XSS）
  - 发送完整安全响应头
  - Server 头不泄露版本
  - /api/profile 无 Authorization 返回 401（无 IDOR、无无鉴权访问）
  - 无敏感文件（全部 404）
理想情况下管线对它应"零发现"。

    python labs/secure_app.py 8901
"""
import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8901

HOME = """<!doctype html><html><head><title>Acme Secure</title></head><body>
<h1>Acme Secure Portal</h1>
<form action="/search" method="get"><input name="q"><button>Go</button></form>
<ul><li><a href="/search?q=hello">search</a></li><li><a href="/api/profile?id=1">profile api</a></li></ul>
</body></html>"""

SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000",
    "Referrer-Policy": "no-referrer",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Acme"      # 不泄露版本
    sys_version = ""

    def _headers(self, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            self._headers(); self.wfile.write(HOME.encode())
        elif u.path == "/search":
            q = html.escape(unquote(qs.get("q", [""])[0]))   # 转义 => 无 XSS
            self._headers()
            self.wfile.write(f"<html><body><h2>Results for: {q}</h2></body></html>".encode())
        elif u.path == "/api/profile":
            auth = self.headers.get("Authorization")
            if not auth:                                     # 强制鉴权 => 无 IDOR / 无鉴权访问
                self._headers(ctype="application/json", code=401)
                self.wfile.write(b'{"error":"unauthorized"}')
            else:
                self._headers(ctype="application/json")
                self.wfile.write(b'{"id":"self","name":"me"}')
        else:
            self._headers(code=404); self.wfile.write(b"<h1>404</h1>")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[lab] Acme SECURE app on http://127.0.0.1:{PORT}")
    srv.serve_forever()
