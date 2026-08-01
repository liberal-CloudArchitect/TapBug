#!/usr/bin/env python3
"""Hermes 自建靶场 —— Phase 1/2 端到端验证的确定性目标（仅本地、故意含漏洞）。

⚠️ 教学用途，只监听 127.0.0.1。预置的可复现问题：
  1. 反射型 XSS：/search?q= 把 q 原样回显进 HTML（Web 专家）
  2. 缺失安全响应头 + 冗长 Server 版本（Web 专家）
  3. IDOR / BOLA：/api/profile?id= 改 id 即返回他人数据，无鉴权（认证授权专家）
  4. API 无鉴权 + 错误信息泄露：/api/* 无需 Authorization（API 专家）
  5. 敏感文件暴露：/.env、/.git/config、/backup.zip、/admin（基础设施专家）

    python labs/vulnerable_app.py 8899
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899

HOME = """<!doctype html><html><head><title>Acme Lab</title></head><body>
<h1>Acme Search Portal</h1>
<form action="/search" method="get"><input name="q" placeholder="search"><button>Go</button></form>
<ul>
  <li><a href="/search?q=hello">search demo</a></li>
  <li><a href="/api/profile?id=1">profile api</a></li>
</ul></body></html>"""

USERS = {"1": ("alice", "member", "alice@acme.test"),
         "2": ("bob", "admin", "bob@acme.test"),
         "3": ("carol", "member", "carol@acme.test")}

# 故意暴露的敏感文件（基础设施专家目标）
SENSITIVE = {
    "/.env": ("text/plain", "DB_PASSWORD=s3cr3t\nAPI_KEY=AKIA_FAKE_1234\n"),
    "/.git/config": ("text/plain", "[remote \"origin\"]\n\turl = git@acme.test:app.git\n"),
    "/backup.zip": ("application/zip", "PK\x03\x04 fake-backup-archive"),
    "/admin": ("text/html", "<h1>Admin Panel</h1><p>internal only</p>"),
    # 仅知识库开启时才会被 infra 专家探测到（默认字典未含）—— 演示知识复利
    "/.env.bak": ("text/plain", "OLD_DB_PASSWORD=legacy_s3cr3t\n"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AcmePortal/2.3.1"          # 冗长版本泄露
    sys_version = ""

    def _headers(self, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # 故意不发送任何安全响应头
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/":
            self._headers(); self.wfile.write(HOME.encode())
        elif u.path == "/search":
            q = unquote(qs.get("q", [""])[0])
            # 反射型 XSS：q 原样拼接进 HTML
            body = f"<html><body><h2>Results for: {q}</h2><p>No results.</p></body></html>"
            self._headers(); self.wfile.write(body.encode())
        elif u.path == "/api/profile":
            uid = qs.get("id", ["0"])[0]
            self._headers(ctype="application/json")
            if uid in USERS:
                name, role, email = USERS[uid]
                # IDOR/BOLA：无鉴权即返回任意 id 的私有数据（含 email）
                self.wfile.write(f'{{"id":"{uid}","name":"{name}","role":"{role}","email":"{email}"}}'.encode())
            else:
                # 错误信息泄露（API 专家）
                self.wfile.write(f'{{"error":"user {uid} not found","query":"SELECT * FROM users WHERE id={uid}"}}'.encode())
        elif u.path in SENSITIVE:
            ctype, content = SENSITIVE[u.path]
            self._headers(ctype=ctype)
            self.wfile.write(content.encode("utf-8", "ignore"))
        else:
            self._headers(code=404); self.wfile.write(b"<h1>404</h1>")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[lab] Acme vulnerable app on http://127.0.0.1:{PORT}")
    srv.serve_forever()
