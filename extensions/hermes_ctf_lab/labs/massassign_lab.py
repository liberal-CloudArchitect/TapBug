#!/usr/bin/env python3
"""Hermes 批量赋值靶场 —— /register 盲绑用户提交的所有字段（含 role），可越权注册为 admin。

⚠️ 仅本地、教学、只监听 127.0.0.1。注册端点把请求里的全部字段并入用户对象；
提交 role=admin 即注册出管理员账户 → 响应直接给 flag。

    python labs/massassign_lab.py 8921
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8921
FLAG = "flag{mass_assignment_admin_register}"


class H(BaseHTTPRequestHandler):
    server_version = "AccountSvc"
    sys_version = ""

    def _send(self, obj, code=200):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write((obj if isinstance(obj, str) else json.dumps(obj)).encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<form action="/register" method="post"><input name="username">'
                       '<input name="password"></form>', code=200)
        else:
            self._send({"error": "404"}, 404)

    def do_POST(self):
        if self.path != "/register":
            self._send({"error": "404"}, 404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore")
        try:
            data = json.loads(raw) if "json" in self.headers.get("Content-Type", "") \
                else {k: v[0] for k, v in parse_qs(raw).items()}
        except Exception:  # noqa: BLE001
            data = {}
        # 过度绑定：把用户提交的全部字段并入账户（含 role）
        user = {"username": data.get("username", "guest"), "role": "user"}
        user.update(data)                     # ← 漏洞：盲目合并
        if str(user.get("role")).lower() == "admin" or str(user.get("isAdmin")).lower() in ("true", "1"):
            self._send({"status": "admin account created", "flag": FLAG})
        else:
            self._send({"status": "user created", "role": user.get("role")})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] mass-assignment on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
