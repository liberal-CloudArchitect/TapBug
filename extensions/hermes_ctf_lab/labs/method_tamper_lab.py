#!/usr/bin/env python3
"""Hermes HTTP 动词篡改靶场 —— 访问控制只挡了 GET，其它方法/override 头可绕过。

⚠️ 仅本地、教学、只监听 127.0.0.1。/admin：GET → 403；但 POST（或 X-HTTP-Method-Override）
未做同样校验 → 返回 flag。经典 verb tampering。

    python labs/method_tamper_lab.py 8920
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8920
FLAG = "flag{http_verb_tampering_bypass}"


class H(BaseHTTPRequestHandler):
    server_version = "AdminSvc"
    sys_version = ""

    def _send(self, body, code=200):
        self.send_response(code); self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        if body:
            self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<a href="/admin">admin</a>')
        elif self.path == "/admin":
            ov = (self.headers.get("X-HTTP-Method-Override")
                  or self.headers.get("X-HTTP-Method") or self.headers.get("X-Method-Override") or "")
            if ov.upper() in ("POST", "PUT"):     # override 头绕过
                self._send(f"admin panel (via override). {FLAG}")
            else:
                self._send("403 forbidden (GET blocked)", 403)   # 只挡 GET
        else:
            self._send("404", 404)

    def _admin_ok(self):
        if self.path == "/admin":
            self._send(f"admin panel. {FLAG}")     # 其它方法未做校验
        else:
            self._send("404", 404)

    do_POST = do_PUT = do_PATCH = do_DELETE = _admin_ok

    def do_HEAD(self):
        self.send_response(200 if self.path == "/admin" else 404); self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] method-tamper on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
