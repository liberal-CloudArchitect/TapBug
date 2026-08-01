#!/usr/bin/env python3
"""Hermes XPath 注入靶场 —— 用**真实** lxml XPath 查 XML 用户库，登录条件可被注入绕过。

⚠️ 仅本地、教学、只监听 127.0.0.1。/login 把用户名/口令未转义地拼进 XPath：
  //user[username/text()='$u' and password/text()='$p']
注入 ' or '1'='1 使条件恒真 → 越权登录 admin → 返回 flag。

    python labs/xpath_lab.py 8922
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from lxml import etree

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8922
FLAG = "flag{xpath_injection_auth_bypass}"
USERS_XML = etree.fromstring(
    "<users><user><username>admin</username><password>Sup3rSecret</password>"
    "<role>admin</role></user></users>")


class H(BaseHTTPRequestHandler):
    server_version = "AuthSvc"
    sys_version = ""

    def _send(self, obj, code=200):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write((obj if isinstance(obj, str) else json.dumps(obj)).encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<form action="/login" method="post"><input name="username">'
                       '<input name="password" type="password"></form>')
        else:
            self._send({"error": "404"}, 404)

    def do_POST(self):
        if self.path != "/login":
            self._send({"error": "404"}, 404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore")
        try:
            data = json.loads(raw) if "json" in self.headers.get("Content-Type", "") \
                else {k: v[0] for k, v in parse_qs(raw).items()}
        except Exception:  # noqa: BLE001
            data = {}
        u = data.get("username", ""); p = data.get("password", "")
        # 真实 XPath 注入：未转义拼接
        q = f"//user[username/text()='{u}' and password/text()='{p}']"
        try:
            nodes = USERS_XML.xpath(q)
        except Exception as e:  # noqa: BLE001
            self._send({"error": f"xpath error: {e}"}, 400); return
        if nodes:
            role = nodes[0].findtext("role")
            if role == "admin":
                self._send({"status": "welcome admin", "flag": FLAG})
            else:
                self._send({"status": f"welcome {nodes[0].findtext('username')}"})
        else:
            self._send({"status": "invalid credentials"}, 401)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] XPath on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
