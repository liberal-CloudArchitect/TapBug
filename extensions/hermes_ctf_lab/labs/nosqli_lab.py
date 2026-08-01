#!/usr/bin/env python3
"""Hermes NoSQLi 靶场 —— 模拟 MongoDB 运算符语义的登录，易受 $ne/$gt/$regex 运算符注入。

⚠️ 仅本地、教学、只监听 127.0.0.1。/login 接受 JSON 或 form；用户输入直接进"查询条件"，
运算符（如 {"$ne":null}）会绕过口令校验，以 admin 身份登录 → 返回 flag。

    python labs/nosqli_lab.py 8913
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8913
FLAG = "flag{nosql_operator_bypass}"
USERS = [{"username": "admin", "password": "S3cr3tP@ss!", "role": "admin"}]


def match(cond, value):
    """模拟 Mongo 匹配：cond 为 dict 时按运算符匹配。"""
    if isinstance(cond, dict):
        for op, v in cond.items():
            if op == "$ne" and value == v:
                return False
            if op == "$gt" and not (str(value) > str(v)):
                return False
            if op == "$regex" and not re.search(str(v), str(value)):
                return False
            if op == "$in" and value not in v:
                return False
        return True
    return cond == value


class H(BaseHTTPRequestHandler):
    server_version = "AuthAPI"
    sys_version = ""

    def _send(self, body, code=200, ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<form action="/login" method="post"><input name="username">'
                       '<input name="password" type="password"><button>login</button></form>',
                       ctype="text/html")
        else:
            self._send("404", 404, "text/plain")

    def do_POST(self):
        if self.path != "/login":
            self._send("404", 404, "text/plain"); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore")
        ctype = self.headers.get("Content-Type", "")
        try:
            if "application/json" in ctype:
                data = json.loads(raw)
                ucond, pcond = data.get("username"), data.get("password")
            else:  # form: username[$ne]= 风格
                q = parse_qs(raw)
                ucond = _form_cond(q, "username")
                pcond = _form_cond(q, "password")
        except Exception as e:  # noqa: BLE001
            self._send(f'{{"error":"{e}"}}', 400); return
        for u in USERS:
            if match(ucond, u["username"]) and match(pcond, u["password"]):
                # 用运算符（非正确口令字面量）登录成功 → 越权
                bypass = isinstance(pcond, dict)
                if bypass or pcond == u["password"]:
                    self._send(f'{{"status":"Welcome {u["username"]}","role":"{u["role"]}"'
                               + (f',"flag":"{FLAG}"' if bypass else "") + "}")
                    return
        self._send('{"status":"invalid credentials"}', 401)

    def log_message(self, *a):
        pass


def _form_cond(q, name):
    for k in q:
        m = re.match(rf"{name}\[(\$\w+)\]$", k)
        if m:
            return {m.group(1): q[k][0]}
    return q.get(name, [""])[0]


if __name__ == "__main__":
    print(f"[lab] NoSQLi on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
