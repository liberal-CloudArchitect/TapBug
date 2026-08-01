#!/usr/bin/env python3
"""Hermes 原型链污染靶场 —— 模拟 JS 不安全深合并，__proto__ 污染共享原型（Python 模拟其语义）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/config 深合并用户 JSON；__proto__/constructor.prototype
会污染"共享原型"（模拟 Object.prototype）；/flag 用一个全新对象做 admin 检查，被污染后即放行 flag。
（原型链污染是 JS 特有；此处用 Python 忠实模拟其"污染共享默认 → 影响后续新对象"的语义。）

    python labs/protopollution_lab.py 8914
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8914
FLAG = "flag{prototype_pollution_admin}"
PROTO = {}   # 模拟 Object.prototype（被污染后所有新对象继承）


def merge(dst, src):
    for k, v in src.items():
        if k in ("__proto__", "prototype"):
            if isinstance(v, dict):
                PROTO.update(v)            # 污染共享原型
        elif k == "constructor" and isinstance(v, dict) and isinstance(v.get("prototype"), dict):
            PROTO.update(v["prototype"])
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def get_inherited(obj, key, default=False):
    return obj.get(key, PROTO.get(key, default))   # 模拟原型链查找


class H(BaseHTTPRequestHandler):
    server_version = "ConfigSvc"
    sys_version = ""

    def _send(self, body, code=200, ctype="application/json"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<form action="/config" method="post"><textarea name="config"></textarea>'
                       '<button>save</button></form><a href="/flag">flag</a>', ctype="text/html")
        elif self.path == "/flag":
            user = {}                       # 全新对象
            if get_inherited(user, "isAdmin") or get_inherited(user, "admin"):
                self._send(f'{{"flag":"{FLAG}"}}')
            else:
                self._send('{"error":"admin only"}', 403)
        else:
            self._send("404", 404, "text/plain")

    def do_POST(self):
        if self.path != "/config":
            self._send("404", 404, "text/plain"); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8", "ignore"))
            merge({"user": {"name": "guest"}}, data)
            self._send('{"status":"config updated"}')
        except Exception as e:  # noqa: BLE001
            self._send(f'{{"error":"{e}"}}', 400)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] proto-pollution on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
