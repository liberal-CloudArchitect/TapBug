#!/usr/bin/env python3
"""Hermes 不安全反序列化靶场 —— 用**真实** pickle.loads 反序列化用户 cookie（非模拟）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/profile 读取 base64 cookie 并 pickle.loads，构成真实反序列化 RCE；
agent 构造的 __reduce__ payload 会**真的执行** cat 读取 flag，其返回被反射进响应。

    python labs/deser_lab.py 8908
"""
import base64
import pickle
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8908
FLAG = "flag{pickle_deser_rce}"
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG + "\n")

# 默认良性 cookie（一个 dict）
DEFAULT = base64.b64encode(pickle.dumps({"user": "guest", "role": "member"})).decode()


class H(BaseHTTPRequestHandler):
    server_version = "Profiler"
    sys_version = ""

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if "session" not in (self.headers.get("Cookie") or ""):
            self.send_header("Set-Cookie", f"session={DEFAULT}; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def do_GET(self):
        if self.path != "/profile" and self.path != "/":
            self._send("<h1>404</h1>", 404); return
        raw = self._cookie("session")
        obj = None
        if raw:
            try:
                obj = pickle.loads(base64.b64decode(raw))   # 真实不安全反序列化
            except Exception as e:  # noqa: BLE001
                obj = f"(error: {e})"
        # 反射反序列化结果（RCE 输出会随之出现在响应里）
        self._send(f'<h1>Profile</h1><p>session: {obj}</p><a href="/profile">refresh</a>')

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] deser-RCE on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
