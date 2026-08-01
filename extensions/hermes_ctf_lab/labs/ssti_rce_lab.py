#!/usr/bin/env python3
"""Hermes SSTI→RCE 靶场 —— 用**真实、未沙箱**的 Jinja2 渲染用户输入（非模拟）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/greet?name= 直接 Template(name).render()，构成真实 SSTI；
Jinja2 沙箱逃逸 gadget 会**真的执行** os.popen 读取 flag 文件（本 lab 自建的临时 flag）。

    python labs/ssti_rce_lab.py 8907
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from jinja2 import Template   # 真实模板引擎

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8907
# 出题者放置的 flag 文件（常见 CTF 路径）
FLAG = "flag{ssti_rce_via_jinja2}"
FLAG_PATH = "/tmp/flag.txt"
with open(FLAG_PATH, "w") as f:
    f.write(FLAG + "\n")


class H(BaseHTTPRequestHandler):
    server_version = "Greeter"
    sys_version = ""

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send('<h1>Greeter</h1><a href="/greet?name=guest">greet</a>')
        elif u.path == "/greet":
            name = unquote(parse_qs(u.query).get("name", ["world"])[0])
            try:
                # 真实 SSTI：用户输入进入模板源码
                rendered = Template("<p>Hello, " + name + "</p>").render()
            except Exception as e:  # noqa: BLE001
                rendered = f"<p>error: {e}</p>"
            self._send(rendered)
        else:
            self._send("404", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] SSTI-RCE on http://127.0.0.1:{PORT} (flag at {FLAG_PATH})")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
