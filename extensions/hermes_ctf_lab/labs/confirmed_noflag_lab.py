#!/usr/bin/env python3
"""Hermes G7 测试靶 —— 真 Jinja2 SSTI，但 flag **只在内存、绝不落盘**。

⚠️ 仅本地、教学、只监听 127.0.0.1。用途：验证"漏洞已确认 vs 仅 flag 提取失败"的区分——
`{{7*7}}`→49 差分能确认 SSTI（真模板注入），但 agent 的 `cat <flagpath>` gadget 读不到 flag
（flag 从不写文件），故应判 **confirmed（高置信）而非彻底 miss**，并自动出 VRT 草稿。

    python labs/confirmed_noflag_lab.py 8926
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from jinja2 import Template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8926
FLAG = "flag{never_written_to_disk}"          # 只在内存；SSTI 的 cat gadget 读不到


class H(BaseHTTPRequestHandler):
    server_version = "TplDemo"
    sys_version = ""

    def do_GET(self):
        name = parse_qs(urlparse(self.path).query).get("name", ["world"])[0]
        try:
            rendered = Template("Hello " + name + "!").render()   # 真 SSTI（故意不安全，教学）
        except Exception as e:  # noqa: BLE001
            rendered = "err: " + str(e)[:100]
        body = f"<h1>{rendered}</h1><p>try ?name=</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] confirmed-noflag SSTI on http://127.0.0.1:{PORT} (flag in-memory only)")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
