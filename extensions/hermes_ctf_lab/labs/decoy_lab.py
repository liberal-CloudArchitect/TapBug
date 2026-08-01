#!/usr/bin/env python3
"""Hermes 回溯测试靶场 —— 多个"看着可利用"的死胡同 + 一个真实可夺旗端点。

⚠️ 仅本地、教学、只监听 127.0.0.1。
  - /search?q=  → 转义回显（SSTI/cmdi/XSS 都是死胡同）
  - /view?id=   → 安全回显（IDOR/LFI 死胡同）
  - /graphql    → introspection 泄露 secretFlag（真正的路）
规划器需在死胡同失败后**回溯**、换到 GraphQL 才能夺旗。

    python labs/decoy_lab.py 8918
"""
import html
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8918
FLAG = "flag{backtrack_to_graphql}"
SCHEMA = {"data": {"__schema": {"queryType": {"fields": [
    {"name": "hello"}, {"name": "secretFlag"}]}}}}

HOME = ('<h1>Portal</h1><a href="/search?q=x">search</a> '
        '<a href="/view?id=1">view</a> <a href="/graphql">graphql</a>')


class H(BaseHTTPRequestHandler):
    server_version = "Portal"
    sys_version = ""

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write((body if isinstance(body, str) else json.dumps(body)).encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(HOME)
        elif u.path == "/search":
            q = html.escape(unquote(parse_qs(u.query).get("q", [""])[0]))   # 转义 → 死胡同
            self._send(f"<p>You searched: {q}</p>")
        elif u.path == "/view":
            iid = html.escape(unquote(parse_qs(u.query).get("id", [""])[0]))
            self._send(f"<p>Item {iid}</p>")                                 # 安全 → 死胡同
        else:
            self._send("404", 404, "text/plain")

    def do_POST(self):
        if self.path != "/graphql":
            self._send("404", 404, "text/plain"); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            query = json.loads(self.rfile.read(n).decode("utf-8", "ignore")).get("query", "")
        except Exception:  # noqa: BLE001
            query = ""
        if "__schema" in query:
            self._send(SCHEMA, ctype="application/json")
        elif re.search(r"\bsecretFlag\b", query):
            self._send({"data": {"secretFlag": FLAG}}, ctype="application/json")
        else:
            self._send({"errors": [{"message": "Cannot query field"}]}, ctype="application/json")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] decoy on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
