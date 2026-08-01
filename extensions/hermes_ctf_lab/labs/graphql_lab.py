#!/usr/bin/env python3
"""Hermes GraphQL 靶场 —— introspection 开放 + 隐藏 secretFlag 查询（极简 GraphQL 模拟）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/graphql 接受 {"query": "..."}；introspection 暴露字段名，
其中隐藏了 secretFlag —— 查询它即得 flag。（用轻量解析模拟 GraphQL 语义。）

    python labs/graphql_lab.py 8916
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8916
FLAG = "flag{graphql_introspection_leak}"

SCHEMA = {"data": {"__schema": {
    "queryType": {"fields": [{"name": "hello"}, {"name": "user"}, {"name": "secretFlag"}]},
    "types": [{"name": "Query", "fields": [{"name": "hello"}, {"name": "secretFlag"}]}]}}}


class H(BaseHTTPRequestHandler):
    server_version = "GraphQLSvc"
    sys_version = ""

    def _send(self, obj, code=200):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write((obj if isinstance(obj, str) else json.dumps(obj)).encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<h1>API</h1><a href="/graphql">GraphQL endpoint</a>')
        else:
            self._send({"error": "404"}, 404)

    def do_POST(self):
        if self.path != "/graphql":
            self._send({"error": "404"}, 404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "ignore")
        try:
            query = json.loads(raw).get("query", "")
        except Exception:  # noqa: BLE001
            query = raw
        if "__schema" in query or "introspection" in query.lower():
            self._send(SCHEMA); return
        if re.search(r"\bsecretFlag\b", query):
            self._send({"data": {"secretFlag": FLAG}}); return
        if re.search(r"\bhello\b", query):
            self._send({"data": {"hello": "world"}}); return
        self._send({"errors": [{"message": "Cannot query field"}]})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] GraphQL on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
