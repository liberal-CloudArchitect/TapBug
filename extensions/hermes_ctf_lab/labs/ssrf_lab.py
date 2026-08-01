#!/usr/bin/env python3
"""Hermes SSRF 靶场 —— 服务端按用户 URL 拉取并反射内容（含 file:// 误处理）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/fetch?url= 会真的按 url 取内容；file:// 被误当可取协议，
构成 SSRF 本地文件读。agent 指向 file:///tmp/flag.txt 即可读到 flag。

    python labs/ssrf_lab.py 8911
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8911
FLAG = "flag{ssrf_internal_read}"
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG + "\n")


class H(BaseHTTPRequestHandler):
    server_version = "Fetcher"
    sys_version = ""

    def _send(self, body, code=200, ctype="text/plain; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send('<a href="/fetch?url=http://example.com">fetch</a>', ctype="text/html")
            return
        if u.path == "/secret":     # 内网专用 flag 端点（本意仅内部可达）
            self._send(FLAG); return
        if u.path == "/fetch":
            target = parse_qs(u.query).get("url", [""])[0]
            try:
                if target.startswith("file://"):     # SSRF：file 协议被误处理 → 本地文件读
                    content = open(target[7:]).read()
                elif target.startswith(("http://127.0.0.1", "http://localhost")):
                    import httpx
                    content = httpx.get(target, timeout=3).text
                else:
                    content = "(fetched external, omitted)"
            except Exception as e:  # noqa: BLE001
                content = f"error: {e}"
            self._send(f"Fetched content:\n{content}")
            return
        self._send("404", 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] SSRF on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
