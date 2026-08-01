#!/usr/bin/env python3
"""Hermes XXE 靶场 —— 用**真实** lxml（开启外部实体解析）解析用户 XML（非模拟）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/parse 用 resolve_entities=True 解析 XML，构成真实 XXE；
agent 的外部实体 payload 会**真的读取** /tmp/flag.txt，其内容被反射进响应。

    python labs/xxe_lab.py 8910
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lxml import etree

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8910
FLAG = "flag{xxe_file_read}"
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG + "\n")

HOME = ('<h1>XML Import</h1><p>POST 你的 XML 到 /parse</p>'
        '<form action="/parse" method="post"><textarea name="xml"></textarea></form>')


class H(BaseHTTPRequestHandler):
    server_version = "XMLImport"
    sys_version = ""

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._send(HOME) if self.path == "/" else self._send("404", 404)

    def do_POST(self):
        if self.path != "/parse":
            self._send("404", 404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n)
        try:
            # 真实 XXE：允许外部实体、允许读本地文件
            parser = etree.XMLParser(resolve_entities=True, no_network=True, load_dtd=True)
            root = etree.fromstring(raw, parser)
            text = " ".join(root.itertext())
        except Exception as e:  # noqa: BLE001
            text = f"parse error: {e}"
        self._send(f"<p>Imported: {text}</p>", ctype="text/plain")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] XXE on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
