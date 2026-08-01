#!/usr/bin/env python3
"""Hermes 任意文件上传靶场 —— 上传→触发→夺旗的多步链。

⚠️ 仅本地、教学、只监听 127.0.0.1。/upload 无校验保存任意文件；/view 取回时，若内容以 `RUN:` 开头
则"执行"其后的命令（此处只模拟 echo/cat，不真的 exec 任意上传代码，保持安全）。演示 upload→trigger→flag 链。

    python labs/upload_lab.py 8909
"""
import cgi
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8909
FLAG = "flag{arbitrary_upload_rce}"
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG + "\n")

STORE = {}   # filename -> content
HOME = ('<h1>Uploader</h1><form action="/upload" method="post" enctype="multipart/form-data">'
        '<input type="file" name="file"><button>upload</button></form>')


def emulate(cmd: str) -> str:
    out = []
    for m in re.finditer(r"echo\s+([A-Za-z0-9_]+)", cmd):
        out.append(m.group(1))
    if re.search(r"cat\s+\S*flag", cmd, re.I) or "/flag" in cmd:
        try:
            out.append(open("/tmp/flag.txt").read().strip())
        except OSError:
            pass
    return "\n".join(out)


class H(BaseHTTPRequestHandler):
    server_version = "Uploader"
    sys_version = ""

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        self.send_response(code); self.send_header("Content-Type", ctype); self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(HOME)
        elif u.path == "/view":
            name = parse_qs(u.query).get("name", [""])[0]
            content = STORE.get(name, "")
            if content.startswith("RUN:"):        # 触发"执行"
                self._send("output:\n" + emulate(content[4:]), ctype="text/plain")
            else:
                self._send(content, ctype="text/plain")
        else:
            self._send("404", 404)

    def do_POST(self):
        if self.path != "/upload":
            self._send("404", 404); return
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            self._send("bad request", 400); return
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype})
        item = form["file"] if "file" in form else None
        if item is None:
            self._send("no file", 400); return
        name = item.filename or "upload.bin"
        STORE[name] = (item.file.read().decode("utf-8", "ignore")
                       if hasattr(item, "file") and item.file else (item.value or ""))
        # 无校验：返回可取回路径
        self._send(f"uploaded: /view?name={name}", ctype="text/plain")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] upload-RCE on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
