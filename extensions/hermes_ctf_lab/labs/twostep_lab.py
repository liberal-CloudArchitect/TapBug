#!/usr/bin/env python3
"""Hermes 子目标分解测试靶 —— 真 **2 阶段耦合** 链，后依赖前。

⚠️ 仅本地、教学、只监听 127.0.0.1。用途：验证 synth 的**子目标分解**（先取中间产物 ticket → 再用它夺旗）。
阶段1：GET /stage1 拿 nonce+提示 → 算 answer=sha256(nonce+盐) → POST /stage1 换 ticket。
阶段2：POST /stage2 用 ticket 换 flag。单发一次难同时搞定两段，分解成两步逐个解则稳。

    python labs/twostep_lab.py 8928
"""
import hashlib
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8928
FLAG = "flag{two_step_decomposition_chain}"
SALT = "saltyStage1_2026"
NONCES = {}          # nonce -> True
TICKETS = {}         # ticket -> True


class H(BaseHTTPRequestHandler):
    server_version = "TwoStep"
    sys_version = ""

    def _send(self, obj, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write((obj if isinstance(obj, str) else json.dumps(obj)).encode())

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n).decode("utf-8", "ignore"))
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):
        if self.path == "/":
            self._send('<p>2-step: GET /stage1 → POST /stage1 {nonce,answer} → ticket; '
                       'POST /stage2 {ticket} → flag</p>')
        elif self.path == "/stage1":
            nonce = secrets.token_hex(8)
            NONCES[nonce] = True
            self._send({"nonce": nonce,
                        "hint": f"answer = sha256(nonce + '{SALT}') hex; POST /stage1 {{nonce,answer}} -> ticket"})
        else:
            self._send({"error": "404"}, 404)

    def do_POST(self):
        d = self._body()
        if self.path == "/stage1":
            nonce, answer = d.get("nonce", ""), d.get("answer", "")
            if nonce in NONCES and answer == hashlib.sha256((nonce + SALT).encode()).hexdigest():
                ticket = secrets.token_hex(12)
                TICKETS[ticket] = True
                self._send({"ticket": ticket, "next": "POST /stage2 {ticket} to get flag"})
            else:
                self._send({"error": "wrong answer"}, 403)
        elif self.path == "/stage2":
            if d.get("ticket", "") in TICKETS:
                self._send({"message": "unlocked", "flag": FLAG})
            else:
                self._send({"error": "invalid ticket"}, 403)
        else:
            self._send({"error": "404"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] two-step chain on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
