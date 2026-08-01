#!/usr/bin/env python3
"""Hermes 动态合成测试靶场 —— 无现成原语可用，必须**现写代码**算出证明值才能夺旗。

⚠️ 仅本地、教学、只监听 127.0.0.1。逻辑：GET /token 拿随机 token + 提示；
按提示算 proof = md5(token + 盐)，POST /verify 提交；对了给 flag。考验 agent 现写 wheel 的能力。

    python labs/synth_lab.py 8924
"""
import hashlib
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8924
FLAG = "flag{synthesized_wheel_md5_proof}"
SALT = "HermesSalt2024"
TOKENS = {}   # token -> True


class H(BaseHTTPRequestHandler):
    server_version = "Proof"
    sys_version = ""

    def _send(self, obj, code=200):
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write((obj if isinstance(obj, str) else json.dumps(obj)).encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<p>GET /token, then POST /verify {"token","proof"}</p>')
        elif self.path == "/token":
            t = secrets.token_hex(8)
            TOKENS[t] = True
            self._send({"token": t, "hint": "proof = md5(token + 'HermesSalt2024') hex digest"})
        else:
            self._send({"error": "404"}, 404)

    def do_POST(self):
        if self.path != "/verify":
            self._send({"error": "404"}, 404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            d = json.loads(self.rfile.read(n).decode("utf-8", "ignore"))
        except Exception:  # noqa: BLE001
            d = {}
        token, proof = d.get("token", ""), d.get("proof", "")
        if token in TOKENS and proof == hashlib.md5((token + SALT).encode()).hexdigest():
            self._send({"message": "correct", "flag": FLAG})
        else:
            self._send({"message": "wrong proof"}, 403)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] synth on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
