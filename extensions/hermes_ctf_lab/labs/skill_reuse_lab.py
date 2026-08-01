#!/usr/bin/env python3
"""Hermes 技能复用测试靶场 —— 与 synth_lab 同协议、但**不同盐值**。

⚠️ 仅本地、教学、只监听 127.0.0.1。用途：验证"自扩展"闭环——agent 在 synth_lab 上现写的 wheel
被**泛化成读 hint 里盐值的技能**后，面对本靶（盐值不同）应走 skill-first 直接复用秒解，
而不必再从头合成。逻辑：GET /token 拿 token + hint；proof = md5(token + 盐)；POST /verify 提交对了给 flag。

    python labs/skill_reuse_lab.py 8925
"""
import hashlib
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925
FLAG = "flag{skill_reused_across_challenges}"
SALT = "ReuseSalt2026Different"          # 与 synth_lab 的 HermesSalt2024 不同 —— 逼技能读 hint 泛化
TOKENS = {}


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
            self._send({"token": t, "hint": f"proof = md5(token + '{SALT}') hex digest"})
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
    print(f"[lab] skill-reuse on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
