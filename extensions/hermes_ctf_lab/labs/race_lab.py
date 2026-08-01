#!/usr/bin/env python3
"""Hermes 竞态条件靶场 —— "限一次"奖励存在 TOCTOU，并发可越限（非模拟，真并发）。

⚠️ 仅本地、教学、只监听 127.0.0.1。/redeem 先查计数再发奖励，检查与写入之间有窗口（sleep）；
并发请求会都通过检查、都发奖励 → 超限 → 泄露 flag。

    python labs/race_lab.py 8919
"""
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8919
FLAG = "flag{race_condition_double_redeem}"
LIMIT = 1
STATE = {"count": 0}
REWARDS = []          # 实际发放的奖励（越限即中招）


class H(BaseHTTPRequestHandler):
    server_version = "Shop"
    sys_version = ""

    def _send(self, body, code=200):
        self.send_response(code); self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers(); self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self._send('<form action="/redeem" method="post"><button>redeem</button></form>')
        else:
            self._send("404", 404)

    def do_POST(self):
        if self.path != "/redeem":
            self._send("404", 404); return
        # 故意非原子：check-then-act，中间有窗口
        if STATE["count"] < LIMIT:
            time.sleep(0.06)               # 竞态窗口
            REWARDS.append(1)
            STATE["count"] += 1
        granted = len(REWARDS)
        if granted > LIMIT:                # 越限 → 中招
            self._send(f"rewards granted: {granted} (over limit!) {FLAG}")
        else:
            self._send(f"rewards granted: {granted}")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"[lab] race on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
