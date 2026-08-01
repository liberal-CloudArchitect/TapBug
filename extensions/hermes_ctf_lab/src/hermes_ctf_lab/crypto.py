"""G8 crypto 域求解器 —— 把 synth 的"LLM 现写解题脚本"扩到非 web 的 crypto 挑战。

crypto CTF 多为 **nc 到端口的交互 oracle**（而非 HTTP）。本模块复用 synth 的沙箱/执行/迭代，
但给沙箱注入 `tcp()`（仅连挑战绑定的 oracle）并允许 import Crypto(pycryptodome)/sympy/gmpy2，
用 crypto 定向提示让 LLM 读题→写 `def solve(base_url, session)`（内部用 tcp() 交互）→跑→报错迭代→夺旗。

⚠️ 仅授权 CTF/靶场：`enabled()` = synth.enabled()（CTF_MODE + allow_active）；recon-only 不启用。
`tcp()` 只连绑定 target，不给任意主机。
"""
from __future__ import annotations

from hermes_ctf_lab import synth

FLAG_RE = synth.FLAG_RE


def enabled() -> bool:
    return synth.enabled()


class CryptoSolver:
    """LLM 现写现跑的 crypto 解题器（写码→tcp 交互跑→读错→改）。"""

    def __init__(self, source_text="", max_iters=5):
        from hermes_ctf_lab.exploit_agent import make_reasoner
        self.source = source_text or ""
        self.reasoner = make_reasoner()
        self.max_iters = max_iters
        self.log = []

    def _prompt(self, host, port, prev_code, prev_err) -> str:
        base = (
            "你是顶尖 CTF crypto 选手。为下面这个**授权 crypto 挑战**写 Python 函数：\n"
            "  def solve(base_url, session):  # 返回 flag 字符串（flag{...}/HTB{...}），拿不到返回 None\n"
            "已注入命名空间（**勿 import os/subprocess/open/socket**）：\n"
            "  tcp()  # 返回**已连接**的 oracle 对象（无需 connect），方法：send/sendline(bytes)、recv(n)、"
            "recvuntil(delim)、recvline()、recvall()、close()（均 bytes）\n"
            "  注意：很多 oracle 连上即**一次性输出全部数据**——不确定交互协议时先 recvall()/多次 recvline() 读全再解析；"
            "别臆造不存在的菜单/选项。\n"
            "  re, json, base64, binascii, hashlib, hmac, struct, math\n"
            "可直接 import：Crypto(pycryptodome，如 Crypto.Util.number)、sympy、gmpy2、secrets、random、fractions。\n"
            "策略：用 tcp() 与 oracle 交互，读题/源码搞清密码学机制（RSA/AES/异或/LCG/hash 等），"
            "实现对应攻击（如小指数立方根、共模、Hastad、ECB 逐字节、LCG 预测、长度扩展）拿 flag。\n"
            "**只输出 Python 代码**（可放 ```python 代码块），不要解释。\n\n"
            f"oracle 目标: {host}:{port}\n")
        if self.source:
            base += f"挑战源码(截断):\n{self.source[:3000]}\n"
        if prev_code and prev_err:
            base += f"\n你上一版代码报错了，请修正：\n上版代码:\n{prev_code[:1500]}\n错误: {prev_err}\n"
        return base + "\n代码:"

    def solve(self, host, port) -> dict:
        if not hasattr(self.reasoner, "_complete"):
            return {"success": False, "reason": "需 LLM 后端"}
        target = (host, int(port))
        code, err = None, None
        for i in range(self.max_iters):
            try:
                code = synth._extract_code(self.reasoner._complete(self._prompt(host, port, code, err)))
            except Exception as e:  # noqa: BLE001
                return {"success": False, "reason": f"LLM 失败: {e}", "log": self.log}
            result, err = synth.run_code(code, None, f"{host}:{port}", tcp_target=target)
            flag = None
            if isinstance(result, str):
                m = FLAG_RE.search(result)
                flag = m.group(0) if m else (result if result.strip().startswith(("flag", "HTB", "CTF")) else None)
            self.log.append({"iter": i, "err": err, "got_flag": bool(flag)})
            if flag:
                return {"success": True, "flag": flag, "code": code, "vuln": "Crypto",
                        "iters": i + 1, "reasoner": self.reasoner.name, "log": self.log}
        return {"success": False, "reason": err or "未夺旗", "last_code": code, "log": self.log}


def solve_crypto(host, port, source_text="") -> dict:
    """入口：对一个授权 crypto oracle 现写脚本夺旗。门控关闭时不启用。"""
    if not enabled():
        return {"success": False, "reason": "门控未开（需 CTF_MODE + allow_active）"}
    return CryptoSolver(source_text=source_text).solve(host, port)
