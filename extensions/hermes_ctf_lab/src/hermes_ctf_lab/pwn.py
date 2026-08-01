"""G8 pwn 域求解器 —— 把 synth 的"LLM 现写脚本"扩到二进制 pwn（远程 ELF，经 tcp() 交互）。

无 qemu/gdb：目标二进制在 docker 里，agent 用注入的 `tcp()` 远程交互；据 `bintriage` 的静态分析
（file/checksec/nm/objdump 反汇编）+ 可 import capstone/elftools/ropgadget/struct 构造 payload
（ret2win/栈溢出/ROP/fmtstr）。复用 synth 沙箱/执行/迭代循环。

⚠️ 仅授权 CTF/靶场：`enabled()` = synth.enabled()（CTF_MODE + allow_active）。tcp() 仅连绑定 target。
"""
from __future__ import annotations

import os

from hermes_ctf_lab import synth

FLAG_RE = synth.FLAG_RE


def enabled() -> bool:
    return synth.enabled()


class PwnSolver:
    def __init__(self, source_text="", max_iters=None):
        from hermes_ctf_lab.exploit_agent import make_reasoner
        self.source = source_text or ""
        self.reasoner = make_reasoner()
        self.max_iters = max_iters if max_iters is not None else int(os.environ.get("HERMES_SYNTH_MAX_ITERS", "5"))
        self.log = []

    def _prompt(self, host, port, prev_code, prev_err) -> str:
        base = (
            "你是顶尖 CTF pwn 选手。为下面这个**授权 pwn 挑战**写 Python 函数：\n"
            "  def solve(base_url, session):  # 返回 flag 字符串（flag{...}/HTB{...}），拿不到返回 None\n"
            "已注入命名空间（**勿 import os/subprocess/open/socket**）：\n"
            "  tcp()  # 连到远端二进制，方法：send/sendline(bytes)、recv(n)、recvuntil(delim)、recvline()、"
            "recvall()、close()（均 bytes）\n"
            "  re, json, base64, binascii, struct, hashlib\n"
            "可直接 import：capstone、elftools(pyelftools)、ropgadget。\n"
            "据下方**二进制 triage**（file/checksec/nm/objdump 反汇编）分析：NX/PIE/Canary 保护位；"
            "找 win()/backdoor/system/'/bin/sh' 的地址；算栈溢出偏移（局部 buf 大小 + 8 saved rbp；"
            "不确定就试常见值 40/72/136/264）。\n"
            "构造 payload：ret2win = b'A'*offset + struct.pack('<Q', win_addr)（32位用 '<I'）；"
            "有 PIE 需先泄漏基址。用 tcp()：先 recvuntil 读提示 → send(payload) → recvall() 找 flag。\n"
            "**只输出 Python 代码**（可放 ```python 代码块），不要解释。\n\n"
            f"目标(远端二进制): {host}:{port}\n")
        if self.source:
            base += f"二进制 triage / 源码:\n{self.source[:7000]}\n"
        if prev_code and prev_err:
            base += f"\n你上一版代码报错了，请修正：\n上版代码:\n{prev_code[:1500]}\n错误: {prev_err}\n"
        return base + "\n代码:"

    def solve(self, host, port) -> dict:
        if not hasattr(self.reasoner, "_complete"):
            return {"success": False, "reason": "需 LLM 后端"}
        tgt = (host, int(port))
        code, err = None, None
        for i in range(self.max_iters):
            try:
                code = synth._extract_code(self.reasoner._complete(self._prompt(host, port, code, err)))
            except Exception as e:  # noqa: BLE001
                return {"success": False, "reason": f"LLM 失败: {e}", "log": self.log}
            # 隔离子进程执行：pwn 代码常有阻塞 recv/暴力循环，用子进程硬超时兜底防挂死（inline 无墙钟界）
            result, err = synth.run_code(code, None, f"{host}:{port}", tcp_target=tgt, isolate=True)
            flag = None
            if isinstance(result, str):
                m = FLAG_RE.search(result)
                flag = m.group(0) if m else (result if result.strip().startswith(("flag", "HTB", "CTF")) else None)
            self.log.append({"iter": i, "err": err, "got_flag": bool(flag)})
            if flag:
                return {"success": True, "flag": flag, "code": code, "vuln": "Pwn",
                        "iters": i + 1, "reasoner": self.reasoner.name, "log": self.log}
        return {"success": False, "reason": err or "未夺旗", "last_code": code, "log": self.log}


def solve_pwn(host, port, source_text="") -> dict:
    """入口：对一个授权 pwn 远端二进制现写脚本夺旗。门控关闭时不启用。"""
    if not enabled():
        return {"success": False, "reason": "门控未开（需 CTF_MODE + allow_active）"}
    return PwnSolver(source_text=source_text).solve(host, port)
