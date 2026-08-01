"""动态利用合成 —— 无现成原语时，让 LLM 读题（源码/响应/过往技法）**现写一个 wheel** 并沙箱运行。

自我扩展：primitive 打不动 → 合成 `def solve(base_url, session)` → 受限沙箱执行 → 报错反馈迭代
→ 成功则把该"轮子"存回知识库（跨会话复用）。

⚠️ 仅用于**授权 CTF/靶场**（受 HERMES_CTF_MODE + allow_active 门控，recon-only/真实 Bugcrowd 下不启用）。
沙箱：只暴露 HTTP + 加密/解析库；**禁 os/subprocess/open/文件/任意 import**，限制本地爆破面。
"""
from __future__ import annotations

import builtins as _builtins
import json as _json
import os
import re
import subprocess as _sp
import sys as _sys
import tempfile as _tf

# 沙箱内可用的安全内置
_SAFE_BUILTINS = ["range", "len", "str", "int", "float", "bytes", "bytearray", "list", "dict",
                  "set", "frozenset", "tuple", "enumerate", "zip", "map", "filter", "sorted",
                  "reversed", "sum", "min", "max", "abs", "ord", "chr", "hex", "oct", "bin",
                  "print", "isinstance", "issubclass", "type", "repr", "format", "any", "all",
                  "bool", "next", "iter", "slice", "pow", "divmod", "round", "getattr", "hasattr",
                  "Exception", "ValueError", "KeyError", "IndexError", "TypeError", "RuntimeError",
                  "StopIteration", "True", "False", "None", "id", "vars"]

FLAG_RE = re.compile(os.environ.get("HERMES_FLAG_REGEX",
                     r"(?:flag|FLAG|HTB|CTF|xben)\{[^}\s]{1,200}\}"))

# 沙箱内**允许 import 的安全库根名**（合成/技能代码常写 import re/json/hashlib...）。
# os/subprocess/socket/sys/importlib 等一律不在名单，import 会被拒绝——安全面不变，健壮性提升。
_IMPORTABLE = {"re", "json", "base64", "binascii", "hashlib", "hmac", "struct", "itertools",
               "string", "math", "time", "html", "codecs", "urllib", "collections", "functools",
               "datetime", "random", "decimal", "fractions", "textwrap", "httpx", "jwt", "requests",
               # G8 crypto：数论/对称/非对称库（oracle 交互走注入的 tcp()，不放行 socket）
               "secrets", "Crypto", "Cryptodome", "sympy", "gmpy2",
               # pwn/rev：反汇编/ELF 解析/ROP（远程二进制经 tcp() 交互；无 qemu 本地跑）
               "capstone", "elftools", "ropgadget", "pwn", "pwnlib"}


def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    """受限 __import__：仅放行白名单安全库，其余（os/subprocess/socket...）拒绝。"""
    root = str(name).split(".")[0]
    if level == 0 and root in _IMPORTABLE:
        return _builtins.__import__(name, globals, locals, fromlist, level)
    raise ImportError(f"import '{name}' 被沙箱禁止")


def _target_of(base_url):
    """从 base_url 解析 (host, port)，供 web synth 注入 tcp()（原始 HTTP，绕 httpx 的 fragment 剥离等）。"""
    from urllib.parse import urlparse
    try:
        u = urlparse(base_url if "://" in str(base_url) else "http://" + str(base_url))
        if not u.hostname:
            return None
        return (u.hostname, u.port or (443 if u.scheme == "https" else 80))
    except Exception:  # noqa: BLE001
        return None


def enabled() -> bool:
    """仅 CTF/授权靶场 + 允许主动 时启用。"""
    from hermes import cli
    from hermes.scope import Scope
    return (os.environ.get("HERMES_CTF_MODE", "").lower() in ("1", "true", "yes")
            and cli.allow_active(Scope.load()))


class _Remote:
    """G8：极简 pwntools 风格 TCP 客户端（仅连挑战绑定的 target，非任意主机），供 crypto oracle 交互。"""

    def __init__(self, target, timeout=15):
        import socket
        self.s = socket.create_connection(target, timeout=timeout)
        self.s.settimeout(timeout)          # 防裸 recv() 无限阻塞（defense；硬界靠子进程超时）
        self.buf = b""

    def connect(self, *a, **k):
        return self          # 已在构造时连接；容忍 LLM 误调 connect()

    def send(self, d):
        self.s.sendall(d if isinstance(d, (bytes, bytearray)) else str(d).encode())

    def sendline(self, d=b""):
        d = d if isinstance(d, (bytes, bytearray)) else str(d).encode()
        self.s.sendall(bytes(d) + b"\n")

    def recv(self, n=4096):
        return self.s.recv(n)

    def recvuntil(self, delim, timeout=15):
        delim = delim if isinstance(delim, (bytes, bytearray)) else str(delim).encode()
        self.s.settimeout(timeout)
        while bytes(delim) not in self.buf:
            try:
                chunk = self.s.recv(4096)
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(bytes(delim))
        if i < 0:
            out, self.buf = self.buf, b""
            return out
        out = self.buf[:i + len(delim)]
        self.buf = self.buf[i + len(delim):]
        return out

    def recvline(self, timeout=15):
        return self.recvuntil(b"\n", timeout)

    def recvall(self, timeout=3):
        self.s.settimeout(timeout)
        data, self.buf = self.buf, b""
        try:
            while True:
                c = self.s.recv(4096)
                if not c:
                    break
                data += c
        except Exception:  # noqa: BLE001
            pass
        return data

    def close(self):
        try:
            self.s.close()
        except Exception:  # noqa: BLE001
            pass


def _sandbox(session, base_url, tcp_target=None):
    import base64
    import binascii
    import codecs
    import hashlib
    import hmac
    import html
    import itertools
    import json
    import math
    import string
    import struct
    import time
    from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse

    import httpx

    def http(method, path, **kw):
        """只对目标发请求（相对路径拼到 base_url）；带上认证会话。"""
        url = path if str(path).startswith("http") else urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
        cli = session or httpx
        return cli.request(method, url, timeout=kw.pop("timeout", 15), **kw)

    g = {"re": re, "json": json, "base64": base64, "hashlib": hashlib, "hmac": hmac,
         "binascii": binascii, "struct": struct, "itertools": itertools, "string": string,
         "math": math, "time": time, "html": html, "codecs": codecs, "httpx": httpx,
         "quote": quote, "urlencode": urlencode, "urljoin": urljoin, "parse_qs": parse_qs,
         "urlparse": urlparse, "session": session, "base_url": base_url, "http": http}
    for opt in ("jwt", "requests"):
        try:
            g[opt] = __import__(opt)
        except Exception:  # noqa: BLE001
            pass
    if tcp_target:                # G8 crypto/pwn：注入 tcp() —— 仅连挑战绑定的 target（忽略传入的 host/port 参数）
        g["tcp"] = lambda *a, **k: _Remote(tcp_target)
    g["__builtins__"] = {k: getattr(_builtins, k) for k in _SAFE_BUILTINS if hasattr(_builtins, k)}
    g["__builtins__"]["__import__"] = _safe_import      # 允许 import 白名单安全库（禁 os/subprocess）
    return g


def run_code(code: str, session, base_url: str, isolate=None, tcp_target=None):
    """执行 LLM 写的 solve()，返回 (result, error)。

    isolate=None 时读环境 HERMES_SYNTH_ISOLATE 决定；True 走**子进程隔离**（超时/资源限，
    更复杂/更长的 exploit 可跑而不危及主进程），False 走同进程受限沙箱（快、默认）。
    tcp_target=(host,port) 时给沙箱注入 tcp()（G8 crypto oracle 交互）。
    """
    if isolate is None:
        isolate = os.environ.get("HERMES_SYNTH_ISOLATE", "").lower() in ("1", "true", "yes")
    if isolate:
        return run_code_isolated(code, session, base_url, tcp_target=tcp_target)
    g = _sandbox(session, base_url, tcp_target=tcp_target)
    try:
        exec(compile(code, "<synth>", "exec"), g)          # noqa: S102 — CTF 授权靶场专用
    except Exception as e:  # noqa: BLE001
        return None, f"编译/加载错误 {type(e).__name__}: {e}"
    solve = g.get("solve")
    if not callable(solve):
        return None, "未定义 solve(base_url, session)"
    # inline 墙钟界：防 LLM 代码阻塞挂死（网络类另有 socket 超时；纯 CPU 死循环靠批测子进程硬杀）
    from hermes import reliability
    secs = float(os.environ.get("HERMES_INLINE_TIMEOUT", "30"))
    return reliability.call_with_timeout(lambda: solve(base_url, session), secs)


# 子进程隔离执行体：在**独立进程**里重建同样的白名单沙箱（禁 __import__/os/open），
# 加 resource 限（CPU/内存/文件数）与超时；结果经 stdout 的 JSON 回传。payload 全走临时文件避免转义。
_ISO_RUNNER = r'''
import sys, json, resource, builtins as _b
def _lim(kind, soft):
    try:
        hard = resource.getrlimit(kind)[1]
        cap = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
        resource.setrlimit(kind, (cap, hard))
    except Exception:
        pass
_lim(resource.RLIMIT_CPU, 40)                        # pwn/rev 的 capstone/ROPgadget 分析可能吃 CPU
_lim(resource.RLIMIT_AS, 2 * 1024 * 1024 * 1024)     # 2G：静态分析可能吃内存
_lim(resource.RLIMIT_NOFILE, 256)

p = json.load(open(sys.argv[1]))
code, base_url, cookies, SAFE = p["code"], p["base_url"], p.get("cookies") or {}, p["safe"]
IMPORTABLE = set(p.get("importable") or [])
tcp_target = p.get("tcp_target")
def _safe_import(name, g=None, l=None, fromlist=(), level=0):
    root = str(name).split(".")[0]
    if level == 0 and root in IMPORTABLE:
        return _b.__import__(name, g, l, fromlist, level)
    raise ImportError("import '" + str(name) + "' blocked")

import base64, binascii, codecs, hashlib, hmac, html, itertools, math, re, string, struct, time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse
import httpx
session = httpx.Client(cookies=cookies, timeout=15, follow_redirects=True) if cookies else None
def http(method, path, **kw):
    url = path if str(path).startswith("http") else urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
    c = session or httpx
    return c.request(method, url, timeout=kw.pop("timeout", 15), **kw)
g = {"re": re, "json": json, "base64": base64, "hashlib": hashlib, "hmac": hmac, "binascii": binascii,
     "struct": struct, "itertools": itertools, "string": string, "math": math, "time": time, "html": html,
     "codecs": codecs, "httpx": httpx, "quote": quote, "urlencode": urlencode, "urljoin": urljoin,
     "parse_qs": parse_qs, "urlparse": urlparse, "session": session, "base_url": base_url, "http": http}
for opt in ("jwt", "requests"):
    try:
        g[opt] = __import__(opt)
    except Exception:
        pass
if tcp_target:
    import socket as _sock
    class _Remote:
        def __init__(s):
            s.s = _sock.create_connection(tuple(tcp_target), timeout=15); s.s.settimeout(15); s.buf = b""
        def connect(s, *a, **k): return s
        def send(s, d): s.s.sendall(d if isinstance(d, (bytes, bytearray)) else str(d).encode())
        def sendline(s, d=b""):
            d = d if isinstance(d, (bytes, bytearray)) else str(d).encode(); s.s.sendall(bytes(d) + b"\n")
        def recv(s, n=4096): return s.s.recv(n)
        def recvuntil(s, delim, timeout=15):
            delim = delim if isinstance(delim, (bytes, bytearray)) else str(delim).encode()
            s.s.settimeout(timeout)
            while bytes(delim) not in s.buf:
                try: c = s.s.recv(4096)
                except Exception: break
                if not c: break
                s.buf += c
            i = s.buf.find(bytes(delim))
            if i < 0:
                o, s.buf = s.buf, b""; return o
            o = s.buf[:i + len(delim)]; s.buf = s.buf[i + len(delim):]; return o
        def recvline(s, timeout=15): return s.recvuntil(b"\n", timeout)
        def recvall(s, timeout=3):
            s.s.settimeout(timeout); data, s.buf = s.buf, b""
            try:
                while True:
                    c = s.s.recv(4096)
                    if not c: break
                    data += c
            except Exception: pass
            return data
        def close(s):
            try: s.s.close()
            except Exception: pass
    g["tcp"] = lambda *a, **k: _Remote()
g["__builtins__"] = {k: getattr(_b, k) for k in SAFE if hasattr(_b, k)}
g["__builtins__"]["__import__"] = _safe_import
out = {"result": None, "error": None}
try:
    exec(compile(code, "<synth-iso>", "exec"), g)
    solve = g.get("solve")
    if not callable(solve):
        out["error"] = "未定义 solve(base_url, session)"
    else:
        r = solve(base_url, session)
        out["result"] = r if isinstance(r, str) else (str(r) if r is not None else None)
except Exception as e:
    out["error"] = type(e).__name__ + ": " + str(e)
sys.stdout.write("__SYNTH_RESULT__" + json.dumps(out))
'''


def _cookies_of(session) -> dict:
    try:
        return {c.name: c.value for c in session.cookies.jar} if session is not None else {}
    except Exception:  # noqa: BLE001
        return {}


def run_code_isolated(code: str, session, base_url: str, timeout: int = 45, tcp_target=None):
    """在独立 python 子进程里跑 solve()（超时即 kill、资源受限、最小 env），返回 (result, error)。"""
    payload = {"code": code, "base_url": base_url, "cookies": _cookies_of(session),
               "safe": _SAFE_BUILTINS, "importable": sorted(_IMPORTABLE),
               "tcp_target": list(tcp_target) if tcp_target else None}
    f = _tf.NamedTemporaryFile("w", suffix=".json", delete=False)
    try:
        _json.dump(payload, f)
        f.close()
        env = {"PATH": os.environ.get("PATH", ""), "LANG": os.environ.get("LANG", "C.UTF-8")}
        try:
            r = _sp.run([_sys.executable, "-c", _ISO_RUNNER, f.name],
                        capture_output=True, text=True, timeout=timeout, env=env)
        except _sp.TimeoutExpired:
            return None, f"运行超时被终止(>{timeout}s)"
        out = r.stdout or ""
        i = out.find("__SYNTH_RESULT__")
        if i < 0:
            return None, f"子进程无结果(rc={r.returncode}): {(r.stderr or out)[:200]}"
        try:
            obj = _json.loads(out[i + len("__SYNTH_RESULT__"):])
        except Exception as e:  # noqa: BLE001
            return None, f"结果解析失败: {e}"
        return obj.get("result"), obj.get("error")
    finally:
        try:
            os.unlink(f.name)
        except Exception:  # noqa: BLE001
            pass


def _extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\s*(.+?)```", text, re.S)
    return (m.group(1) if m else text).strip()


class Synthesizer:
    """LLM 现写现跑的利用合成器（ReAct：写码→跑→读错→改，成功存轮子）。"""

    def __init__(self, session=None, source_text="", max_iters=None):
        from hermes_ctf_lab.exploit_agent import make_reasoner
        self.session = session
        self.source = source_text or ""
        self.reasoner = make_reasoner()
        # 显式传入优先；否则读 env（硬题如 LockTalk 多给几轮更稳），默认 4
        self.max_iters = max_iters if max_iters is not None else int(os.environ.get("HERMES_SYNTH_MAX_ITERS", "4"))
        self.log = []
        self.research_notes = ""      # Phase B：合成前联网研究得到的技法/CVE 要点
        self.learn_failure = True     # G7：为 False 时不把本轮当死胡同写失败记忆（已被别处确认）

    def _context(self, observations) -> str:
        """题面上下文（源码+观察正文）——用于技能语义检索、失败召回、研究线索抽取。"""
        obs = " ".join(str(o.get("body", "") or o.get("url", "")) for o in (observations or []))
        return (self.source + " " + obs)[:3000]

    def _skill_hints(self, ctx) -> str:
        """语义检索命中的过往技能（描述+代码）作为可改写复用的参考。"""
        try:
            from hermes_ctf_lab import skills
            top = skills.match(ctx, k=2)
            return "\n".join(f"# {s.get('name')}: {s.get('description', '')}\n{s.get('code', '')[:1200]}"
                             for s in top)
        except Exception:  # noqa: BLE001
            return ""

    def _avoid(self, ctx) -> list[str]:
        try:
            from hermes import knowledge
            return knowledge.recall_failures(ctx)
        except Exception:  # noqa: BLE001
            return []

    def _prompt(self, base_url, observations, prev_code, prev_err) -> str:
        ctx = self._context(observations)
        hints, avoid = self._skill_hints(ctx), self._avoid(ctx)
        base = (
            "你是顶尖 CTF 选手兼漏洞利用开发者。为下面这个**授权 CTF web 题**写一个 Python 函数：\n"
            "  def solve(base_url, session):  # 返回 flag 字符串（flag{...}/HTB{...}），拿不到返回 None\n"
            "可直接用（**已注入命名空间，勿 import os/subprocess/open**）：\n"
            "  http(method, path, **kw)  # 对目标发请求，path 相对 base_url，带认证会话；返回 httpx.Response\n"
            "  tcp()  # 连到目标 host:port 的**原始 socket**（send/sendline/recv/recvuntil/recvline/recvall/close）\n"
            "         # 当 http() 无法表达所需请求时用它手写**原始 HTTP**：例如路径里要放字面 '#'（httpx 会当\n"
            "         # fragment 丢弃）、畸形/未归一化路径、HAProxy/nginx ACL 绕过等——如\n"
            "         #   r=tcp(); r.send(b'GET /api/v1/x#/../y HTTP/1.1\\r\\nHost: h\\r\\nConnection: close\\r\\n\\r\\n'); r.recvall()\n"
            "  session, re, json, base64, hashlib, hmac, binascii, struct, itertools, string, math,\n"
            "  codecs, quote, urlencode, urljoin, parse_qs, jwt(若装)\n"
            "  可 import：Crypto/sympy/gmpy2（crypto）、capstone/elftools(pyelftools)/ropgadget（pwn/rev）。\n"
            "若为 **pwn/rev**（源码含二进制 triage：file/checksec/nm/objdump 反汇编）：目标二进制在**远端**，\n"
            "  用 tcp() 交互（先 recvuntil 读提示再 send）；据反汇编/符号/保护位(NX/PIE/Canary)构造 payload——\n"
            "  ret2win/栈溢出(cyclic 定偏移)/ROP/格式化字符串；用 struct.pack('<Q'/'<I') 打包地址；\n"
            "  用 capstone 反汇编、pyelftools 读符号/plt/got。溢出偏移不确定就试常见值(40/72/136...)。\n"
            "策略：读题面/源码搞清逻辑与算法（如需自定义编解码/签名/爆破就自己实现），构造请求拿 flag。"
            "一般用 http()；只有 http() 表达不了的原始/畸形请求才用 tcp() 手写 HTTP。\n"
            "**只输出 Python 代码**（可放 ```python 代码块），不要解释。\n\n"
            f"目标: {base_url}\n")
        if self.source:
            base += f"挑战源码(截断):\n{self.source[:6000]}\n"
        if observations:
            base += f"侦察/响应观察:\n{str(observations)[:1200]}\n"
        if self.research_notes:
            base += f"外部研究要点(公开技法/CVE，供参考):\n{self.research_notes[:1200]}\n"
        if hints:
            base += f"过往可复用技能(可改写复用)：\n{hints}\n"
        if avoid:
            base += "⚠️ 以下方向过去已失败、别再重复：\n- " + "\n- ".join(avoid) + "\n"
        if prev_code and prev_err:
            base += f"\n你上一版代码报错了，请修正：\n上版代码:\n{prev_code[:1500]}\n错误: {prev_err}\n"
        return base + "\n代码:"

    def _enrich(self, base_url, observations):
        """自主侦察：把观察正文里提到的同源路径也抓回来，给 LLM 更全的题面。"""
        obs = list(observations or [])
        try:
            from hermes import tools
            r0 = tools.get(base_url.rstrip("/") + "/", session=self.session)
            obs.append({"url": "/", "body": r0.text[:500]})
            seen = {o.get("url") for o in obs}
            blob = " ".join(str(o.get("body", "")) for o in obs)
            paths = re.findall(r"/[A-Za-z0-9_./-]{1,40}", blob)
            for p in list(dict.fromkeys(paths))[:6]:
                if p in seen or p.endswith((".css", ".js", ".png", ".ico", ".jpg")):
                    continue
                try:
                    rr = tools.get(base_url.rstrip("/") + p, session=self.session)
                    if rr.status_code < 500:
                        obs.append({"url": p, "status": rr.status_code, "body": rr.text[:400]})
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            pass
        return obs

    # ---------- 合成前联网研究（G2，总是主动研究）----------
    _RESEARCH_KW = ("freemarker", "velocity", "twig", "jinja2", "jinja", "mako", "erb", "smarty",
                    "pickle", "pyyaml", "yaml", "jwt", "jws", "pyjwt", "python_jwt", "jsonwebtoken",
                    "graphql", "xxe", "ssti", "deserial", "ognl", "spel", "werkzeug", "flask",
                    "django", "express", "ejs", "handlebars", "haproxy", "nginx", "prototype",
                    "libxml", "lxml", "marshal", "phar", "log4j", "spring")

    def _clues(self, observations) -> list[str]:
        """从源码/观察抽取"值得联网研究"的公开线索：CVE 号、已知框架/库名、import 名。"""
        text = self._context(observations)
        low = text.lower()
        clues: list[str] = []
        for m in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I):
            clues.append(m.upper())
        for kw in self._RESEARCH_KW:
            if kw in low:
                clues.append(kw)
        for m in re.findall(r"(?:^|\n)\s*(?:import|from)\s+([a-zA-Z_][\w]+)", text):
            clues.append(m)
        for m in re.findall(r"require\(['\"]([\w@/-]+)", text):
            clues.append(m)
        seen, out = set(), []
        for c in clues:                        # 去重保序
            if c.lower() not in seen:
                seen.add(c.lower()); out.append(c)
        return out[:3]                         # 每题研究调用上限，控延迟

    def _research(self, observations):
        try:
            from hermes_ctf_lab import research
        except Exception:  # noqa: BLE001
            return
        if not research.enabled():
            return
        notes = []
        for c in self._clues(observations):
            r = research.research(f"{c} exploit technique payload")
            if r:
                notes.append(f"[{c}]\n{r}")
        if notes:
            self.research_notes = "\n".join(notes)[:1500]

    def solve(self, base_url, observations=None) -> dict:
        if not hasattr(self.reasoner, "_complete"):
            return {"success": False, "reason": "需 LLM 后端"}
        observations = self._enrich(base_url, observations)
        self._research(observations)          # 合成前先联网研究相关技法/CVE（门控内、缓存、可降级）
        tgt = _target_of(base_url)            # 注入 tcp()（原始 HTTP：可发 http() 表达不了的请求，如字面 #）
        code, err = None, None
        for i in range(self.max_iters):
            try:
                code = _extract_code(self.reasoner._complete(self._prompt(base_url, observations, code, err)))
            except Exception as e:  # noqa: BLE001
                return {"success": False, "reason": f"LLM 失败: {e}", "log": self.log}
            result, err = run_code(code, self.session, base_url, tcp_target=tgt)
            flag = None
            if isinstance(result, str):
                m = FLAG_RE.search(result)
                flag = m.group(0) if m else (result if result.strip().startswith(("flag", "HTB", "CTF")) else None)
            self.log.append({"iter": i, "err": err, "got_flag": bool(flag)})
            if flag:
                self._promote_skill(base_url, code, observations)
                return {"success": True, "flag": flag, "vuln": "Synthesized Exploit",
                        "code": code, "iters": i + 1, "reasoner": self.reasoner.name, "log": self.log}
        # 单发失败 → 子目标分解（G3：硬题拆成"取中间产物 → 用它夺旗"的链）
        dec = self._solve_decomposed(base_url, observations)
        if dec.get("success"):
            return dec
        if self.learn_failure:                # G7：确认型近失不写死胡同，避免误导后续避让
            self._reflect_failure(base_url, observations, err, code)
        return {"success": False, "reason": err or "未夺旗", "last_code": code, "log": self.log}

    # ---------- 子目标分解（G3：深多步链推理）----------
    def _decompose(self, observations) -> list[str]:
        ctx = self._context(observations)
        prompt = (
            "下面这个授权 CTF web 题单发利用没成功，很可能需要**多步链**。"
            "请把攻击拆成 2-4 个有先后依赖的子目标（例：先绕过某校验拿到令牌 → 再用令牌访问受限端点拿 flag）。"
            "每行一个子目标，从第一步到最后一步，最后一步应能拿到 flag。不要编号、不要解释。\n\n"
            f"题面/源码:\n{ctx[:2000]}\n"
            + (f"外部研究要点:\n{self.research_notes[:800]}\n" if self.research_notes else "")
            + "\n子目标(每行一个):")
        try:
            raw = self.reasoner._complete(prompt)
        except Exception:  # noqa: BLE001
            return []
        goals = []
        for ln in raw.splitlines():
            ln = re.sub(r"^\s*(?:[-*]\s+|\d+[.)]\s+)", "", ln).strip()
            if ln and len(ln) > 4 and not ln.lower().startswith(("子目标", "以下", "这里", "step", "步骤")):
                goals.append(ln)
        return goals[:4]

    def _step_prompt(self, base_url, observations, goal, state) -> str:
        p = (
            "这是一个授权 CTF web 题的**多步利用**中的一步。\n"
            f"本步子目标：{goal}\n"
            "写 def solve(base_url, session): 只完成**本步**，并 return 一个字符串结果——"
            "若本步即可拿到 flag 就返回 flag；否则返回本步获得的中间产物（令牌/cookie 值/泄露串）。\n"
            "★运行契约：一般发请求用注入的 **http(method, path, **kw)**（path 相对，如 http('POST','/stage1', json=...)）；"
            "**绝不用 session.get/session.post、绝不 import requests**（session 可能为 None）；"
            "http() 表达不了的原始/畸形请求（如路径含字面 '#'、ACL 绕过）用注入的 **tcp()** 手写原始 HTTP；"
            "可 import re/json/hashlib 等安全库，禁 os/open。只输出代码。\n\n"
            f"目标:{base_url}\n")
        if self.source:
            p += f"源码(截断):\n{self.source[:1800]}\n"
        if self.research_notes:
            p += f"外部研究要点:\n{self.research_notes[:800]}\n"
        if state:
            p += "已完成步骤及其结果(可直接使用这些中间产物):\n"
            for s in state:
                p += f"- {s['goal']} => {str(s['result'])[:300]}\n"
        return p + "\n代码:"

    def _solve_decomposed(self, base_url, observations) -> dict:
        goals = self._decompose(observations)
        if len(goals) < 2:
            return {"success": False}
        state = []
        for goal in goals[:4]:
            got, err = None, None
            for _ in range(2):                 # 每子目标最多 2 轮改错
                try:
                    code = _extract_code(self.reasoner._complete(
                        self._step_prompt(base_url, observations, goal, state)))
                except Exception:  # noqa: BLE001
                    break
                result, err = run_code(code, self.session, base_url, tcp_target=_target_of(base_url))
                if isinstance(result, str) and result.strip():
                    got = result.strip()
                    m = FLAG_RE.search(got)
                    if m:                       # 任一步直接拿到 flag → 收工
                        self._promote_skill(base_url, code, observations)
                        return {"success": True, "flag": m.group(0), "code": code,
                                "vuln": "Synthesized Exploit (multi-step)", "steps": len(state) + 1,
                                "reasoner": self.reasoner.name, "log": self.log}
                    break
            state.append({"goal": goal, "result": got if got is not None else f"(失败:{err})"})
        return {"success": False}

    # ---------- 成功即泛化促进为技能（G1）----------
    def _promote_skill(self, base_url, code, observations):
        """把刚验证成功的代码泛化成"参数化+带签名"的技能写入技能库；泛化失败则原样存。"""
        meta = self._generalize(code, observations)
        try:
            from hermes_ctf_lab import skills
            if meta:
                skills.add_skill(meta["code"], name=meta.get("name", ""),
                                 description=meta.get("description", ""),
                                 vuln_class=meta.get("vuln_class", ""),
                                 signature=meta.get("signature", []),
                                 provenance={"from": base_url, "reviewed": False})
            else:
                skills.add_skill(code.strip()[:4000], provenance={"from": base_url, "reviewed": False})
        except Exception:  # noqa: BLE001
            pass

    def _generalize(self, code, observations):
        """让 LLM 去硬编码、抽签名。用分隔符格式（避免把多行代码塞进 JSON 字符串的脆弱性）。"""
        prompt = (
            "下面是一段刚在**授权 CTF 靶场验证成功**的利用代码 solve(base_url, session)。"
            "请把它**泛化成可跨同类题复用的技能**。\n"
            "★最关键：**绝不硬编码本题实例特有的值**（盐值/密钥/具体路径/token/魔数）——"
            "这些必须在运行时从响应正文里用正则/解析动态提取（例如从 hint 字段里 re.search 出盐值），"
            "使同一技能面对『同机制但参数不同』的题也能直接跑通。保留通用逻辑与算法。\n"
            "★运行契约（务必遵守）：发请求**只用注入的 http(method, path, **kw)**，path 用相对路径"
            "（如 http('GET','/token')、http('POST','/verify', json=...)）；**绝不要用 session.get/"
            "session.post**（session 可能为 None）。可 import re/json/hashlib 等安全库，禁 os/subprocess/open。"
            "仍返回 flag 字符串。\n"
            "严格按下面格式输出（不要多余解释）：\n"
            "NAME: <短名>\nVULN_CLASS: <漏洞类，如 ssti/jwt/crypto-oracle>\n"
            "SIGNATURE: <5-8个英文检索关键词，逗号分隔>\nDESCRIPTION: <一句话适用场景>\n"
            "```python\n<泛化后的完整 solve 代码>\n```\n\n"
            f"成功代码:\n{code[:2500]}\n"
            + (f"\n本题响应/源码片段（据此判断那些常量在运行时该从哪个字段/正则提取）:\n"
               f"{self._context(observations)[:1200]}\n" if observations else ""))
        try:
            raw = self.reasoner._complete(prompt)
        except Exception:  # noqa: BLE001
            return None
        # 稳健取码：优先代码块围栏；否则从 def solve 起截取（丢弃上方 NAME/SIGNATURE 头行，避免整段不可编译）
        mfence = re.search(r"```(?:python)?\s*(.+?)```", raw, re.S)
        c = mfence.group(1).strip() if mfence else ""
        if "def solve" not in c:
            mdef = re.search(r"(def solve\(.*)", raw, re.S)
            c = mdef.group(1).strip() if mdef else ""
        if "def solve" not in c:
            return None
        try:
            compile(c, "<skill>", "exec")            # 泛化后必须可编译，否则退化为原样存
        except Exception:  # noqa: BLE001
            return None

        def _field(tag, default=""):
            m = re.search(rf"^{tag}:\s*(.+)$", raw, re.M)
            return m.group(1).strip() if m else default
        sig = [t.strip() for t in re.split(r"[,\s]+", _field("SIGNATURE")) if t.strip()]
        return {"name": _field("NAME", "synthesized-skill"), "vuln_class": _field("VULN_CLASS"),
                "description": _field("DESCRIPTION"), "signature": sig[:8], "code": c}

    # ---------- 失败即反思（G4）----------
    def _reflect_failure(self, base_url, observations, last_err, last_code):
        ctx = self._context(observations)
        prompt = (
            "下面这个授权 CTF 题我没能拿到 flag。用**一句话中文**复盘：最可能的正确方向是什么、"
            "以及别再重复哪种无效思路。只输出这一句话，不要解释。\n\n"
            f"目标:{base_url}\n源码/观察:{ctx[:1500]}\n最后错误:{last_err}\n最后代码:{(last_code or '')[:800]}\n")
        note = f"失败:{last_err}" if last_err else ""
        try:
            out = self.reasoner._complete(prompt).strip().splitlines()
            note = out[0][:300] if out else note
        except Exception:  # noqa: BLE001
            pass
        if note:
            try:
                from hermes import knowledge
                knowledge.remember_failure(ctx, note)
            except Exception:  # noqa: BLE001
                pass
