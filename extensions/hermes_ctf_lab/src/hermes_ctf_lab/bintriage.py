"""二进制 triage —— 给 pwn/rev 挑战做静态分析，喂给 agent 当"源码"（无 gdb 动态、无 angr）。

对任务目录里的 ELF 跑 `file`/`nm`/`strings`/`objdump -d` + pyelftools 读保护位/符号/plt/got，
拼成文本注入 synth 的 source_text，让 agent 据反汇编/符号/保护位推理利用（ret2win/bof/ROP/fmtstr）。
交互仍走注入的 `tcp()`（远程二进制在 docker 里）。仅静态分析、只读，纯离线。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

_MAGIC = b"\x7fELF"


def _run(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001
        return f"(err {cmd[0]}: {e})"


def _checksec(path):
    """用 pyelftools 读 RELRO/NX/PIE/Canary/符号 —— 无需 pwntools。"""
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:  # noqa: BLE001
        return ""
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            out = [f"arch={elf.get_machine_arch()} type={elf['e_type']} entry={hex(elf['e_entry'])}"]
            seg = {s["p_type"] for s in elf.iter_segments()}
            out.append("NX=" + ("on" if "PT_GNU_STACK" in seg else "?"))
            out.append("PIE=" + ("yes" if elf["e_type"] == "ET_DYN" else "no"))
            out.append("RELRO=" + ("full/partial" if "PT_GNU_RELRO" in seg else "no"))
            funcs = []
            sym = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
            if sym:
                for s in sym.iter_symbols():
                    if s["st_info"]["type"] == "STT_FUNC" and s.name:
                        funcs.append(f"{s.name}@{hex(s['st_value'])}")
            canary = any("stack_chk" in x for x in funcs)
            out.append("Canary=" + ("yes" if canary else "no"))
            if funcs:
                out.append("funcs: " + ", ".join(funcs[:40]))
            return "\n".join(out)
    except Exception as e:  # noqa: BLE001
        return f"(elftools err: {e})"


def triage_file(path) -> str:
    p = str(path)
    parts = [f"# ==== BINARY TRIAGE: {Path(p).name} ====",
             "[file] " + _run(["file", p]).strip(),
             "[checksec/elf]\n" + _checksec(p),
             "[strings -n6 (截断)]\n" + _run(["strings", "-n", "6", p])[:1500],
             "[nm (符号, 截断)]\n" + _run(["nm", p])[:1500],
             "[objdump -d (反汇编, 截断)]\n" + _run(["objdump", "-d", p])[:6000]]
    return "\n".join(parts)


def is_elf(path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == _MAGIC
    except Exception:  # noqa: BLE001
        return False


def triage_dir(task_dir, max_bins=3) -> str:
    """扫任务目录里的 ELF（可执行/无扩展名），逐个 triage。返回拼接文本。"""
    out, n = [], 0
    for p in sorted(Path(task_dir).rglob("*")):
        if n >= max_bins:
            break
        try:
            if p.is_file() and p.stat().st_size < 5_000_000 and is_elf(p):
                out.append(triage_file(p))
                n += 1
        except Exception:  # noqa: BLE001
            pass
    return "\n\n".join(out)
