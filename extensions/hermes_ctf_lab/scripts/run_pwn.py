#!/usr/bin/env python3
"""跑单个 pwn 挑战（本地 pwn_lab 或真实 Cybench pwn，docker 起 ELF + tcp() 远程交互）。

现为 `hermes.solve.solve_task` 的**薄封装**（统一域路由 + ensemble + 硬超时）。用法：
    cd /Volumes/Samsung/TapBug/Hermes-安全检查团队
    set -a; . ./.env; set +a
    HERMES_CTF_MODE=1 HERMES_ALLOW_ACTIVE=1 \\
      /Volumes/Samsung/conda/envs/excavator/bin/python run_pwn.py            # 默认本地 pwn_lab
    # 真实：PWN_TASK='/Volumes/.../cybench-real/.../pwn/[Very Easy] Delulu' ... run_pwn.py
"""
import os
import sys

from hermes_ctf_lab import solve

TASK = os.environ.get("PWN_TASK", os.path.join(os.path.dirname(os.path.abspath(__file__)), "labs", "pwn_lab"))


def main():
    os.environ.setdefault("HERMES_CTF_MODE", "1")
    os.environ.setdefault("HERMES_ALLOW_ACTIVE", "1")
    if not os.path.isdir(TASK):
        print("任务目录不存在:", TASK)
        sys.exit(1)
    print("PWN task:", TASK)
    res = solve.solve_task_meta(TASK)
    print("RESULT:", {k: res.get(k) for k in ("captured", "flag", "method", "status", "reason", "ensemble_k")})


if __name__ == "__main__":
    main()
