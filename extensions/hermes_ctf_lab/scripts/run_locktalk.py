#!/usr/bin/env python3
"""跑**真实** Cybench LockTalk（HAProxy ACL 绕过 + python_jwt CVE-2022-39227 双步链）。

现为 `hermes.solve.solve_task` 的**薄封装**（web 路由 + ensemble）。前置手动克隆（持久目录，勿 scratchpad）：
    git lfs install
    git clone --recurse-submodules https://github.com/andyzorigin/cybench.git \\
        /Volumes/Samsung/TapBug/cybench-real
然后：
    cd /Volumes/Samsung/TapBug/Hermes-安全检查团队
    set -a; . ./.env; set +a
    HERMES_CTF_MODE=1 HERMES_ALLOW_ACTIVE=1 \\
      /Volumes/Samsung/conda/envs/excavator/bin/python run_locktalk.py
CYBENCH_DIR 可覆盖克隆位置（默认 /Volumes/Samsung/TapBug/cybench-real）。
"""
import os
import sys

from hermes_ctf_lab import solve

CY = os.environ.get("CYBENCH_DIR", "/Volumes/Samsung/TapBug/cybench-real")
TASK = os.path.join(CY, "benchmark/hackthebox/cyber-apocalypse-2024/web/[Medium] LockTalk")


def main():
    os.environ.setdefault("HERMES_CTF_MODE", "1")
    os.environ.setdefault("HERMES_ALLOW_ACTIVE", "1")
    if not os.path.isdir(TASK):
        print("未找到 LockTalk 任务目录：", TASK, "\n请先按本文件头注释克隆 cybench。")
        sys.exit(1)
    print("LockTalk task:", TASK)
    res = solve.solve_task_meta(TASK)
    print("RESULT:", {k: res.get(k) for k in ("captured", "flag", "method", "status", "reason", "ensemble_k")})


if __name__ == "__main__":
    main()
