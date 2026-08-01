"""XBOW validation-benchmarks 适配器（github.com/xbow-engineering/validation-benchmarks）。

XBOW 是 104 个 flag 夺取型 Web CTF（docker-compose 起靶）。我们的管线是**检测型**而非夺旗型，
故采用**检测代理**指标：challenge 的 `tags`（目标漏洞类）能否被我们检出对应类的发现。
- 可检测标签（Python 检测器 + nuclei 覆盖）计入评测；
- 需利用型 agent 的标签（ssti/命令注入/反序列化/xxe/ssrf 等）标注为"覆盖边界外"，诚实反映能力差距。

用法：
  from hermes_ctf_lab.benchmarks import xbow
  xbow.coverage(repo)          # 静态覆盖分析（无需 docker）
  xbow.cases(repo, limit=3)    # 起真实 docker 靶跑管线
"""
from __future__ import annotations

import glob
import json
import os
import re
import subprocess
from pathlib import Path

import yaml

# XBOW 标签 → 我方**具体检测器**产出的漏洞类（精确匹配，非类桶；每类只由对应专用探针产出）。
# 细化后：一个 challenge 只有当我们检出其目标漏洞的**专用类**才算命中——通用"缺失头"等不再冒充命中。
DETECTABLE = {
    "xss": {"XSS"},
    "idor": {"Broken Access Control"},
    "sqli": {"SQL Injection"},
    "blind_sqli": {"SQL Injection"},
    "information_disclosure": {"Information Disclosure", "Sensitive Data Exposure"},
    "cve": {"Known CVE"},
    "ssti": {"SSTI"},                       # 新利用型探针
    "command_injection": {"Command Injection"},
    "lfi": {"Path Traversal"},
    "path_traversal": {"Path Traversal"},
    # default_credentials/jwt/ssrf/xxe/deserialization 等：无专用检测器 → 覆盖边界外（诚实计入差距）
}


def load_manifests(repo: str) -> list[dict]:
    out = []
    for f in sorted(glob.glob(f"{repo}/benchmarks/*/benchmark.json")):
        try:
            d = json.load(open(f))
        except Exception:  # noqa: BLE001
            continue
        d["_dir"] = str(Path(f).parent)
        d["tags"] = d.get("tags", []) or []
        out.append(d)
    return out


def expected_classes(tags: list[str]) -> set[str]:
    out = set()
    for t in tags:
        out |= DETECTABLE.get(t, set())
    return out


def coverage(repo: str) -> dict:
    ms = load_manifests(repo)
    total = len(ms)
    detectable = [m for m in ms if expected_classes(m["tags"])]
    by_tag = {}
    for m in ms:
        for t in m["tags"]:
            by_tag.setdefault(t, {"count": 0, "detectable": t in DETECTABLE})
            by_tag[t]["count"] += 1
    return {"total": total, "detectable_challenges": len(detectable),
            "coverage_pct": round(100 * len(detectable) / total, 1) if total else 0,
            "by_tag": dict(sorted(by_tag.items(), key=lambda x: -x[1]["count"])),
            "detectable_names": [Path(m["_dir"]).name for m in detectable]}


# ---------- docker 起靶 ----------
def _service_with_ports(compose_path: str) -> str | None:
    try:
        data = yaml.safe_load(open(compose_path))
    except Exception:  # noqa: BLE001
        return None
    for name, svc in (data.get("services") or {}).items():
        if svc.get("ports"):
            return name
    return None


def _compose(args, cwd, timeout=600):
    env = {**os.environ, "FLAG": os.environ.get("FLAG", "flag{hermes_bench}")}
    return subprocess.run(["docker", "compose", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=timeout)


def _published_port(cwd, service) -> int | None:
    """发现服务映射到宿主的端口——不假设容器内端口（80/8000/5000 等各异）。"""
    cid = _compose(["ps", "-q", service], cwd, timeout=30).stdout.strip().splitlines()
    if cid:
        r = subprocess.run(["docker", "port", cid[0]], capture_output=True, text=True, timeout=30)
        m = re.search(r"->\s*[\d.:]*:(\d+)", r.stdout)
        if m:
            return int(m.group(1))
    # 回退：按 compose 里声明的容器内端口逐个查
    for internal in ("80", "8000", "5000", "3000", "8080"):
        r = _compose(["port", service, internal], cwd, timeout=20)
        m = re.search(r":(\d+)\s*$", r.stdout.strip())
        if m:
            return int(m.group(1))
    return None


def _wait_http(port, tries=40):
    import time
    import httpx
    for _ in range(tries):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=1.5)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(1.0)
    return False


def cases(repo: str, limit: int | None = None, only_detectable: bool = True,
          names: list[str] | None = None):
    from hermes_ctf_lab.benchmarks.base import BenchCase
    from pathlib import Path as _P
    ms = load_manifests(repo)
    if names:
        want = set(names)
        ms = [m for m in ms if _P(m["_dir"]).name in want]
    elif only_detectable:
        ms = [m for m in ms if expected_classes(m["tags"])]
    if limit:
        ms = ms[:limit]
    result = []
    for m in ms:
        cdir = m["_dir"]
        compose = f"{cdir}/docker-compose.yml"
        svc = _service_with_ports(compose)
        truth = expected_classes(m["tags"])
        holder = {"cwd": cdir}

        def setup(cwd=cdir, service=svc):
            if not service:
                return None
            up = _compose(["up", "-d", "--build"], cwd, timeout=900)
            if up.returncode != 0:
                return None
            port = _published_port(cwd, service)
            if not port or not _wait_http(port):
                return None
            return f"http://127.0.0.1:{port}"

        def teardown(cwd=cdir):
            try:
                _compose(["down", "-v", "--remove-orphans"], cwd, timeout=120)
            except Exception:  # noqa: BLE001
                pass

        def normalize(verified):
            return {v["class"] for v in verified}

        result.append(BenchCase(
            name=Path(cdir).name, truth=truth, setup=setup, teardown=teardown,
            normalize=normalize, mode="recall",
            meta={"tags": m["tags"], "level": m.get("level")}))
    return result
