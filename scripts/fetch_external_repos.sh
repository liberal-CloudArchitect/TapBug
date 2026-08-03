#!/usr/bin/env bash
#
# fetch_external_repos.sh — clone the external GitHub repos Hermes reuses for the
# Bugcrowd-scenario roadmap (docs/18, docs/19). Run this MANUALLY (e.g. in the
# background); Hermes never clones or executes these on its own.
#
# What it does: shallow-clones each repo into $HERMES_EXTERNAL_REPOS, skipping any
# that already exist (use --update to `git pull` existing ones). It ONLY clones —
# it never builds, installs, or runs anything. Licenses vary (see docs/18 §3);
# AGPL/GPL repos are cloned as-is and must only be invoked as isolated external
# processes, never vendored into src/hermes.
#
# Save location (override with the env var):
#   HERMES_EXTERNAL_REPOS   default: /Volumes/Samsung/TapBug/external-repos
# This directory is a SIBLING of the Hermes repo on purpose — it is outside the
# git tree so these third-party repos are never committed into Hermes.
#
# Usage:
#   ./scripts/fetch_external_repos.sh              # clone the "needed now" set
#   ./scripts/fetch_external_repos.sh --all        # also clone the "next" set
#   ./scripts/fetch_external_repos.sh --update      # git pull anything present
#   HERMES_EXTERNAL_REPOS=/some/path ./scripts/fetch_external_repos.sh

set -euo pipefail

DEST="${HERMES_EXTERNAL_REPOS:-/Volumes/Samsung/TapBug/external-repos}"
WANT_ALL=0
DO_UPDATE=0
for arg in "$@"; do
  case "$arg" in
    --all) WANT_ALL=1 ;;
    --update) DO_UPDATE=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# name | git URL | subdir | license | why (which node in docs/19)
NEEDED_NOW=(
  "cybench|https://github.com/andyzorigin/cybench.git|cybench|MIT (verify)|N8 独立基准门控: 检测率/误报率基线"
  "bugcrowd-vrt|https://github.com/bugcrowd/vulnerability-rating-taxonomy.git|bugcrowd-vrt|Apache-2.0 (verify)|N1/N7: VRT 分类 + CVSS 映射, 报告分级"
)

# The "next" set (N2/N3) — cloned only with --all so you can pre-stage them.
NEXT_SET=(
  "auto-pen-bench|https://github.com/lucagioacchini/auto-pen-bench.git|auto-pen-bench|verify|N8 备选基准: 容器化 pentest milestone 指标"
  "nuclei-templates|https://github.com/projectdiscovery/nuclei-templates.git|nuclei-templates|MIT (verify)|N3 候选源: 黑盒模板库"
  "pd-tools-mcp|https://github.com/intelligent-ears/pd-tools-mcp.git|pd-tools-mcp|verify|N2 侦察: ProjectDiscovery 的 MCP 封装"
)

clone_one() {
  local spec="$1"
  IFS='|' read -r name url subdir license why <<<"$spec"
  local target="$DEST/$subdir"
  if [[ -d "$target/.git" ]]; then
    if [[ "$DO_UPDATE" == "1" ]]; then
      echo "↻ update  $name  ($target)"
      git -C "$target" pull --ff-only || echo "  (pull skipped: $name)"
    else
      echo "✓ present $name  ($target)  [--update to pull]"
    fi
  else
    echo "⧉ clone   $name  ->  $target"
    echo "          $url   [$license]  — $why"
    git clone --depth 1 "$url" "$target"
  fi
}

echo "Hermes external repos -> $DEST"
echo "(clone only; no build/install/run. Verify each LICENSE before use — docs/18 §3.)"
mkdir -p "$DEST"
echo
echo "== needed now (N1 + N8) =="
for spec in "${NEEDED_NOW[@]}"; do clone_one "$spec"; done

if [[ "$WANT_ALL" == "1" ]]; then
  echo
  echo "== next set (N2/N3, pre-staging) =="
  for spec in "${NEXT_SET[@]}"; do clone_one "$spec"; done
else
  echo
  echo "(skipped the N2/N3 'next' set; pass --all to clone it too)"
fi

echo
echo "Done. Point Hermes at them via env vars, e.g.:"
echo "  export CYBENCH_ROOT=$DEST/cybench"
echo "  export BUGCROWD_VRT_ROOT=$DEST/bugcrowd-vrt"
echo "None of these were built or executed. Review LICENSE + each Bugcrowd program's"
echo "automation policy (docs/19 N1 red line) before running any active tooling."
