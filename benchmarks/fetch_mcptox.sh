#!/usr/bin/env bash
# Fetch the real MCPTox poisoned-tool corpus for the Phase-3 tripwire.
#
#   source:  MCPTox (arXiv:2508.14925) anonymized artifact
#            https://anonymous.4open.science/r/AAAI26-7C02
#   file:    pure_tool.json  (~316 KB, 485 poisoned tool descriptions / 45 servers)
#   dest:    benchmarks/data/mcptox_pure_tool.json  (git-ignored)
#
# The corpus is NOT vendored into this repo (it is third-party research data and
# embeds realistic-looking secret payloads). run_pie.py falls back to the
# committed synthetic sample (poison_samples.jsonl) when this file is absent.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/data/mcptox_pure_tool.json"
URL="https://anonymous.4open.science/api/repo/AAAI26-7C02/file/pure_tool.json"

mkdir -p "$HERE/data"
echo "downloading MCPTox pure_tool.json (~316 KB) from anonymous.4open.science ..."
curl -fsSL -m 120 "$URL" -o "$DEST"
python3 -c "import json,sys; d=json.load(open('$DEST')); n=sum(len(x) for x in d); print(f'ok: {n} poisoned cases across {len(d)} servers -> {\"$DEST\"}')"
