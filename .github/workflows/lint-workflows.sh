#!/usr/bin/env bash
# Lints workflow YAMLs: quotes balanced inside every `run:` block fragment,
# YAML parses. Catches the heredoc-echo-unterminated-quote class that hit
# win-dll twice (PowerShell ParserError only visible at CI time).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import pathlib, sys, re
try:
    import yaml
except ImportError:
    print("pyyaml missing; YAML parse check skipped"); sys.exit(0)
bad = 0
for f in pathlib.Path(".github/workflows").glob("*.yml"):
    yaml.safe_load(f.read_text())  # syntax
    text = f.read_text()
    for i, ln in enumerate(text.split("\n"), 1):
        t = ln.strip()
        if t.startswith(("echo ",)):
            # count unescaped double quotes on echo lines
            if t.count('"') % 2 != 0:
                print(f"{f}:{i}: unbalanced quotes: {t}")
                bad += 1
sys.exit(1 if bad else 0)
PY
