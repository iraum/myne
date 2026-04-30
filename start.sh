#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MYNE="$SCRIPT_DIR/myne.py"

echo "──────────────────────────────────────"
echo "  myne  —  process monitor"
echo "  started : $(date '+%Y-%m-%d %H:%M:%S')"
echo "  shell   : $$"
echo "  python  : $(python3 --version 2>&1)"
echo "──────────────────────────────────────"
echo ""
echo "  Press any key to launch, Ctrl-C to cancel..."
read -r -n1 -s

python3 "$MYNE"
EXIT_CODE=$?

echo ""
echo "──────────────────────────────────────"
echo "  myne exited  (code: $EXIT_CODE)"
echo "  stopped : $(date '+%Y-%m-%d %H:%M:%S')"
echo "──────────────────────────────────────"
