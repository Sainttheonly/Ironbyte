#!/usr/bin/env bash
set -euo pipefail
sudo -n true 2>/dev/null || { echo "ERROR: run sudo -v"; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ibg"
sudo install -m 755 "$SRC" /usr/local/bin/ibg
echo "OK: installed /usr/local/bin/ibg"
