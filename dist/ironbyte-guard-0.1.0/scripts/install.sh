#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BIN_SRC=""
BPF_SRC=""
CFG_SRC=""
SVC_SRC=""

# Tarball layout
if [[ -f "${ROOT_DIR}/bin/ironbyte-guard" ]]; then
  BIN_SRC="${ROOT_DIR}/bin/ironbyte-guard"
  BPF_SRC="${ROOT_DIR}/bpf/guard.bpf.o"
  CFG_SRC="${ROOT_DIR}/config/config.yaml"
  SVC_SRC="${ROOT_DIR}/systemd/ironbyte-guard.service"
# Repo layout
else
  BIN_SRC="${ROOT_DIR}/target/release/ironbyte-guard"
  BPF_SRC="${ROOT_DIR}/bpf/guard.bpf.o"
  CFG_SRC="${ROOT_DIR}/config/config.yaml"
  SVC_SRC="${ROOT_DIR}/systemd/ironbyte-guard.service"
fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Missing binary: $BIN_SRC"
  echo "If running from repo: build first: cargo build --release"
  exit 1
fi

if [[ ! -f "$BPF_SRC" ]]; then
  echo "Missing BPF object: $BPF_SRC"
  echo "If running from repo: build first: (cd bpf && make)"
  exit 1
fi

sudo install -Dm755 "$BIN_SRC" /usr/local/bin/ironbyte-guard
sudo install -Dm644 "$BPF_SRC" /usr/lib/ironbyte-guard/guard.bpf.o

# Only install config if it doesn't exist (don’t overwrite user config)
if [[ ! -f /etc/ironbyte-guard/config.yaml ]]; then
  sudo install -Dm644 "$CFG_SRC" /etc/ironbyte-guard/config.yaml
else
  echo "Config exists, not overwriting: /etc/ironbyte-guard/config.yaml"
fi

sudo install -Dm644 "$SVC_SRC" /etc/systemd/system/ironbyte-guard.service

sudo systemctl daemon-reload
sudo systemctl enable --now ironbyte-guard

echo "Installed."
echo "Logs: journalctl -u ironbyte-guard -f"
