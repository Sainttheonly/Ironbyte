#!/usr/bin/env bash
set -euo pipefail

VERSION="$(cat VERSION)"
DIST="dist/ironbyte-guard-${VERSION}"

echo "[*] Building dist for version ${VERSION}"

rm -rf "${DIST}"
mkdir -p "${DIST}"/{bin,bpf,systemd,config,scripts}

# Build everything
echo "[*] Building BPF..."
(cd bpf && make clean && make)

echo "[*] Building Rust..."
cargo build --release

# Copy artifacts
cp target/release/ironbyte-guard "${DIST}/bin/"
cp bpf/guard.bpf.o "${DIST}/bpf/"
cp systemd/ironbyte-guard.service "${DIST}/systemd/"
cp config/config.yaml "${DIST}/config/"
cp scripts/install.sh "${DIST}/scripts/"
cp scripts/uninstall.sh "${DIST}/scripts/"
cp VERSION "${DIST}/"

# Permissions
chmod +x "${DIST}/bin/ironbyte-guard"
chmod +x "${DIST}/scripts/"*.sh

# Create tarball
tar -C dist -czf "dist/ironbyte-guard-${VERSION}.tar.gz" "ironbyte-guard-${VERSION}"

echo "[*] Done."
echo "[*] Output: dist/ironbyte-guard-${VERSION}.tar.gz"
