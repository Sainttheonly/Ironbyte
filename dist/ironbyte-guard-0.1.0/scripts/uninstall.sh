#!/usr/bin/env bash
set -euo pipefail

echo "Stopping service..."
sudo systemctl disable --now ironbyte-guard 2>/dev/null || true

echo "Removing systemd unit..."
sudo rm -f /etc/systemd/system/ironbyte-guard.service
sudo systemctl daemon-reload

echo "Removing binaries and assets..."
sudo rm -f /usr/local/bin/ironbyte-guard
sudo rm -rf /usr/lib/ironbyte-guard

echo "Removing config..."
sudo rm -rf /etc/ironbyte-guard

echo "Done."
echo "Verify:"
echo "  systemctl status ironbyte-guard"
echo "  which ironbyte-guard"
