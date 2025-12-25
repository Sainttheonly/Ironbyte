# IronByte Guard v0.1.0

## Highlights
- eBPF syscall telemetry: `openat` + `write`
- Behavioral detection: TRUNC + distinct files + bytes threshold in time window
- Modes: `detect_only` (default) and `enforce` (kills)
- Config-driven via `/etc/ironbyte-guard/config.yaml`
- Allowlist + directory exclusions
- systemd service + install/uninstall scripts
- Release tarball: `dist/ironbyte-guard-0.1.0.tar.gz`

## Default thresholds
- window: 1s
- distinct files: 50
- bytes: 5 MB
- TRUNC required

## Safety
Start in `detect_only`, tune allowlist/exclusions, then enable `enforce`.
