# IronByte Guard (v0.1.0)

Kernel-level ransomware circuit breaker for Linux using eBPF.

IronByte Guard watches `openat()` + `write()` behavior and flags/kills processes that exhibit ransomware-style overwrite patterns:
- `O_TRUNC` overwrite intent
- many distinct files in a short window
- meaningful byte volume

Default mode: **detect_only**. Switch to **enforce** via config to enable kills.

---

## Install (tarball)

```bash
tar -xzf ironbyte-guard-0.1.0.tar.gz
cd ironbyte-guard-0.1.0
./scripts/install.sh
