# IronByte Guard (v0.2 – kernel-enforce)

IronByte Guard is a **kernel-level ransomware circuit breaker** for Linux built on **eBPF**, with optional **LSM-based enforcement**.

It detects ransomware-style filesystem behavior in real time and escalates response safely:

**Observe → Warn → Contain → Kill**

Default mode is **detect_only** (log-only). Enforcement is available but deliberately hard-gated.

---

## Architecture

### Kernel (eBPF)
- Observes file operations: write, rename, unlink, truncate
- Emits structured events to userspace
- Optional LSM deny hooks when armed

### Userspace (Rust)
- Aggregates events by **process identity**
- Scores behavior over time windows
- Drives escalation state machine
- Applies enforcement with strict safety bounds

Identity is computed as:

FNV1a64(comm | exe_path_prefix)

This identity survives fork, respawn, and PID churn.

---

## Safety guarantees

IronByte Guard is explicitly designed **not to brick systems**.

Safety mechanisms include:

- Detect-only default (no enforcement unless explicitly armed)
- Dual arming for enforcement:
  1. config mode must be set to `enforce`
  2. policy.enforce_token must match environment variable `IBG_ENFORCE_TOKEN`
- Identity allowlist (logs ALLOWLIST_HIT, skips enforcement)
- Cooldowns (process-level and identity-level)
- Global and per-identity kill budgets
- Killset caps (bounded subtree traversal)
- Budget exhaustion degrades to **block-only** behavior instead of kill

---

## Configuration

Config file location:

/etc/ironbyte-guard/config.yaml

Example configuration:

mode: detect_only  
cooldown_seconds: 30  

policy:  
  enforce_token: "secret"  

  killset_cap: 256  
  budget_window_ns: 60000000000  
  budget_global_limit: 200  
  budget_per_id_limit: 50  

Enforcement tunables are loaded once at startup and stored in a OnceLock to keep runtime behavior deterministic.

---

## Development workflow

Build:

ibg build

Tests:

ibg test detect  
ibg test kill  
ibg test allow  

---

## Current status

Branch: v0.2-kernel-enforce

- Detection pipeline: complete
- Enforcement pipeline: complete
- LSM deny path: functional
- Cooldowns: enforced
- Budgets: enforced and verified
- Killset caps: enforced
- Policy → runtime wiring: complete
- Safety fallback (block-only): verified

This represents a stable, safe baseline.

---

## License

Apache-2.0. See LICENSE.
