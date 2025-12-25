# Threat Model (IronByte Guard v0.1.0)

## Goal
Interrupt ransomware-style file destruction by enforcing a behavioral circuit breaker at syscall time using eBPF telemetry.

## In-scope
- Ransomware that overwrites/encrypts many files quickly.
- Unknown/0-day ransomware payloads whose impact depends on mass file overwrite behavior.
- Commodity malware doing TRUNC + bulk rewrite.

## Out-of-scope
- “Low and slow” encryption staying below thresholds.
- Pure exfiltration (read-only) attacks.
- Memory-only malware with no file writes.
- Kernel-level attackers who can disable eBPF or tamper with the host.
- Network-only threats (not implemented).

## Detection primitive
A process is suspicious if, within a window (default 1s):
- it overwrites files (`O_TRUNC`)
- it touches many distinct files (default 50)
- it writes enough bytes (default 5MB)

## Response
- `detect_only`: log detection event
- `enforce`: send `SIGKILL` to TGID

## Tuning assumptions
- Legit tools can trip thresholds (backups, mass edits).
- Allowlist and directory exclusions reduce false positives.
- Start in `detect_only`, tune, then enable `enforce`.
