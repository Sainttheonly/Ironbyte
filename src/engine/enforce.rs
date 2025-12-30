use libbpf_rs::MapCore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;

use crate::engine::risk::RiskState;

// /proc subtree helpers
fn read_ppid(pid: u32) -> Option<u32> {
    // /proc/<pid>/stat: comm is in parentheses, ppid is field after state.
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rparen = stat.rfind(')')?;
    let after = &stat[rparen + 1..];
    let mut it = after.split_whitespace();
    let _state = it.next()?;
    let ppid_s = it.next()?;
    ppid_s.parse::<u32>().ok()
}

fn build_children_map() -> std::collections::HashMap<u32, Vec<u32>> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if name.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(pid) = name.parse::<u32>() {
                    if let Some(ppid) = read_ppid(pid) {
                        children.entry(ppid).or_default().push(pid);
                    }
                }
            }
        }
    }
    children
}

fn collect_subtree(root: u32, max_nodes: usize) -> Vec<u32> {
    let children = build_children_map();
    let mut out: Vec<u32> = Vec::new();
    let mut stack: Vec<u32> = vec![root];

    while let Some(pid) = stack.pop() {
        if out.len() >= max_nodes {
            break;
        }
        if out.contains(&pid) {
            continue;
        }
        out.push(pid);
        if let Some(kids) = children.get(&pid) {
            for &c in kids {
                if out.len() >= max_nodes {
                    break;
                }
                stack.push(c);
            }
        }
    }
    out
}

// ---- identity sweep helpers ----
const FNV_OFFSET: u64 = 1469598103934665603;
const FNV_PRIME: u64  = 1099511628211;

fn fnv1a64_prefix32(s: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in s.as_bytes().iter().take(32) {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn identity_key_for_pid(pid: u32) -> Option<u64> {
    let comm = read_comm(pid)?;
    let exe = read_exe(pid).unwrap_or_else(|| "?".into());
    Some(fnv1a64_prefix32(&format!("{}|{}", comm, exe)))
}

fn collect_identity_roots(risk_key: u64, max_roots: usize) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
            let pid = match name.parse::<u32>() { Ok(v) => v, Err(_) => continue };
            if let Some(k) = identity_key_for_pid(pid) {
                if k == risk_key {
                    out.push(pid);
                    if out.len() >= max_roots { break; }
                }
            }
        }
    }
    out
}

fn collect_identity_killset(risk_key: u64, fallback_root: u32, max_roots: usize, max_nodes: usize) -> Vec<u32> {
    use std::collections::HashSet;
    let mut roots = collect_identity_roots(risk_key, max_roots);
    if roots.is_empty() {
        roots.push(fallback_root);
    }
    let mut set: HashSet<u32> = HashSet::new();
    for r in &roots {
        for p in collect_subtree(*r, max_nodes) {
            set.insert(p);
        }
    }
    let mut v: Vec<u32> = set.into_iter().collect();
    v.sort_unstable();
    v
}


/// Score-based enforcement with escalation + subtree containment.
/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_score(
    enforce: bool,
    no_enforce: bool,
    skip_kill: bool,
    skip_block: bool,
    risk_key: u64,
    tgid: u32,
    ts_ns: u64,
    comm: &str,
    score: f64,
    cooldown_ns: u64,
    last_kill_ns: &mut HashMap<u32, u64>,
    blocked_map: &mut dyn MapCore,
    lsm_ctrl_map: &mut dyn MapCore,
    lsm_mark_blocked: fn(bool, &mut dyn MapCore, &mut dyn MapCore, u32),
    risk_state: &mut HashMap<u64, RiskState>,
) -> bool {
    // Escalate risk
    let cur = risk_state.get(&risk_key).copied().unwrap_or(RiskState::Observe);
    let next = cur.next();
    risk_state.insert(risk_key, next);
    eprintln!("RISK key={} tgid={} {:?}->{:?}", risk_key, tgid, cur, next);

    // Actions are gated by enforce
    if !enforce {
        return false;
    }


    // OBSERVE: log-only
    if next == RiskState::Observe {
        return false;
    }

    // WARN: block root only (if allowed)
        if next == RiskState::Warn {
        // log-only (no action)
        return false;
    }


    // CONTAIN: block subtree (no kill)
        if next == RiskState::Contain {
        // log-only (no action)
        return false;
    }


    // KILL: honor policies + cooldown, kill subtree
    if no_enforce {
        // preserve old behavior: if comm is no_enforce, don't kill
        return false;
    }

    if skip_kill {
        eprintln!("POLICY skip_kill=true reason=trusted_ancestry");
        return false;
    }

    let last = last_kill_ns.get(&tgid).copied().unwrap_or(0);
    if ts_ns.saturating_sub(last) < cooldown_ns {
        eprintln!("COOLDOWN: tgid={} comm={} (skip kill) score={:.2}", tgid, comm, score);
        return true;
    }
    last_kill_ns.insert(tgid, ts_ns);

        let killset = collect_identity_killset(risk_key, tgid, 64, 512);

    if !skip_block {
        for p in &killset {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
    } else {
        eprintln!("POLICY skip_block=true reason=trusted_ancestry");
    }

    for p in &killset {
        let _ = kill(Pid::from_raw(*p as i32), Signal::SIGKILL);
    }

    eprintln!("KILLED identity key={} roots<=64 n={} comm={} score={:.2}", risk_key, killset.len(), comm, score);
    false
}

/// Threshold-based enforcement with escalation + subtree containment.
/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_threshold(
    enforce: bool,
    no_enforce: bool,
    skip_kill: bool,
    skip_block: bool,
    risk_key: u64,
    tgid: u32,
    ts_ns: u64,
    comm: &str,
    distinct: usize,
    bytes: u64,
    cooldown_ns: u64,
    last_kill_ns: &mut HashMap<u32, u64>,
    blocked_map: &mut dyn MapCore,
    lsm_ctrl_map: &mut dyn MapCore,
    lsm_mark_blocked: fn(bool, &mut dyn MapCore, &mut dyn MapCore, u32),
    risk_state: &mut HashMap<u64, RiskState>,
) -> bool {
    let cur = risk_state.get(&risk_key).copied().unwrap_or(RiskState::Observe);
    let next = cur.next();
    risk_state.insert(risk_key, next);
    eprintln!("RISK key={} tgid={} {:?}->{:?}", risk_key, tgid, cur, next);

    // Actions are gated by enforce
    if !enforce || no_enforce {
        return false;
    }


        if next == RiskState::Warn {
        // log-only (no action)
        return false;
    }


        if next == RiskState::Contain {
        // log-only (no action)
        return false;
    }


    if next != RiskState::Kill {
        return false;
    }

    if skip_kill {
        eprintln!("POLICY skip_kill=true reason=trusted_ancestry");
        return false;
    }

    let last = last_kill_ns.get(&tgid).copied().unwrap_or(0);
    if ts_ns.saturating_sub(last) < cooldown_ns {
        eprintln!("COOLDOWN: tgid={} comm={} (skip kill) distinct={} bytes={}", tgid, comm, distinct, bytes);
        return true;
    }
    last_kill_ns.insert(tgid, ts_ns);

        let killset = collect_identity_killset(risk_key, tgid, 64, 512);

    if !skip_block {
        for p in &killset {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
    } else {
        eprintln!("POLICY skip_block=true reason=trusted_ancestry");
    }

    for p in &killset {
        let _ = kill(Pid::from_raw(*p as i32), Signal::SIGKILL);
    }

    eprintln!("KILLED(threshold) identity key={} roots<=64 n={} comm={}", risk_key, killset.len(), comm);
    false
}
