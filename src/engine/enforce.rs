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


// ---- kill budgets (userspace) ----
#[derive(Default)]
struct BudgetState {
    window_start_ns: u64,
    global_kills: u32,
    per_id: std::collections::HashMap<u64, u32>,
}

fn budget_reset_if_needed(st: &mut BudgetState, now_ns: u64, window_ns: u64) {
    if st.window_start_ns == 0 || now_ns.saturating_sub(st.window_start_ns) > window_ns {
        st.window_start_ns = now_ns;
        st.global_kills = 0;
        st.per_id.clear();
    }
}

fn budget_can_kill(st: &mut BudgetState, now_ns: u64, window_ns: u64,
                   risk_key: u64, add: u32,
                   global_limit: u32, per_id_limit: u32) -> bool {
    budget_reset_if_needed(st, now_ns, window_ns);
    let cur_id = *st.per_id.get(&risk_key).unwrap_or(&0);
    if st.global_kills.saturating_add(add) > global_limit {
        return false;
    }
    if cur_id.saturating_add(add) > per_id_limit {
        return false;
    }
    true
}

fn budget_apply_kill(st: &mut BudgetState, risk_key: u64, add: u32) {
    st.global_kills = st.global_kills.saturating_add(add);
    let e = st.per_id.entry(risk_key).or_insert(0);
    *e = e.saturating_add(add);
}

static BUDGET_STATE: std::sync::OnceLock<std::sync::Mutex<BudgetState>> = std::sync::OnceLock::new();

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
    allowlisted: bool,
    tgid: u32,
    ts_ns: u64,
    comm: &str,
    score: f64,
    cooldown_ns: u64,
    last_kill_ns: &mut HashMap<u32, u64>,
    blocked_map: &mut dyn MapCore,
    lsm_ctrl_map: &mut dyn MapCore,
    lsm_mark_blocked: fn(bool, &mut dyn MapCore, &mut dyn MapCore, u32),
    killed_out: &mut u32,
    key_cooldown_ns: u64,
    last_kill_key_ns: &mut HashMap<u64, u64>,
    risk_state: &mut HashMap<u64, RiskState>,
) -> bool {
    *killed_out = 0;

    // Escalate risk
    let mut cur = risk_state.get(&risk_key).copied().unwrap_or(RiskState::Observe);
let mut next = cur;
if enforce {
    next = cur.next();
    risk_state.insert(risk_key, next);
}
eprintln!("RISK key={} tgid={} {:?}->{:?}", risk_key, tgid, cur, next);
if allowlisted {
    eprintln!("ALLOWLIST_HIT key={} comm={} -> log-only", risk_key, comm);
    return false;
}

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

    // DEBUG: per-key last kill (always log when we reach Kill stage)
    let last_key = last_kill_key_ns.get(&risk_key).copied().unwrap_or(0);
    if last_key == 0 {
    } else {
        let dt = ts_ns.saturating_sub(last_key);
        if dt < key_cooldown_ns {
            eprintln!("KILL_KEY_COOLDOWN key={} dt_ns={} cooldown_ns={} -> skip kill", risk_key, dt, key_cooldown_ns);
            return false;
        }
    }

    // per-identity kill cooldown (prevents respawn storms)
    if let Some(last) = last_kill_key_ns.get(&risk_key).copied() {
        let dt = ts_ns.saturating_sub(last);
        if dt < key_cooldown_ns {
            eprintln!("KILL_KEY_COOLDOWN key={} dt_ns={} cooldown_ns={} -> skip kill", risk_key, dt, key_cooldown_ns);
            return false;
        }
    }
let max_killset: usize = 256;          // hard cap
    let budget_window_ns: u64 = 60_000_000_000; // 60s
    let global_limit: u32 = 200;               // max kills per minute
    let per_id_limit: u32 = 50;                // max kills per identity per minute

    // If killset is huge, do not SIGKILL storm; block-only and log.
    if killset.len() > max_killset {
        eprintln!("KILLSET_CAP_HIT key={} n={} cap={} -> block-only", risk_key, killset.len(), max_killset);
        // block-only path
        if !skip_block {
            for p in &killset {
                lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
            }
        }
        return false;
    }

    // Budget check
    let mtx = BUDGET_STATE.get_or_init(|| std::sync::Mutex::new(BudgetState::default()));
    let mut st = mtx.lock().unwrap();
    let add = killset.len() as u32;
    if !budget_can_kill(&mut st, ts_ns, budget_window_ns, risk_key, add, global_limit, per_id_limit) {
        eprintln!("BUDGET_HIT key={} add={} global={}/{} per_id={}/{} -> block-only",
                  risk_key, add, st.global_kills, global_limit, *st.per_id.get(&risk_key).unwrap_or(&0), per_id_limit);
        drop(st);
        if !skip_block {
            for p in &killset {
                lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
            }
        }
        return false;
    }
    budget_apply_kill(&mut st, risk_key, add);
    drop(st);

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

    *killed_out = killset.len() as u32;
    last_kill_key_ns.insert(risk_key, ts_ns);
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
    allowlisted: bool,
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
    killed_out: &mut u32,
    key_cooldown_ns: u64,
    last_kill_key_ns: &mut HashMap<u64, u64>,
    risk_state: &mut HashMap<u64, RiskState>,
) -> bool {
    *killed_out = 0;

    let mut cur = risk_state.get(&risk_key).copied().unwrap_or(RiskState::Observe);
let mut next = cur;
if enforce {
    next = cur.next();
    risk_state.insert(risk_key, next);
}
eprintln!("RISK key={} tgid={} {:?}->{:?}", risk_key, tgid, cur, next);
if allowlisted {
    eprintln!("ALLOWLIST_HIT key={} comm={} -> log-only", risk_key, comm);
    return false;
}

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

    // DEBUG: per-key last kill (always log when we reach Kill stage)
    let last_key = last_kill_key_ns.get(&risk_key).copied().unwrap_or(0);
    if last_key == 0 {
    } else {
        let dt = ts_ns.saturating_sub(last_key);
        if dt < key_cooldown_ns {
            eprintln!("KILL_KEY_COOLDOWN key={} dt_ns={} cooldown_ns={} -> skip kill", risk_key, dt, key_cooldown_ns);
            return false;
        }
    }

    // per-identity kill cooldown (prevents respawn storms)
    if let Some(last) = last_kill_key_ns.get(&risk_key).copied() {
        let dt = ts_ns.saturating_sub(last);
        if dt < key_cooldown_ns {
            eprintln!("KILL_KEY_COOLDOWN key={} dt_ns={} cooldown_ns={} -> skip kill", risk_key, dt, key_cooldown_ns);
            return false;
        }
    }
let max_killset: usize = 256;
    let budget_window_ns: u64 = 60_000_000_000;
    let global_limit: u32 = 200;
    let per_id_limit: u32 = 50;

    if killset.len() > max_killset {
        eprintln!("KILLSET_CAP_HIT(threshold) key={} n={} cap={} -> block-only", risk_key, killset.len(), max_killset);
        if !skip_block {
            for p in &killset {
                lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
            }
        }
        return false;
    }

    let mtx = BUDGET_STATE.get_or_init(|| std::sync::Mutex::new(BudgetState::default()));
    let mut st = mtx.lock().unwrap();
    let add = killset.len() as u32;
    if !budget_can_kill(&mut st, ts_ns, budget_window_ns, risk_key, add, global_limit, per_id_limit) {
        eprintln!("BUDGET_HIT(threshold) key={} add={} global={}/{} per_id={}/{} -> block-only",
                  risk_key, add, st.global_kills, global_limit, *st.per_id.get(&risk_key).unwrap_or(&0), per_id_limit);
        drop(st);
        if !skip_block {
            for p in &killset {
                lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
            }
        }
        return false;
    }
    budget_apply_kill(&mut st, risk_key, add);
    drop(st);

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

    *killed_out = killset.len() as u32;
    last_kill_key_ns.insert(risk_key, ts_ns);
    eprintln!("KILLED(threshold) identity key={} roots<=64 n={} comm={}", risk_key, killset.len(), comm);
    false
}
