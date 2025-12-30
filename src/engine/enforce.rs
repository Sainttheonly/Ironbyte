use libbpf_rs::MapCore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;

use crate::engine::risk::RiskState;

// /proc subtree helpers
fn read_children(tgid: u32) -> Vec<u32> {
    let path = format!("/proc/{0}/task/{0}/children", tgid);
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.split_whitespace()
        .filter_map(|x| x.parse::<u32>().ok())
        .collect()
}

fn collect_subtree(root: u32, max_nodes: usize) -> Vec<u32> {
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
        for c in read_children(pid) {
            if out.len() >= max_nodes {
                break;
            }
            stack.push(c);
        }
    }
    out
}

/// Score-based enforcement with escalation + subtree containment.
/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_score(
    enforce: bool,
    no_enforce: bool,
    skip_kill: bool,
    skip_block: bool,
    tgid: u32,
    ts_ns: u64,
    comm: &str,
    score: f64,
    cooldown_ns: u64,
    last_kill_ns: &mut HashMap<u32, u64>,
    blocked_map: &mut dyn MapCore,
    lsm_ctrl_map: &mut dyn MapCore,
    lsm_mark_blocked: fn(bool, &mut dyn MapCore, &mut dyn MapCore, u32),
    risk_state: &mut HashMap<u32, RiskState>,
) -> bool {
    if !enforce {
        return false;
    }

    // Escalate risk
    let cur = risk_state.get(&tgid).copied().unwrap_or(RiskState::Observe);
    let next = cur.next();
    risk_state.insert(tgid, next);
    eprintln!("RISK tgid={} {:?}->{:?}", tgid, cur, next);

    // OBSERVE: log-only
    if next == RiskState::Observe {
        return false;
    }

    // WARN: block root only (if allowed)
    if next == RiskState::Warn {
        if skip_block {
            eprintln!("POLICY skip_block=true reason=trusted_ancestry");
            return false;
        }
        lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, tgid);
        return false;
    }

    // CONTAIN: block subtree (no kill)
    if next == RiskState::Contain {
        if skip_block {
            eprintln!("POLICY skip_block=true reason=trusted_ancestry");
            return false;
        }
        let subtree = collect_subtree(tgid, 256);
        for p in &subtree {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
        eprintln!("CONTAIN subtree root={} n={}", tgid, subtree.len());
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

    let subtree = collect_subtree(tgid, 256);

    if !skip_block {
        for p in &subtree {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
    } else {
        eprintln!("POLICY skip_block=true reason=trusted_ancestry");
    }

    for p in &subtree {
        let _ = kill(Pid::from_raw(*p as i32), Signal::SIGKILL);
    }

    eprintln!("KILLED subtree root={} n={} comm={} score={:.2}", tgid, subtree.len(), comm, score);
    false
}

/// Threshold-based enforcement with escalation + subtree containment.
/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_threshold(
    enforce: bool,
    no_enforce: bool,
    skip_kill: bool,
    skip_block: bool,
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
    risk_state: &mut HashMap<u32, RiskState>,
) -> bool {
    if !enforce || no_enforce {
        return false;
    }

    let cur = risk_state.get(&tgid).copied().unwrap_or(RiskState::Observe);
    let next = cur.next();
    risk_state.insert(tgid, next);
    eprintln!("RISK tgid={} {:?}->{:?}", tgid, cur, next);

    if next == RiskState::Warn {
        if skip_block {
            eprintln!("POLICY skip_block=true reason=trusted_ancestry");
            return false;
        }
        lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, tgid);
        return false;
    }

    if next == RiskState::Contain {
        if skip_block {
            eprintln!("POLICY skip_block=true reason=trusted_ancestry");
            return false;
        }
        let subtree = collect_subtree(tgid, 256);
        for p in &subtree {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
        eprintln!("CONTAIN(threshold) subtree root={} n={}", tgid, subtree.len());
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

    let subtree = collect_subtree(tgid, 256);

    if !skip_block {
        for p in &subtree {
            lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, *p);
        }
    } else {
        eprintln!("POLICY skip_block=true reason=trusted_ancestry");
    }

    for p in &subtree {
        let _ = kill(Pid::from_raw(*p as i32), Signal::SIGKILL);
    }

    eprintln!("KILLED(threshold) subtree root={} n={} comm={}", tgid, subtree.len(), comm);
    false
}
