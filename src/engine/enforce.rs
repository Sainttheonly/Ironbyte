use libbpf_rs::MapCore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;

/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_score(
    enforce: bool,
    no_enforce: bool,
    tgid: u32,
    ts_ns: u64,
    comm: &str,
    score: f64,
    cooldown_ns: u64,
    last_kill_ns: &mut HashMap<u32, u64>,
    blocked_map: &mut dyn MapCore,
    lsm_ctrl_map: &mut dyn MapCore,
    lsm_mark_blocked: fn(bool, &mut dyn MapCore, &mut dyn MapCore, u32),
) -> bool {
    if !enforce {
        return false;
    }

    // Preserve existing behavior: mark TGID blocked in ENFORCE even for no_enforce comms.
    lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, tgid);

    if no_enforce {
        return false;
    }

    let last = last_kill_ns.get(&tgid).copied().unwrap_or(0);
    if ts_ns.saturating_sub(last) < cooldown_ns {
        eprintln!(
            "COOLDOWN: tgid={} comm={} (skip kill) score={:.2}",
            tgid, comm, score
        );
        return true;
    }

    last_kill_ns.insert(tgid, ts_ns);
    let _ = kill(Pid::from_raw(tgid as i32), Signal::SIGKILL);
    eprintln!("KILLED tgid={} comm={} score={:.2}", tgid, comm, score);
    false
}

/// Returns true if cooldown hit and caller should `return 0;`.
pub fn maybe_kill_threshold(
    enforce: bool,
    no_enforce: bool,
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
) -> bool {
    if !enforce || no_enforce {
        return false;
    }

    let last = last_kill_ns.get(&tgid).copied().unwrap_or(0);
    if ts_ns.saturating_sub(last) < cooldown_ns {
        eprintln!(
            "COOLDOWN: tgid={} comm={} (skip kill) distinct={} bytes={}",
            tgid, comm, distinct, bytes
        );
        return true;
    }

    last_kill_ns.insert(tgid, ts_ns);
    lsm_mark_blocked(enforce, blocked_map, lsm_ctrl_map, tgid);
    let _ = kill(Pid::from_raw(tgid as i32), Signal::SIGKILL);
    eprintln!("KILLED tgid={} comm={}", tgid, comm);
    false
}
