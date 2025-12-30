use anyhow::{Context, Result};
use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::{mem, ptr, time::Duration};

mod engine;

const OP_WRITE: u32 = 2;
const OP_CLOSE: u32 = 3;
const OP_OPENAT_RET: u32 = 4;
const OP_RENAMEAT2: u32 = 5;
const OP_UNLINKAT: u32 = 6;
const OP_FTRUNCATE: u32 = 7;
const O_TRUNC: u32 = 0x0200;

const BPF_OBJ_INSTALLED: &str = "/usr/lib/ironbyte-guard/guard.bpf.o";
const BPF_OBJ_DEV: &str = "/home/saint/dev/ironbyte-guard/bpf/guard.bpf.o";
const CFG_PATH: &str = "/etc/ironbyte-guard/config.yaml";

const FNV_OFFSET: u64 = 1469598103934665603;
const FNV_PRIME: u64 = 1099511628211;

fn fnv1a64(s: &str) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in s.as_bytes().iter().take(32) {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[derive(Debug, Deserialize)]
struct Config {
    mode: Option<String>,
    thresholds: Option<Thresholds>,
    cooldown_seconds: Option<u64>,
    ignore_comms: Option<Vec<String>>,
    no_enforce_comms: Option<Vec<String>>,
    exclude_dirs: Option<Vec<String>>,
    ignore_rules: Option<Vec<AllowRule>>,
    scoring: Option<Scoring>,
    dir_window_seconds: Option<u64>,
    dir_min_distinct: Option<usize>,

}

#[derive(Debug, Deserialize)]
struct Thresholds {
    window_seconds: Option<u64>,
    distinct_files: Option<usize>,
    bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
struct AllowRule {
    comm: String,
    exe_prefixes: Vec<String>,
}




#[derive(Debug, Deserialize, Clone)]
struct Scoring {
    trunc_add: Option<f64>,         // added per O_TRUNC write
    mb_add: Option<f64>,            // added per MB written
    decay_per_second: Option<f64>,  // e.g. 0.90 means 10% leak per second
    trigger: Option<f64>,           // score threshold for trip
    min_distinct: Option<usize>,      // minimum distinct files required for score trip
    rename_add: Option<f64>,          // added per rename event
    unlink_add: Option<f64>,          // added per unlink event
    ftruncate_add: Option<f64>,       // added per ftruncate event
}

impl Config {
    fn load() -> Self {
        let s = std::fs::read_to_string(CFG_PATH).unwrap_or_default();
        serde_yaml::from_str(&s).unwrap_or(Config {
            mode: Some("detect_only".into()),
            thresholds: Some(Thresholds {
                window_seconds: Some(1),
                distinct_files: Some(50),
                bytes: Some(5 * 1024 * 1024),
            }),
            dir_window_seconds: Some(10),
            dir_min_distinct: Some(10),
            cooldown_seconds: Some(30),
            scoring: None,
            ignore_comms: Some(vec![
                "apt","apt-get","dpkg","unattended-upgr","rsync","tar","gzip","pigz","zstd",
                "updatedb","locate","cp","mv","ironbyte-guard"
            ].into_iter().map(|s| s.to_string()).collect()),
            exclude_dirs: Some(vec![
                "/var/log/".into(),
                "/var/cache/".into(),
                "/tmp/".into(),
                "/home/saint/.cache/".into(),
            ]),
            ignore_rules: None,
            no_enforce_comms: None,
        })
    }

    fn scoring_enabled(&self) -> bool {
        self.scoring.is_some()
    }

    fn scoring_trunc_add(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.trunc_add).unwrap_or(10.0)
    }

    fn scoring_mb_add(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.mb_add).unwrap_or(5.0)
    }

    fn scoring_decay(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.decay_per_second).unwrap_or(0.90)
    }

    fn scoring_trigger(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.trigger).unwrap_or(100.0)
    }

    fn scoring_min_distinct(&self) -> usize {
        self.scoring.as_ref().and_then(|s| s.min_distinct).unwrap_or(10)
    }

    fn scoring_rename_add(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.rename_add).unwrap_or(5.0)
    }

    fn scoring_unlink_add(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.unlink_add).unwrap_or(8.0)
    }

    fn scoring_ftruncate_add(&self) -> f64 {
        self.scoring.as_ref().and_then(|s| s.ftruncate_add).unwrap_or(12.0)
    }





    fn enforce(&self) -> bool {
        let m = self.mode.as_deref().unwrap_or("detect_only");
        let m = m.trim().to_ascii_lowercase();
        m == "enforce"
    }

    fn window_ns(&self) -> u64 {
        self.thresholds
            .as_ref()
            .and_then(|t| t.window_seconds)
            .unwrap_or(1)
            * 1_000_000_000
    }

    fn distinct_thresh(&self) -> usize {
        self.thresholds
            .as_ref()
            .and_then(|t| t.distinct_files)
            .unwrap_or(50)
    }

    fn bytes_thresh(&self) -> u64 {
        self.thresholds.as_ref().and_then(|t| t.bytes).unwrap_or(5 * 1024 * 1024)
    }

    fn cooldown_ns(&self) -> u64 {
        self.cooldown_seconds.unwrap_or(30) * 1_000_000_000
    }

    fn dir_window_ns(&self) -> u64 {
        self.dir_window_seconds.unwrap_or(10) * 1_000_000_000
    }

    fn dir_min_distinct(&self) -> usize {
        self.dir_min_distinct.unwrap_or(10)
    }


    fn ignore_set(&self) -> HashSet<String> {
        self.ignore_comms.clone().unwrap_or_default().into_iter().collect()
    }

    fn no_enforce_set(&self) -> HashSet<String> {
        self.no_enforce_comms.clone().unwrap_or_default().into_iter().collect()
    }


    fn excluded_dir_hashes(&self) -> HashSet<u64> {
        self.exclude_dirs
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|d| fnv1a64(&d))
            .collect()
    }
}


fn lsm_mark_blocked(enforce: bool, blocked_map: &mut dyn MapCore, lsm_ctrl_map: &mut dyn MapCore, tgid: u32) {
    // LSM_PHASE2: enable enforcement and mark this tgid as blocked
    eprintln!("LSM_MARK_CALLED: tgid={}", tgid);

    if !enforce {
        eprintln!("LSM_SKIP: detect_only (refusing to arm LSM / block TGID)");
        return;
    }


    let key0: u32 = 0;
    let one: u8 = 1;

    // enable enforcement
    match lsm_ctrl_map.update(&key0.to_ne_bytes(), &one.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
        Ok(_) => eprintln!("LSM_UPDATE_OK: lsm_control[0]=1"),
        Err(e) => eprintln!("LSM_UPDATE_ERR: lsm_control update failed: {e}"),
    }

    // mark tgid
    match blocked_map.update(&tgid.to_ne_bytes(), &one.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {
        Ok(_) => eprintln!("LSM_UPDATE_OK: blocked_tgids[{tgid}]=1"),
        Err(e) => eprintln!("LSM_UPDATE_ERR: blocked_tgids update failed (tgid={tgid}): {e}"),
    }
}

fn pick_bpf_obj() -> &'static str {
    if Path::new(BPF_OBJ_INSTALLED).exists() {
        BPF_OBJ_INSTALLED
    } else {
        BPF_OBJ_DEV
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FileEvent {
    ts_ns: u64,
    pid: u32,
    tgid: u32,
    opcode: u32,
    fd: i32,
    bytes: u32,
    flags: u32,
    path_hash: u64,
    dir_hash: u64,
    comm: [u8; 16],
}

#[derive(Default)]
struct WindowState {
    start_ns: u64,
    bytes: u64,
    distinct: HashSet<u64>,
    last_comm: String,
    tripped: bool,
    score: f64,
    last_ts_ns: u64,

}


#[derive(Default)]
struct DirWindow {
    start_ns: u64,
    distinct: std::collections::HashSet<u64>, // path_hash
}


fn comm_str(comm: [u8; 16]) -> String {
    String::from_utf8_lossy(&comm).trim_end_matches('\0').to_string()
}


fn read_exe_path(tgid: u32) -> Option<String> {
    let p = format!("/proc/{}/exe", tgid);
    std::fs::read_link(p).ok().map(|pb| pb.to_string_lossy().to_string())
}

fn comm_has_rule(comm: &str, rules: &Option<Vec<AllowRule>>) -> bool {
    match rules {
        Some(rs) => rs.iter().any(|r| r.comm == comm),
        None => false,
    }
}

fn allowed_by_rules(comm: &str, exe_path: Option<&str>, rules: &Option<Vec<AllowRule>>) -> bool {
    let rules = match rules {
        Some(r) => r,
        None => return false,
    };

    let exe = match exe_path {
        Some(e) => e,
        None => return false,
    };

    for r in rules.iter() {
        if r.comm == comm {
            for pref in r.exe_prefixes.iter() {
                if exe.starts_with(pref) {
                    return true;
                }
            }
            return false; // comm matched but exe didn't
        }
    }
    false
}


#[repr(C)]
#[derive(Clone, Copy)]
struct FileEvent64 {
    ts_ns: u64,
    pid: u32,
    tgid: u32,
    opcode: u32,
    fd: i32,
    bytes: u32,
    flags: u32,
    path_hash: u64,
    dir_hash: u64,
    comm: [u8; 16],
}
const _: [u8; 64] = [0u8; core::mem::size_of::<FileEvent64>()];

fn main() -> Result<()> {
    let cfg = Config::load();
    eprintln!("cfg.mode={:?} env.ENFORCE={:?} cfg_path={}", cfg.mode, std::env::var("ENFORCE").ok(), CFG_PATH);
    let enforce = cfg.enforce();
    let window_ns = cfg.window_ns();
    let distinct_thresh = cfg.distinct_thresh();
    let bytes_thresh = cfg.bytes_thresh();
    let cooldown_ns = cfg.cooldown_ns();
    let dir_window_ns = cfg.dir_window_ns();
    let dir_min_distinct = cfg.dir_min_distinct();
    let ignore_set = cfg.ignore_set();
    let no_enforce_set = cfg.no_enforce_set();
    let excluded_dirs = cfg.excluded_dir_hashes();

    let ignore_rules = cfg.ignore_rules.clone();
    let scoring_enabled = cfg.scoring_enabled();
    let score_trunc_add = cfg.scoring_trunc_add();
    let score_mb_add = cfg.scoring_mb_add();
    let score_decay = cfg.scoring_decay();
    let score_trigger = cfg.scoring_trigger();

    let score_min_distinct = cfg.scoring_min_distinct();
    let score_rename_add = cfg.scoring_rename_add();
    let score_unlink_add = cfg.scoring_unlink_add();
    let score_ftruncate_add = cfg.scoring_ftruncate_add();
    let bpf_obj = pick_bpf_obj();
    eprintln!("loading BPF obj: {}", bpf_obj);
    eprintln!(
        "config: mode={}, window_ns={}, distinct>={}, bytes>={}, cooldown_ns={}",
        if enforce { "ENFORCE" } else { "DETECT_ONLY" },
        window_ns,
        distinct_thresh,
        bytes_thresh,
        cooldown_ns
    );

    // force autoload for LSM before load()
    let mut open_obj = ObjectBuilder::default()
        .open_file(bpf_obj)
        .with_context(|| format!("open BPF object {}", bpf_obj))?;

    // force autoload for LSM program (otherwise it may be skipped)
    if let Some(mut p) = open_obj.progs_mut().find(|p| p.name() == "handle_lsm_file_permission") {
        // force autoload for LSM
        p.set_autoload(true);
    }

    let mut obj = open_obj
        .load()
        .context("load BPF object")?;

    let p_write = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_write")
        .context("missing program handle_sys_enter_write")?;
    let _lk_write = p_write
        .attach_tracepoint("syscalls", "sys_enter_write")
        .context("attach sys_enter_write")?;

    let p_close_enter = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_close")
        .context("missing program handle_sys_enter_close")?;
    let _lk_close_enter = p_close_enter
        .attach_tracepoint("syscalls", "sys_enter_close")
        .context("attach sys_enter_close")?;

    // LSM hook (Phase 1 log-only)
    let p_lsm = obj
        .progs_mut()
        .find(|p| p.name() == "handle_lsm_file_permission")
        .context("missing program handle_lsm_file_permission")?;
    let _lk_lsm = p_lsm
        .attach_lsm()
        .context("attach lsm/file_permission")?;

    let p_open_enter = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_openat")
        .context("missing program handle_sys_enter_openat")?;
    let _lk_open_enter = p_open_enter
        .attach_tracepoint("syscalls", "sys_enter_openat")
        .context("attach sys_enter_openat")?;

    let p_open_exit = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_exit_openat")
        .context("missing program handle_sys_exit_openat")?;
    let _lk_open_exit = p_open_exit
        .attach_tracepoint("syscalls", "sys_exit_openat")
        .context("attach sys_exit_openat")?;

    let p_rename = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_renameat2")
        .context("missing program handle_sys_enter_renameat2")?;
    let _lk_rename = p_rename
        .attach_tracepoint("syscalls", "sys_enter_renameat2")
        .context("attach sys_enter_renameat2")?;

    let p_unlink = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_unlinkat")
        .context("missing program handle_sys_enter_unlinkat")?;
    let _lk_unlink = p_unlink
        .attach_tracepoint("syscalls", "sys_enter_unlinkat")
        .context("attach sys_enter_unlinkat")?;

    let p_ftr = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_ftruncate")
        .context("missing program handle_sys_enter_ftruncate")?;
    let _lk_ftr = p_ftr
        .attach_tracepoint("syscalls", "sys_enter_ftruncate")
        .context("attach sys_enter_ftruncate")?;
    let mut rb = RingBufferBuilder::new();

    // LSM_PHASE2: fetch maps in one borrow to satisfy Rust
    let mut events_map = None;
    let mut blocked_map = None;
    let mut lsm_ctrl_map = None;

    for m in obj.maps_mut() {
        let name = m.name().to_string_lossy();
        if name == "events" {
            events_map = Some(m);
        } else if name == "blocked_tgids" {
            blocked_map = Some(m);
        } else if name == "lsm_control" {
            lsm_ctrl_map = Some(m);
        }
    }

    let events_map = events_map.context("BPF map 'events' not found")?;
    let blocked_map = blocked_map.context("BPF map 'blocked_tgids' not found")?;
    let lsm_ctrl_map = lsm_ctrl_map.context("BPF map 'lsm_control' not found")?;

    // --- SAFETY INVARIANT: detect_only ALWAYS disables enforcement ---

    if !enforce {

        let key0: u32 = 0;

        let zero: u8 = 0;

        match lsm_ctrl_map.update(&key0.to_ne_bytes(), &zero.to_ne_bytes(), libbpf_rs::MapFlags::ANY) {

            Ok(_) => eprintln!("LSM_SAFETY_OK: lsm_control[0]=0 (detect_only)"),

            Err(e) => eprintln!("LSM_SAFETY_ERR: failed to set lsm_control[0]=0: {e}"),

        }

    }
    let self_tgid = std::process::id();

    let mut fd_map: HashMap<(u32, i32), (u32, u64, u64)> = HashMap::new();
    let mut windows: HashMap<u32, WindowState> = HashMap::new();
    let mut last_kill_ns: HashMap<u32, u64> = HashMap::new();

    let mut dir_windows: HashMap<u64, DirWindow> = HashMap::new();

    let mut exe_cache: HashMap<u32, Option<String>> = HashMap::new();
    let mut proc_cache: HashMap<u32, engine::process::ProcInfo> = HashMap::new();

    let mut blocked_map = blocked_map;
    let mut lsm_ctrl_map = lsm_ctrl_map;

    rb.add(&events_map, move |data: &[u8]| {
        if data.len() != mem::size_of::<FileEvent>() {
            return 0;
        }

        let ev: FileEvent = unsafe { ptr::read_unaligned(data.as_ptr() as *const FileEvent) };
        if ev.tgid == self_tgid {
            return 0;
        }        let comm = comm_str(ev.comm);


        let no_enforce = no_enforce_set.contains(&comm);
        // Always process close events (even for allowlisted comm) so fd_map doesn't leak
        if ev.opcode == OP_CLOSE {
            fd_map.remove(&(ev.tgid, ev.fd));
            return 0;
        }

        // Anti-mimic: cache /proc/<tgid>/exe once per tgid and enforce exe-prefix rules when present
        let exe_entry = exe_cache.entry(ev.tgid).or_insert_with(|| read_exe_path(ev.tgid));
        let exe_path = exe_entry.as_deref();

        if comm_has_rule(&comm, &ignore_rules) {
            if allowed_by_rules(&comm, exe_path, &ignore_rules) {
                return 0;
            }
            // comm has a rule but exe didn't match -> NOT allowlisted
        } else if ignore_set.contains(&comm) {
            // no rule for this comm -> fall back to legacy allowlist behavior
            return 0;
        }

        match ev.opcode {
            OP_OPENAT_RET => {
                fd_map.insert((ev.tgid, ev.fd), (ev.flags, ev.path_hash, ev.dir_hash));
            }            OP_RENAMEAT2 => {
                // Rename telemetry: treat as high-signal file activity (temp->final patterns)
                let ph = ev.path_hash;
                let dh = ev.dir_hash;
                if ph == 0 {
                    return 0;
                }
                if dh != 0 && excluded_dirs.contains(&dh) {
                // DIR_WINDOW_UPDATE: track per-directory fan-out
                if dh != 0 && ph != 0 {
                    let dw = dir_windows.entry(dh).or_default();
                    if dw.start_ns == 0 || ev.ts_ns.saturating_sub(dw.start_ns) > dir_window_ns {
                        dw.start_ns = ev.ts_ns;
                        dw.distinct.clear();
                    }
                    dw.distinct.insert(ph);
                }

                    return 0;
                }

                let w = windows.entry(ev.tgid).or_default();

                // Reset window bookkeeping for distinct/bytes, but scoring uses decay over time
                if w.start_ns == 0 || ev.ts_ns.saturating_sub(w.start_ns) > window_ns {
                    w.start_ns = ev.ts_ns;
                    w.bytes = 0;
                    w.distinct.clear();
                    w.tripped = false;

                    if scoring_enabled {
                        w.score = 0.0;
                        w.last_ts_ns = ev.ts_ns;
                    }
                }

                w.last_comm = comm.clone();
                w.distinct.insert(ph);

                if scoring_enabled {
                    let dt_ns = ev.ts_ns.saturating_sub(w.last_ts_ns);
                    let dt_s = (dt_ns as f64) / 1_000_000_000.0;
                    if dt_s > 0.0 {
                        w.score *= score_decay.powf(dt_s);
                        w.last_ts_ns = ev.ts_ns;
                    }

                    w.score += score_rename_add;

                    if !w.tripped && w.score >= score_trigger && w.distinct.len() >= score_min_distinct {
                        // DIR_GATE_ALL: require per-directory fanout within window
                        let dir_n = if dh != 0 {
                            dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0)
                        } else { 0 };
                        if dir_n < dir_min_distinct {
                            return 0;
                        }

                        // DIR_GATE: require per-directory fanout too
                        let dir_ok = if dh != 0 {
                            dir_windows.get(&dh).map(|dw| dw.distinct.len() >= dir_min_distinct).unwrap_or(false)
                        } else {
                            false
                        };
                        if !dir_ok { return 0; }

                        w.tripped = true;
                        // LSM_PHASE2: mark TGID blocked when trip happens in ENFORCE mode
                        if enforce {
                            lsm_mark_blocked(enforce, &mut blocked_map, &mut lsm_ctrl_map, ev.tgid);
                        }

                        engine::trip::log_trip_score_dir(&engine::types::TripContext {
    tgid: ev.tgid,
    comm: &w.last_comm,
    score: w.score,
    distinct: w.distinct.len() as u32,
    bytes: w.bytes,
    enforce,
}, dh, dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0));
// ancestry + context (LOG ONLY)
let chain = engine::process::ancestry(&mut proc_cache, ev.tgid, 8);
eprintln!("ANCESTRY {}", engine::process::fmt_ancestry(&chain));
let ctx = engine::context::classify(&chain);
eprintln!("CONTEXT trusted={} class={} reason={}", ctx.trusted, ctx.class, ctx.reason);


                        eprintln!("DIRDBG2 tgid={} dh={} dir_n={}", ev.tgid, dh, dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0));
                        if engine::enforce::maybe_kill_score(
                            enforce,
                            no_enforce,
                            ev.tgid,
                            ev.ts_ns,
                            &w.last_comm,
                            w.score,
                            cooldown_ns,
                            &mut last_kill_ns,
                            &mut blocked_map,
                            &mut lsm_ctrl_map,
                            lsm_mark_blocked,
                        ) {
                            return 0;
                        }
                    }
                }
            }            OP_UNLINKAT => {
                let ph = ev.path_hash;
                let dh = ev.dir_hash;
                // DIR_WINDOW_UPDATE: track per-directory fan-out
                if dh != 0 && ph != 0 {
                    let dw = dir_windows.entry(dh).or_default();
                    if dw.start_ns == 0 || ev.ts_ns.saturating_sub(dw.start_ns) > dir_window_ns {
                        dw.start_ns = ev.ts_ns;
                        dw.distinct.clear();
                    }
                    dw.distinct.insert(ph);
                }

                if ph == 0 {
                    return 0;
                }
                if dh != 0 && excluded_dirs.contains(&dh) {
                    return 0;
                }


                // DIR_WINDOW_UPDATE: track per-directory fan-out (correct placement)
                if dh != 0 && ph != 0 {
                    let dw = dir_windows.entry(dh).or_default();
                    if dw.start_ns == 0 || ev.ts_ns.saturating_sub(dw.start_ns) > dir_window_ns {
                        dw.start_ns = ev.ts_ns;
                        dw.distinct.clear();
                    }
                    dw.distinct.insert(ph);

                    // DIRUPDBG: light debug at milestones
                    if dw.distinct.len() == 1 || dw.distinct.len() == 5 || dw.distinct.len() == 10 {
                        eprintln!("DIRUPDBG tgid={} dh={} dir_n={}", ev.tgid, dh, dw.distinct.len());
                    }
                }

                let w = windows.entry(ev.tgid).or_default();
                if w.start_ns == 0 || ev.ts_ns.saturating_sub(w.start_ns) > window_ns {
                    w.start_ns = ev.ts_ns;
                    w.bytes = 0;
                    w.distinct.clear();
                    w.tripped = false;

                    if scoring_enabled {
                        w.score = 0.0;
                        w.last_ts_ns = ev.ts_ns;
                    }
                }

                w.last_comm = comm.clone();
                w.distinct.insert(ph);

                if scoring_enabled {
                    let dt_ns = ev.ts_ns.saturating_sub(w.last_ts_ns);
                    let dt_s = (dt_ns as f64) / 1_000_000_000.0;
                    if dt_s > 0.0 {
                        w.score *= score_decay.powf(dt_s);
                        w.last_ts_ns = ev.ts_ns;
                    }

                    w.score += score_unlink_add;

                    if !w.tripped && w.score >= score_trigger && w.distinct.len() >= score_min_distinct {
                        // DIR_GATE_ALL: require per-directory fanout within window
                        let dir_n = if dh != 0 {
                            dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0)
                        } else { 0 };
                        if dir_n < dir_min_distinct {
                            return 0;
                        }

                        w.tripped = true;
engine::trip::log_trip(&engine::types::TripContext {
    tgid: ev.tgid,
    comm: &comm,
    score: w.score,
    distinct: w.distinct.len() as u32,
    bytes: w.bytes,
    enforce,
});
// ancestry + context (LOG ONLY)
let chain = engine::process::ancestry(&mut proc_cache, ev.tgid, 8);
eprintln!("ANCESTRY {}", engine::process::fmt_ancestry(&chain));
let ctx = engine::context::classify(&chain);
eprintln!("CONTEXT trusted={} class={} reason={}", ctx.trusted, ctx.class, ctx.reason);


                        if engine::enforce::maybe_kill_score(
                            enforce,
                            no_enforce,
                            ev.tgid,
                            ev.ts_ns,
                            &w.last_comm,
                            w.score,
                            cooldown_ns,
                            &mut last_kill_ns,
                            &mut blocked_map,
                            &mut lsm_ctrl_map,
                            lsm_mark_blocked,
                        ) {
                            return 0;
                        }
                    }
                }
            }            OP_FTRUNCATE => {
                // ftruncate telemetry: treat like destructive write signal (trunc without O_TRUNC)
                let ph = ev.path_hash;
                let dh = ev.dir_hash;
                // DIR_WINDOW_UPDATE: track per-directory fan-out
                if dh != 0 && ph != 0 {
                    let dw = dir_windows.entry(dh).or_default();
                    if dw.start_ns == 0 || ev.ts_ns.saturating_sub(dw.start_ns) > dir_window_ns {
                        dw.start_ns = ev.ts_ns;
                        dw.distinct.clear();
                    }
                    dw.distinct.insert(ph);
                }

                if ph == 0 {
                    return 0;
                }
                if dh != 0 && excluded_dirs.contains(&dh) {
                    return 0;
                }

                let w = windows.entry(ev.tgid).or_default();
                if w.start_ns == 0 || ev.ts_ns.saturating_sub(w.start_ns) > window_ns {
                    w.start_ns = ev.ts_ns;
                    w.bytes = 0;
                    w.distinct.clear();
                    w.tripped = false;

                    if scoring_enabled {
                        w.score = 0.0;
                        w.last_ts_ns = ev.ts_ns;
                    }
                }

                w.last_comm = comm.clone();
                w.distinct.insert(ph);

                if scoring_enabled {
                    let dt_ns = ev.ts_ns.saturating_sub(w.last_ts_ns);
                    let dt_s = (dt_ns as f64) / 1_000_000_000.0;
                    if dt_s > 0.0 {
                        w.score *= score_decay.powf(dt_s);
                        w.last_ts_ns = ev.ts_ns;
                    }

                    w.score += score_ftruncate_add;

                    if !w.tripped && w.score >= score_trigger && w.distinct.len() >= score_min_distinct {
                        // DIR_GATE_ALL: require per-directory fanout within window
                        let dir_n = if dh != 0 {
                            dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0)
                        } else { 0 };
                        if dir_n < dir_min_distinct {
                            return 0;
                        }

                        w.tripped = true;
                        engine::trip::log_trip(&engine::types::TripContext {
    tgid: ev.tgid,
    comm: &w.last_comm,
    score: w.score,
    distinct: w.distinct.len() as u32,
    bytes: w.bytes,
    enforce,
});
// ancestry + context (LOG ONLY)
let chain = engine::process::ancestry(&mut proc_cache, ev.tgid, 8);
eprintln!("ANCESTRY {}", engine::process::fmt_ancestry(&chain));
let ctx = engine::context::classify(&chain);
eprintln!("CONTEXT trusted={} class={} reason={}", ctx.trusted, ctx.class, ctx.reason);


                        if engine::enforce::maybe_kill_score(
                            enforce,
                            no_enforce,
                            ev.tgid,
                            ev.ts_ns,
                            &w.last_comm,
                            w.score,
                            cooldown_ns,
                            &mut last_kill_ns,
                            &mut blocked_map,
                            &mut lsm_ctrl_map,
                            lsm_mark_blocked,
                        ) {
                            return 0;
                        }
                    }
                }
            }






            OP_WRITE => {
                let (flags, ph, dh) = fd_map
                    .get(&(ev.tgid, ev.fd))
                    .copied()
                    .unwrap_or((ev.flags, ev.path_hash, ev.dir_hash));

                if (flags & O_TRUNC) == 0 || ph == 0 {
                    return 0;
                }

                if dh != 0 && excluded_dirs.contains(&dh) {
                    return 0;
                }


                // DIR_WINDOW_UPDATE: per-directory fan-out (OP_WRITE)
                if dh != 0 && ph != 0 {
                    let dw = dir_windows.entry(dh).or_default();
                    if dw.start_ns == 0 || ev.ts_ns.saturating_sub(dw.start_ns) > dir_window_ns {
                        dw.start_ns = ev.ts_ns;
                        dw.distinct.clear();
                    }
                    dw.distinct.insert(ph);
                }

                let w = windows.entry(ev.tgid).or_default();

                if w.start_ns == 0 || ev.ts_ns.saturating_sub(w.start_ns) > window_ns {
                    w.start_ns = ev.ts_ns;
                    w.bytes = 0;
                    w.distinct.clear();
                    w.tripped = false;
                

                    if scoring_enabled {
                        w.score = 0.0;
                        w.last_ts_ns = ev.ts_ns;
                    }
                }

                w.last_comm = comm.clone();
                w.bytes += ev.bytes as u64;
                w.distinct.insert(ph);
                if scoring_enabled {
                    // time-based decay: score *= decay_per_second^(dt_seconds)
                    let dt_ns = ev.ts_ns.saturating_sub(w.last_ts_ns);
                    let dt_s = (dt_ns as f64) / 1_000_000_000.0;
                    if dt_s > 0.0 {
                        w.score *= score_decay.powf(dt_s);
                        w.last_ts_ns = ev.ts_ns;
                    }

                    // Add contributions
                    if (flags & O_TRUNC) != 0 {
                        w.score += score_trunc_add;
                    }
                    w.score += (ev.bytes as f64 / (1024.0 * 1024.0)) * score_mb_add;

                    if !w.tripped && w.score >= score_trigger && w.distinct.len() >= score_min_distinct {
                        // DIR_GATE_ALL: require per-directory fanout within window
                        let dir_n = if dh != 0 {
                            dir_windows.get(&dh).map(|dw| dw.distinct.len()).unwrap_or(0)
                        } else { 0 };
                        if dir_n < dir_min_distinct {
                            return 0;
                        }

                        w.tripped = true;

                        engine::trip::log_trip(&engine::types::TripContext {
                            tgid: ev.tgid,
                            comm: &w.last_comm,
                            score: w.score,
                            distinct: w.distinct.len() as u32,
                            bytes: w.bytes,
                            enforce,
                        });
                        // ancestry + context (LOG ONLY)
let chain = engine::process::ancestry(&mut proc_cache, ev.tgid, 8);
eprintln!("ANCESTRY {}", engine::process::fmt_ancestry(&chain));
let ctx = engine::context::classify(&chain);
eprintln!("CONTEXT trusted={} class={} reason={}", ctx.trusted, ctx.class, ctx.reason);

                        if engine::enforce::maybe_kill_score(
                            enforce,
                            no_enforce,
                            ev.tgid,
                            ev.ts_ns,
                            &w.last_comm,
                            w.score,
                            cooldown_ns,
                            &mut last_kill_ns,
                            &mut blocked_map,
                            &mut lsm_ctrl_map,
                            lsm_mark_blocked,
                        ) {
                            return 0;
                        }
                    }
                }


                if !w.tripped && w.distinct.len() >= distinct_thresh && w.bytes >= bytes_thresh {
                    w.tripped = true;

engine::trip::log_trip_threshold(ev.tgid, &w.last_comm, w.distinct.len(), w.bytes, enforce);
// ancestry + context (LOG ONLY)
let chain = engine::process::ancestry(&mut proc_cache, ev.tgid, 8);
eprintln!("ANCESTRY {}", engine::process::fmt_ancestry(&chain));
let ctx = engine::context::classify(&chain);
eprintln!("CONTEXT trusted={} class={} reason={}", ctx.trusted, ctx.class, ctx.reason);



                    // cooldown+kill (enforce only)
                    if engine::enforce::maybe_kill_threshold(
                        enforce,
                        no_enforce,
                        ev.tgid,
                        ev.ts_ns,
                        &w.last_comm,
                        w.distinct.len(),
                        w.bytes,
                        cooldown_ns,
                        &mut last_kill_ns,
                        &mut blocked_map,
                        &mut lsm_ctrl_map,
                        lsm_mark_blocked,
                    ) {
                        return 0;
                    }
                }
            }
            _ => {}
        }

        0
    })?;

    let ringbuf = rb.build().context("build ringbuf")?;

    eprintln!(
        "ironbyte-guard: mode={} (CONFIG ON) (ALLOWLIST ON) (DIR EXCLUDES ON) (COOLDOWN ON)",
        if enforce { "ENFORCE" } else { "DETECT_ONLY" }
    );

    loop {
        match ringbuf.poll(Duration::from_millis(200)) {
            Ok(()) => {}
            Err(e) => {
                // libbpf-rs returns its own Error type. EINTR shows up as:
                // "Interrupted system call (os error 4)"
                let msg = e.to_string();
                if msg.contains("Interrupted system call") || msg.contains("os error 4") {
                    continue;
                }
                return Err(e.into());
            }
        }
    }
}

// LSM_MARK_ALL_TRIPSCORE

// DIR_GATE_ALL
