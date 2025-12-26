use anyhow::{Context, Result};
use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::{mem, ptr, time::Duration};

const OP_WRITE: u32 = 2;
const OP_OPENAT_RET: u32 = 4;
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
    allowlist: Option<Vec<String>>,
    exclude_dirs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    window_seconds: Option<u64>,
    distinct_files: Option<usize>,
    bytes: Option<u64>,
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
            cooldown_seconds: Some(30),
            allowlist: Some(vec![
                "apt","apt-get","dpkg","unattended-upgr","rsync","tar","gzip","pigz","zstd",
                "updatedb","locate","cp","mv","ironbyte-guard"
            ].into_iter().map(|s| s.to_string()).collect()),
            exclude_dirs: Some(vec![
                "/var/log/".into(),
                "/var/cache/".into(),
                "/tmp/".into(),
                "/home/saint/.cache/".into(),
            ]),
        })
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

    fn allowlist_set(&self) -> HashSet<String> {
        self.allowlist.clone().unwrap_or_default().into_iter().collect()
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
}

fn comm_str(comm: [u8; 16]) -> String {
    String::from_utf8_lossy(&comm).trim_end_matches('\0').to_string()
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
    let allowlist = cfg.allowlist_set();
    let excluded_dirs = cfg.excluded_dir_hashes();

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

    let mut obj = ObjectBuilder::default()
        .open_file(bpf_obj)
        .with_context(|| format!("open BPF object {}", bpf_obj))?
        .load()
        .context("load BPF object")?;

    let p_write = obj
        .progs_mut()
        .find(|p| p.name() == "handle_sys_enter_write")
        .context("missing program handle_sys_enter_write")?;
    let _lk_write = p_write
        .attach_tracepoint("syscalls", "sys_enter_write")
        .context("attach sys_enter_write")?;

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

    let mut rb = RingBufferBuilder::new();
    let events_map = obj
        .maps_mut()
        .find(|m| m.name() == "events")
        .context("BPF map 'events' not found")?;

    let self_tgid = std::process::id();

    let mut fd_map: HashMap<(u32, i32), (u32, u64, u64)> = HashMap::new();
    let mut windows: HashMap<u32, WindowState> = HashMap::new();
    let mut last_kill_ns: HashMap<u32, u64> = HashMap::new();

    rb.add(&events_map, move |data: &[u8]| {
        if data.len() != mem::size_of::<FileEvent>() {
            return 0;
        }

        let ev: FileEvent = unsafe { ptr::read_unaligned(data.as_ptr() as *const FileEvent) };
        if ev.tgid == self_tgid {
            return 0;
        }

        let comm = comm_str(ev.comm);
        if allowlist.contains(&comm) {
            return 0;
        }

        match ev.opcode {
            OP_OPENAT_RET => {
                fd_map.insert((ev.tgid, ev.fd), (ev.flags, ev.path_hash, ev.dir_hash));
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

                let w = windows.entry(ev.tgid).or_default();

                if w.start_ns == 0 || ev.ts_ns.saturating_sub(w.start_ns) > window_ns {
                    w.start_ns = ev.ts_ns;
                    w.bytes = 0;
                    w.distinct.clear();
                    w.tripped = false;
                }

                w.last_comm = comm.clone();
                w.bytes += ev.bytes as u64;
                w.distinct.insert(ph);

                if !w.tripped && w.distinct.len() >= distinct_thresh && w.bytes >= bytes_thresh {
                    w.tripped = true;

                    // cooldown check (enforce only)
                    if enforce {
                        let last = last_kill_ns.get(&ev.tgid).copied().unwrap_or(0);
                        if ev.ts_ns.saturating_sub(last) < cooldown_ns {
                            eprintln!(
                                "COOLDOWN: tgid={} comm={} (skip kill) distinct={} bytes={}",
                                ev.tgid, w.last_comm, w.distinct.len(), w.bytes
                            );
                            return 0;
                        }
                    }

                    eprintln!("TRIP tgid={} comm={} distinct={} bytes={} enforce={}",
                        ev.tgid, w.last_comm, w.distinct.len(), w.bytes, enforce
                    );


                    if enforce {
                        last_kill_ns.insert(ev.tgid, ev.ts_ns);
                        let _ = kill(Pid::from_raw(ev.tgid as i32), Signal::SIGKILL);
                        eprintln!("KILLED tgid={} comm={}", ev.tgid, w.last_comm);
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
        ringbuf.poll(Duration::from_millis(200))?;
    }
}
