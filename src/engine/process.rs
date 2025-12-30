use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub tgid: u32,
    pub ppid: Option<u32>,
    pub comm: Option<String>,
    pub exe: Option<String>,
}

fn read_ppid(tgid: u32) -> Option<u32> {
    // /proc/<pid>/stat: 4th field is ppid, but comm is inside parentheses and may contain spaces.
    let stat = fs::read_to_string(format!("/proc/{}/stat", tgid)).ok()?;
    let rparen = stat.rfind(')')?;
    let after = &stat[rparen+1..];
    // after: " state ppid ..."
    let mut it = after.split_whitespace();
    let _state = it.next()?;
    let ppid_s = it.next()?;
    ppid_s.parse::<u32>().ok()
}

fn read_comm(tgid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", tgid)).ok().map(|s| s.trim().to_string())
}

fn read_exe(tgid: u32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", tgid)).ok().map(|p| p.to_string_lossy().to_string())
}

pub fn get_proc(cache: &mut HashMap<u32, ProcInfo>, tgid: u32) -> ProcInfo {
    if let Some(p) = cache.get(&tgid) {
        return p.clone();
    }
    let info = ProcInfo{
        tgid,
        ppid: read_ppid(tgid),
        comm: read_comm(tgid),
        exe: read_exe(tgid),
    };
    cache.insert(tgid, info.clone());
    info
}

pub fn ancestry(cache: &mut HashMap<u32, ProcInfo>, tgid: u32, max_depth: usize) -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let mut cur = tgid;
    for _ in 0..max_depth {
        let p = get_proc(cache, cur);
        out.push(p.clone());
        match p.ppid {
            Some(pp) if pp > 1 && pp != cur => cur = pp,
            _ => break,
        }
    }
    out
}

pub fn log_ancestry(cache: &mut HashMap<u32, ProcInfo>, tgid: u32) {
    let chain = ancestry(cache, tgid, 8);
    // Format: tgid(comm exe) <- ppid(comm exe) <- ...
    let mut parts = Vec::new();
    for p in chain {
        let comm = p.comm.unwrap_or_else(|| "?".into());
        let exe  = p.exe.unwrap_or_else(|| "?".into());
        parts.push(format!("{}({} {})", p.tgid, comm, exe));
    }
    eprintln!("ANCESTRY {}", parts.join(" <- "));
}
