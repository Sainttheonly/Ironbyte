use crate::engine::process::ProcInfo;

#[derive(Debug, Clone)]
pub struct ContextClass {
    pub trusted: bool,
    pub class: &'static str,
    pub reason: String,
}

fn has_any(chain: &[ProcInfo], needles: &[&str]) -> Vec<String> {
    let mut hit: Vec<String> = Vec::new();
    for p in chain {
        let comm = p.comm.as_deref().unwrap_or("");
        let exe  = p.exe.as_deref().unwrap_or("");
        for &n in needles {
            if comm == n || exe.ends_with(n) {
                let nn = n.to_string();
                if !hit.iter().any(|x| x == &nn) {
                    hit.push(nn);
                }
            }
        }
    }
    hit
}


/// LOG-ONLY classification based on ancestry.
/// No enforcement decisions here. Just a structured hint.
pub fn classify(chain: &[ProcInfo]) -> ContextClass {
    // Signals
    let dev_toolchain = [
        "cargo", "rustc", "clang", "gcc", "cc", "ld", "make", "cmake", "ninja",
        "go", "javac", "gradle", "mvn",
        "node", "npm", "pnpm", "yarn",
    ];
    let pkg_mgr = ["apt", "apt-get", "dpkg", "dnf", "yum", "pacman", "zypper", "snap", "flatpak"];
    let remote = ["sshd", "ssh", "tailscaled"];
    let sched  = ["systemd", "cron", "crond"];

    let dev_hits = has_any(chain, &dev_toolchain);
    if !dev_hits.is_empty() {
        return ContextClass {
            trusted: true,
            class: "dev_build",
            reason: format!("toolchain_in_ancestry({})", dev_hits.join(",")),
        };
    }

    let pkg_hits = has_any(chain, &pkg_mgr);
    if !pkg_hits.is_empty() {
        return ContextClass {
            trusted: true,
            class: "package_manager",
            reason: format!("pkgmgr_in_ancestry({})", pkg_hits.join(",")),
        };
    }

    let remote_hits = has_any(chain, &remote);
    if !remote_hits.is_empty() {
        return ContextClass {
            trusted: false,
            class: "remote_shell",
            reason: format!("remote_in_ancestry({})", remote_hits.join(",")),
        };
    }

    let sched_hits = has_any(chain, &sched);
    if !sched_hits.is_empty() {
        return ContextClass {
            trusted: false,
            class: "scheduled_or_service",
            reason: format!("service_in_ancestry({})", sched_hits.join(",")),
        };
    }

    // Default
    ContextClass {
        trusted: false,
        class: "unknown",
        reason: "no_known_signals".to_string(),
    }
}
