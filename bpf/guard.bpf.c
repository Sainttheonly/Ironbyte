#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Opcodes — must match userspace */
#define MAY_WRITE 0x00000002
#define OP_WRITE        2
#define OP_LSM_FILE_PERM  8
#define OP_CLOSE        3
#define OP_OPENAT_RET   4

#define OP_RENAMEAT2    5
#define OP_UNLINKAT      6
#define OP_FTRUNCATE     7
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME  1099511628211ULL

static __always_inline __u64 fnv1a_step(__u64 h, __u8 c) {
    h ^= c;
    h *= FNV_PRIME;
    return h;
}

/* Hash up to max bytes (stop at NUL). Safe bounded loop. */
static __always_inline __u64 fnv1a64_cstr(const char *s, int max)
{
    __u64 h = FNV_OFFSET;

    #pragma unroll
    for (int i = 0; i < 64; i++) {

        char c = 0;
        /* s points to kernel stack buffer, so regular read is fine */
        c = s[i];
        if (c == 0) break;
        h = fnv1a_step(h, (unsigned char)c);
    }

    return h;
}

/* Hash directory prefix: everything up to last '/' (inclusive), within max. */
static __always_inline __u64 fnv1a64_dirprefix(const char *s, int max)
{
    (void)max;
    __u64 h = FNV_OFFSET;
    __u64 last = 0;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (c == 0) break;
        h = fnv1a_step(h, (unsigned char)c);
        if (c == '/') {
            last = h; /* hash up to and including slash */
        }
    }

    return last; /* 0 if no slash */
}

/* ===== Event ===== */
struct file_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 opcode;
    __s32 fd;
    __u32 bytes;
    __u32 flags;
    __u64 path_hash;
    __u64 dir_hash;
    char  comm[16];
};

/* ===== Maps ===== */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct open_args {
    __u32 flags;
    __u64 path_hash;
    __u64 dir_hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct open_args);
} open_args_map SEC(".maps");

struct fd_key {
    __u32 tgid;
    __s32 fd;
};

struct open_info {
    __u32 flags;
    __u64 path_hash;
    __u64 dir_hash;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fd_key);
    __type(value, struct open_info);
} fd_info_map SEC(".maps");



// ---- LSM control maps ----
// blocked_tgids: userspace marks TGIDs that should be blocked (Phase 2). Phase 1 only logs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} blocked_tgids SEC(".maps");

// lsm_control[0] = 0 -> log-only, 1 -> enforce (-EPERM) (Phase 2)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} lsm_control SEC(".maps");

/* ===== Helper ===== */
static __always_inline void emit_event(
    __u32 opcode, __u32 tgid, __u32 pid,
    int fd, __u32 bytes,
    __u32 flags, __u64 ph, __u64 dh
) {
    struct file_event *e =
        bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tgid = tgid;
    e->opcode = opcode;
    e->fd = fd;
    e->bytes = bytes;
    e->flags = flags;
    e->path_hash = ph;
    e->dir_hash = dh;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

/* ===== Tracepoints ===== */

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    __u32 flags = (__u32)ctx->args[2];

    const char *user_path = (const char *)ctx->args[1];

    char path[128] = {};
    long n = 0;
    if (user_path) {
        n = bpf_probe_read_user_str(path, sizeof(path), user_path);
    }



    /* If read fails, n <= 0; hashes remain 0 */
    __u64 ph = 0;
    __u64 dh = 0;
    if (n > 0) {
        ph = fnv1a64_cstr(path, (int)sizeof(path));
        dh = fnv1a64_dirprefix(path, (int)sizeof(path));
    }

    struct open_args oa = {
        .flags = flags,
        .path_hash = ph,
        .dir_hash = dh,
    };

    bpf_map_update_elem(&open_args_map, &pid, &oa, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;
    int fd = (int)ctx->ret;

    if (fd < 0) {
        bpf_map_delete_elem(&open_args_map, &pid);
        return 0;
    }

    struct open_args *oa =
        bpf_map_lookup_elem(&open_args_map, &pid);
    if (!oa) return 0;

    struct fd_key k = { .tgid = tgid, .fd = fd };
    struct open_info oi = {
        .flags = oa->flags,
        .path_hash = oa->path_hash,
        .dir_hash = oa->dir_hash,
    };

    bpf_map_update_elem(&fd_info_map, &k, &oi, BPF_ANY);

    /* emit open return with real hashes */
    emit_event(OP_OPENAT_RET, tgid, pid, fd, 0, oi.flags, oi.path_hash, oi.dir_hash);

    bpf_map_delete_elem(&open_args_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;
    int fd = (int)ctx->args[0];
    __u32 bytes = (__u32)ctx->args[2];

    __u32 flags = 0;
    __u64 ph = 0, dh = 0;

    struct fd_key k = { .tgid = tgid, .fd = fd };
    struct open_info *oi = bpf_map_lookup_elem(&fd_info_map, &k);
    if (oi) {
        flags = oi->flags;
        ph = oi->path_hash;
        dh = oi->dir_hash;
    }

    emit_event(OP_WRITE, tgid, pid, fd, bytes, flags, ph, dh);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    int fd = (int)ctx->args[0];

    /* Delete kernel-side fd tracking to prevent map growth */
    struct fd_key k = { .tgid = tgid, .fd = fd };
    bpf_map_delete_elem(&fd_info_map, &k);

    /* Emit close so userspace can mirror-delete its own cache */
    emit_event(OP_CLOSE, tgid, pid, fd, 0, 0, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    // args: olddfd, oldname, newdfd, newname, flags
    const char *new_path_user = (const char *)ctx->args[3];
    __u32 flags = (__u32)ctx->args[4];

    char path[128] = {};
    long n = 0;
    if (new_path_user) {
        n = bpf_probe_read_user_str(path, sizeof(path), new_path_user);
    }

    __u64 ph = 0;
    __u64 dh = 0;
    if (n > 0) {
        ph = fnv1a64_cstr(path, (int)sizeof(path));
        dh = fnv1a64_dirprefix(path, (int)sizeof(path));
    }

    // fd not meaningful for rename; set -1
    emit_event(OP_RENAMEAT2, tgid, pid, -1, 0, flags, ph, dh);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    // args: dfd, pathname, flags
    const char *path_user = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];

    char path[128] = {};
    long n = 0;
    if (path_user) {
        n = bpf_probe_read_user_str(path, sizeof(path), path_user);
    }

    __u64 ph = 0;
    __u64 dh = 0;
    if (n > 0) {
        ph = fnv1a64_cstr(path, (int)sizeof(path));
        dh = fnv1a64_dirprefix(path, (int)sizeof(path));
    }

    emit_event(OP_UNLINKAT, tgid, pid, -1, 0, flags, ph, dh);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int handle_sys_enter_ftruncate(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    // args: fd, length
    int fd = (int)ctx->args[0];
    // length is ctx->args[1] but we don't need it for now

    __u32 flags = 0;
    __u64 ph = 0, dh = 0;

    // Try to recover path/dir hashes from our fd_info_map
    struct fd_key k = { .tgid = tgid, .fd = fd };
    struct open_info *oi = bpf_map_lookup_elem(&fd_info_map, &k);
    if (oi) {
        flags = oi->flags;
        ph = oi->path_hash;
        dh = oi->dir_hash;
    }

    emit_event(OP_FTRUNCATE, tgid, pid, fd, 0, flags, ph, dh);
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(handle_lsm_file_permission, struct file *file, int mask)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    // Only care about write permission attempts
    if ((mask & MAY_WRITE) == 0)
        return 0;

    // Only log/act if tgid is marked
    __u8 *marked = bpf_map_lookup_elem(&blocked_tgids, &tgid);
    if (!marked)
        return 0;

    // Emit an event so userspace can see enforcement candidates
    emit_event(OP_LSM_FILE_PERM, tgid, pid, -1, 0, (__u32)mask, 0, 0);

    // Phase 1: log-only (never block)
    // Phase 2: set lsm_control[0]=1 and return -EPERM for marked TGIDs.
    __u32 k = 0;
    __u8 *ctrl = bpf_map_lookup_elem(&lsm_control, &k);
    if (ctrl && *ctrl == 1) {
        return -13; // -EPERM
    }

    return 0;
}

