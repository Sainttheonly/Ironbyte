#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define OP_WRITE      2
#define OP_OPENAT_RET 4

#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME  1099511628211ULL

static __always_inline __u64 fnv1a_step(__u64 h, __u8 c)
{
    h ^= c;
    h *= FNV_PRIME;
    return h;
}

// Hash first 32 bytes of buf (stop on NUL) WITHOUT LOOPS.
static __always_inline __u64 hash32(const char buf[64])
{
    __u64 h = FNV_OFFSET;

#define H(i) do { h = fnv1a_step(h, (__u8)buf[i]); } while (0)

    H(0);  if (!buf[0])  return h;
    H(1);  if (!buf[1])  return h;
    H(2);  if (!buf[2])  return h;
    H(3);  if (!buf[3])  return h;
    H(4);  if (!buf[4])  return h;
    H(5);  if (!buf[5])  return h;
    H(6);  if (!buf[6])  return h;
    H(7);  if (!buf[7])  return h;
    H(8);  if (!buf[8])  return h;
    H(9);  if (!buf[9])  return h;
    H(10); if (!buf[10]) return h;
    H(11); if (!buf[11]) return h;
    H(12); if (!buf[12]) return h;
    H(13); if (!buf[13]) return h;
    H(14); if (!buf[14]) return h;
    H(15); if (!buf[15]) return h;
    H(16); if (!buf[16]) return h;
    H(17); if (!buf[17]) return h;
    H(18); if (!buf[18]) return h;
    H(19); if (!buf[19]) return h;
    H(20); if (!buf[20]) return h;
    H(21); if (!buf[21]) return h;
    H(22); if (!buf[22]) return h;
    H(23); if (!buf[23]) return h;
    H(24); if (!buf[24]) return h;
    H(25); if (!buf[25]) return h;
    H(26); if (!buf[26]) return h;
    H(27); if (!buf[27]) return h;
    H(28); if (!buf[28]) return h;
    H(29); if (!buf[29]) return h;
    H(30); if (!buf[30]) return h;
    H(31); if (!buf[31]) return h;

#undef H
    return h;
}

// Hash directory prefix (up to last '/' within first 32 bytes). No loops.
static __always_inline __u64 dirhash32(const char buf[64])
{
    // find last slash index among first 32 bytes
    int last = -1;
#define SL(i) do { if (buf[i] == '/') last = i; } while (0)
    SL(0);  SL(1);  SL(2);  SL(3);  SL(4);  SL(5);  SL(6);  SL(7);
    SL(8);  SL(9);  SL(10); SL(11); SL(12); SL(13); SL(14); SL(15);
    SL(16); SL(17); SL(18); SL(19); SL(20); SL(21); SL(22); SL(23);
    SL(24); SL(25); SL(26); SL(27); SL(28); SL(29); SL(30); SL(31);
#undef SL

    if (last < 0) return 0;

    __u64 h = FNV_OFFSET;
#define DH(i) do { if (i <= last) h = fnv1a_step(h, (__u8)buf[i]); } while (0)
    // 32 unrolled conditionals
    DH(0);  DH(1);  DH(2);  DH(3);  DH(4);  DH(5);  DH(6);  DH(7);
    DH(8);  DH(9);  DH(10); DH(11); DH(12); DH(13); DH(14); DH(15);
    DH(16); DH(17); DH(18); DH(19); DH(20); DH(21); DH(22); DH(23);
    DH(24); DH(25); DH(26); DH(27); DH(28); DH(29); DH(30); DH(31);
#undef DH

    return h;
}

struct file_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 opcode;
    __s32 fd;
    __u32 bytes;
    __u32 flags;
    __u64 path_hash;
    __u64 dir_hash;   // NEW
    char  comm[16];
};

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

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pid_tgid;

    const char *filename = (const char *)ctx->args[1];
    __u32 flags = (__u32)(long)ctx->args[2];

    char buf[64] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    struct open_args oa = {
        .flags = flags,
        .path_hash = hash32(buf),
        .dir_hash = dirhash32(buf),
    };

    bpf_map_update_elem(&open_args_map, &pid, &oa, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    int ret_fd = (int)ctx->ret;
    if (ret_fd < 0) {
        bpf_map_delete_elem(&open_args_map, &pid);
        return 0;
    }

    struct open_args *oa = bpf_map_lookup_elem(&open_args_map, &pid);
    if (!oa) return 0;

    struct fd_key k = { .tgid = tgid, .fd = ret_fd };
    struct open_info oi = { .flags = oa->flags, .path_hash = oa->path_hash, .dir_hash = oa->dir_hash };
    bpf_map_update_elem(&fd_info_map, &k, &oi, BPF_ANY);

    struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ts_ns = bpf_ktime_get_ns();
        e->pid = pid;
        e->tgid = tgid;
        e->opcode = OP_OPENAT_RET;
        e->fd = ret_fd;
        e->bytes = 0;
        e->flags = oa->flags;
        e->path_hash = oa->path_hash;
        e->dir_hash = oa->dir_hash;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&open_args_map, &pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid  = (__u32)pid_tgid;

    long fd = (long)ctx->args[0];
    size_t count = (size_t)ctx->args[2];

    __u32 flags = 0;
    __u64 path_hash = 0;
    __u64 dir_hash = 0;

    struct fd_key k = { .tgid = tgid, .fd = (int)fd };
    struct open_info *oi = bpf_map_lookup_elem(&fd_info_map, &k);
    if (oi) {
        flags = oi->flags;
        path_hash = oi->path_hash;
        dir_hash = oi->dir_hash;
    }

    struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tgid = tgid;
    e->opcode = OP_WRITE;
    e->fd = (int)fd;
    e->bytes = (count > 0xffffffffu) ? 0xffffffffu : (__u32)count;
    e->flags = flags;
    e->path_hash = path_hash;
    e->dir_hash = dir_hash;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
