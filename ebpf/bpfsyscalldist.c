#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "bits.bpf.h"
#include "maps.bpf.h"

char __license[] SEC("license") = "GPL";

#define MAX_SLOTS 36

static volatile const __u32 filter_pid = 0;

struct bpf_cmd_tmp {
    __u64 ts;
    int cmd;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct bpf_cmd_tmp);
    __uint(max_entries, 1024);
} clocks SEC(".maps");

struct hist {
    __u64 slots[MAX_SLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct hist);
    __uint(max_entries, 64);
} hists SEC(".maps");

SEC("kprobe/__sys_bpf")
int BPF_KPROBE(k_sys_bpf, int cmd)
{
    // __u8 current_command[64] = {};
    // bpf_get_current_comm(&current_command, 64);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    // bpf_printk("__sys_bpf, tgid=%d pid=%d comm=%s\n", (__u32)(pid_tgid>>32), pid, current_command);
    if (filter_pid && pid != filter_pid)
        return BPF_OK;

    struct bpf_cmd_tmp bpf_cmd = {
        .ts = bpf_ktime_get_ns(),
        .cmd = cmd,
    };

    bpf_map_update_elem(&clocks, &pid_tgid, &bpf_cmd, BPF_ANY);

    return BPF_OK;
}

SEC("kretprobe/__sys_bpf")
int BPF_KRETPROBE(kr_sys_bpf, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (filter_pid && pid != filter_pid)
        return BPF_OK;

    struct bpf_cmd_tmp *cmd = bpf_map_lookup_and_delete(&clocks, &pid_tgid);
    if (!cmd)
        return BPF_OK;

    struct hist initial_hist = {};
    __u32 index = (__u32)cmd->cmd;
    struct hist *hist = bpf_map_lookup_or_try_init(&hists, &index, &initial_hist);
    if (!hist)
        return BPF_OK;

    __u64 delta = bpf_ktime_get_ns() - cmd->ts;
    delta /= 1000; // micro-second

    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    hist->slots[slot]++; // PERCPU, no atomic required

    return BPF_OK;
}