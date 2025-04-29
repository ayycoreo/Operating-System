// File: read_demo.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/ksys_write")
int kprobe_ksys_write(struct pt_regs *ctx)
{
	bpf_printk("[read] [kprobe]\n");
    const char *user_buf;
    size_t count;
    char buf[64] = {};  // Small buffer
    u32 pid;

    pid = bpf_get_current_pid_tgid() >> 32;

	int fd= (int) PT_REGS_PARM1(ctx);
    user_buf = (const char *)PT_REGS_PARM2(ctx);
    count = (size_t)PT_REGS_PARM3(ctx);

	bpf_printk("fd: %d", fd);
	bpf_printk("user_buf: %p", user_buf);
	bpf_printk("count: %d", count);
    if (!user_buf || count == 0)
        return 0;

    // Only try to read a small number of bytes for safety
    size_t to_read = sizeof(buf);
    if (count < to_read)
        to_read = count;

    int ret = bpf_probe_read_user(buf, to_read, user_buf);
    if (ret == 0) {
        bpf_printk("[read] PID %d read first bytes: %s\n", pid, buf);
    } else {
        bpf_printk("[read] PID %d failed to read user buffer\n", pid);
    }

    return 0;
}

