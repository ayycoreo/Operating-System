#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe/__x64_sys_execve")
int hello(void *ctx) {
    bpf_printk("Hello from __x64_sys_execve!\\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

