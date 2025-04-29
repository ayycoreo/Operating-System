// File: read_loader.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "read_demo.skel.h"  // generated from bpftool

static volatile sig_atomic_t stop;

void handle_signal(int sig)
{
    stop = 1;
}

int main()
{
    struct read_demo_bpf *skel;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = read_demo_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = read_demo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("Successfully started! Hit Ctrl+C to exit.\n");
    printf("Now watch /sys/kernel/debug/tracing/trace_pipe\n");

    system("cat /sys/kernel/debug/tracing/trace_pipe > logs");

    while (!stop)
        sleep(1);

cleanup:
    read_demo_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

