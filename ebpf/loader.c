// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static struct bpf_link *blink = NULL;
static struct bpf_object *obj = NULL;

// Signal handler for Ctrl+C (SIGINT)
void handle_signal(int sig) {
    printf("\nCaught signal %d, exiting...\n", sig);

    if (blink) {
        bpf_link__destroy(blink);
        blink = NULL;
    }

    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }

    exit(0);
}

int main() {
    struct bpf_program *prog;

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open the pre-compiled BPF object file
    obj = bpf_object__open_file("prog.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    // Load the BPF object into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object into kernel\n");
        bpf_object__close(obj);
        return 1;
    }

    // Find the BPF program inside the object
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach the BPF program (e.g., kprobe attachment)
    blink = bpf_program__attach(prog);
    if (!blink) {
        fprintf(stderr, "Failed to attach BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program loaded and attached successfully.\n");
    printf("Press Ctrl+C to exit and clean up.\n");

    // Sleep forever until interrupted
    while (1) {
        pause();  // Suspend until a signal is received
    }

    // Normally unreachable because handle_signal() calls exit()
    return 0;
}

