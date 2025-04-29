// block_exec.c

#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static volatile bool exiting = false;

void sig_int_handler(int signo)
{
    exiting = true;
}

int main()
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int err;

    signal(SIGINT, sig_int_handler);
    signal(SIGTERM, sig_int_handler);

    obj = bpf_object__open_file("read_demo.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "kprobe_ksys_write");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\\n");
        return 1;
    }

    printf("✅ BPF program loaded and attached! Watching ksys_write syscalls.\n");
    printf("Press Ctrl+C to exit.\n");

    while (!exiting) {
        sleep(1);
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);

    printf("✅ BPF program detached.\n");
    return 0;
}

