all:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c read_demo.bpf.c -o read_demo.bpf.o
	bpftool gen skeleton read_demo.bpf.o > read_demo.skel.h
	gcc -O2 -g -o read_loader read_loader.c -lbpf -lelf -lz
