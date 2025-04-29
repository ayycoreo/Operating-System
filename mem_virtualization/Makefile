all: cow pthread fork anon idempotent mmap ondemand

cow: libmap
	gcc ./cow.c -L./libmap -lmap -o cow 

pthread: libmap
	gcc ./pthread_memory.c -L./libmap -lmap -lpthread -o pthread

fork: libmap
	gcc ./fork_memory.c -L./libmap -lmap -o fork

anon:
	gcc ./anon_mmap.c -o anon

idempotent:
	gcc ./idempotent.c -o idempotent

mmap:
	gcc ./mmap.c -o mmap

ondemand:
	gcc ./ondemand.c -o ondemand

libmap:  # recursively build the libmap library using libmap/Makefile
	$(MAKE) -C libmap

clean:
	rm -f cow pthread fork anon idempotent mmap ondemand
	$(MAKE) -C libmap clean

.PHONY: all clean libmap
