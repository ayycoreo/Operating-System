all:
	gcc -c libmap.c -o libmap.o
	ar rcs libmap.a libmap.o
	gcc demo.c -L. -lmap -o demo

clean:
	rm -f libmap.o libmap.a demo
