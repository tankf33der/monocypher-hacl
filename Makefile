all:
	gcc -I. -I kremlib/dist/minimal main.c Hacl_Poly1305_32.c monocypher.c && ./a.out
clean:
	rm -rf *.o *.out
