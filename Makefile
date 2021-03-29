all:
	clang -fsanitize=address -I. -I kremlib/dist/minimal main.c Hacl_Poly1305_32.c monocypher.c && ./a.out
	clang -fsanitize=memory -I. -I kremlib/dist/minimal main.c Hacl_Poly1305_32.c monocypher.c && ./a.out
	clang -fsanitize=undefined -I. -I kremlib/dist/minimal main.c Hacl_Poly1305_32.c monocypher.c && ./a.out
clean:
	rm -rf *.o *.out
