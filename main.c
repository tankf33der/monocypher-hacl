#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "monocypher.h"
#include "Hacl_Poly1305_32.h"

#define ARRAY(name, size) \
    uint8_t name[size]; \
    for(size_t i = 0; i < size; i++) name[i] = i;

//@ ensures \result == 0;
static int p1305(void) {
    ARRAY(mac1, 16);
    ARRAY(mac2, 16);
    ARRAY(key, 32);
    ARRAY(in,  64);
    int status = 0;
    for(size_t i = 0; i < 64; i++) {
        crypto_poly1305(mac1, in, i, key);
        Hacl_Poly1305_32_poly1305_mac(mac2, i, in, key);
        status |= crypto_verify16(mac1, mac2);
	}
	return status;
}

int main(void) {
	int status = 0;
	
	status |= p1305();

	printf("All OK\n");	
	return status;
}
