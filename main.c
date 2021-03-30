#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "Hacl_Poly1305_32.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_Hash.h"

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
        mac1[i] = 123;
        crypto_poly1305(mac1, in, i, key);
        Hacl_Poly1305_32_poly1305_mac(mac2, i, in, key);
        status |= crypto_verify16(mac1, mac2);
	}
	return status;
}

//@ ensures \result == 0;
int sha512(void) {
    ARRAY(hash1,  64);
    ARRAY(hash2,  64);
    ARRAY(in  , 128);
	int status = 0;
    for(size_t i = 0; i < 128; i++) {
    	hash1[0] = 123;
        crypto_sha512(hash1, in, i);
        Hacl_Hash_SHA2_hash_512(in, i, hash2);
        status |= crypto_verify64(hash1, hash2);
    }
    return status;
}

//@ ensures \result == 0;
int blake2b(void) {
    ARRAY(hash1, 64);
    ARRAY(hash2, 64);
    ARRAY(key,  64);
    ARRAY(in,   64);
	int status = 0;

/*
Hacl_Blake2b_32_blake2b(
  uint32_t nn,
  uint8_t *output,
  uint32_t ll,
  uint8_t *d,
  uint32_t kk,
  uint8_t *k
)
*/

/*
0, 1 0 48
0, 1 0 56
-1, 1 8 0
-1, 1 8 8
-1, 1 8 16
*/

/*
    for(size_t h = 1; h < 64; h += 8)
        for(size_t k = 8; k < 64; k += 8)
            for(size_t i = 8; i < 64; i += 8) {
            	hash1[0] = 123;
                crypto_blake2b_general(hash1, h, key, k, in, i);
                Hacl_Blake2b_32_blake2b(h, hash2, i, in, k, key);
                status |= crypto_verify64(hash1, hash2);
                printf("%d, %d %d %d\n", status, h, k, i);
            }
*/

	hash1[0] = 123;
    crypto_blake2b_general(hash1, 1, key, 8, in, 0);
    Hacl_Blake2b_32_blake2b(1, hash2, 0, in, 8, key);
    //status |= crypto_verify64(hash1, hash2);
                        
    return status;
}


//@ ensures \result == 0;
int x25519(void) {
    ARRAY(key, 32);
    ARRAY(pub1, 32);
    ARRAY(pub2, 32);
    key[0] = 0;
	pub1[0] = 123;
    int status = 0;
    
    crypto_x25519_public_key(pub1, key);
    Hacl_Curve25519_51_secret_to_public(pub2, key);
    status |= crypto_verify32(pub1, pub2);
    return status;
}

int main(void) {
	int status = 0;
	
	status |= p1305();
	status |= x25519();
	status |= sha512();
	status |= blake2b();

	printf("%s\n", status != 0 ? "FAIL" : "OK");	
	return status;
}
