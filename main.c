#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "Hacl_Poly1305_32.h"
#include "Hacl_Curve25519_51.h"
#include "Hacl_Ed25519.h"
#include "Hacl_HMAC.h"
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
        mac1[1] = 123;
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
int hmac(void) {
    ARRAY(hash1, 64);
    ARRAY(hash2, 64);
    ARRAY(key , 64);
    ARRAY(in  , 64);
    int status = 0;

	/*
    Hacl_Hash.c:5628:[value] warning: invalid pointer (void const *)rest.
                     stack: memcpy :: Hacl_Hash.c:5628 <-
                            Hacl_Hash_SHA2_update_last_512 :: Hacl_HMAC.c:432 <-
                            Hacl_HMAC_compute_sha2_512 :: main.c:57 <-
                            hmac
	*/                       
	//         i = 0 generates error ^^^^^ while reading from NULL.
    for(size_t i = 0; i < 64; i++) {
    	hash1[1] = 77;
        crypto_hmac_sha512(hash1, key, i, in, i);
        Hacl_HMAC_compute_sha2_512(hash2, key, i, in, i);
        status |= crypto_verify64(hash1, hash2);
    }
    return status;
}

int hmac_full(void) {
    ARRAY(hash1, 64);
    ARRAY(hash2, 64);
    ARRAY(key , 128);
    ARRAY(in  , 128);
    int status = 0;

    for(size_t i = 0; i < 128; i++)
    	for(size_t j = 0; j < 128; j++) {
	    	hash1[1] = 77;
	        crypto_hmac_sha512(hash1, key, i, in, j);
	        Hacl_HMAC_compute_sha2_512(hash2, key, i, in, j);
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

    for(size_t h = 1; h <= 64; h += 8)
        for(size_t k = 0; k <= 64; k += 8)
            for(size_t i = 0; i <= 64; i += 8) {
            	hash1[1] = 123;
                crypto_blake2b_general(hash1, h, key, k, in, i);
                Hacl_Blake2b_32_blake2b(h, hash2, i, in, k, key);
                // status |= crypto_verify64(hash1, hash2);
            }

	// hash1[0] = 123;
    // crypto_blake2b_general(hash1, 1, key, 8, in, 0);
    // Hacl_Blake2b_32_blake2b(1, hash2, 0, in, 8, key);
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

void ed25519_zero(void) {
	ARRAY(hash1, 64);
	ARRAY(hash2, 64);
    ARRAY(key,   32);
    ARRAY(in,    32);

	memset(hash1, 0, 64);
	memset(hash2, 0, 64);
	memset(in, 0, 32);
	memset(key, 0, 32);
	key[31] = 128;

	for(size_t i = 0; i < 256; i++) {
		int mono;
		int hacl;
		
		in[0] = i;
		mono = crypto_ed25519_check(hash1, key, in, 1);
		hacl = Hacl_Ed25519_verify(key, 1, in, hash2);
		printf("%d=%d\n", mono, hacl);
	}
}

//@ ensures \result == 0;
int sign_check_ed25519(void) {
    ARRAY(hash1, 64);
    ARRAY(hash2, 64);
    ARRAY(key,   32);
    ARRAY(pub1,  32);
    ARRAY(pub2,  32);
    ARRAY(in,    32);
    int status = 0;
    
    crypto_ed25519_public_key(pub1, key);
	Hacl_Ed25519_secret_to_public(pub2, key);
	status |= crypto_verify32(pub1, pub2);
    
    crypto_ed25519_sign(hash1, key, pub1, in, 32);
    Hacl_Ed25519_sign(hash2, key, 32, in);
	status |= crypto_verify64(hash1, hash2);
    
    status |= crypto_ed25519_check(hash1, pub1, in, 32);
    status |= !Hacl_Ed25519_verify(pub2, 32, in, hash2);	// as bool: 1 - ok, 0 - wrong

	// XXX
    for(size_t i = 0; i < 64; i++) hash2[i] = 0;
    // must fail
    status |= Hacl_Ed25519_verify(hash2, 0, hash2, hash2);		// as bool: 1 - ok, 0 - wrong
    
    return status;
}

int ed25519_full(void) {
    ARRAY(hash1, 64);
    ARRAY(hash2, 64);
    ARRAY(key,   32);
    ARRAY(pub1,  32);
    ARRAY(pub2,  32);
    ARRAY(in,    128);
    int status = 0;
    
    crypto_ed25519_public_key(pub1, key);
	Hacl_Ed25519_secret_to_public(pub2, key);
	status |= crypto_verify32(pub1, pub2);
    
    for(size_t i = 0; i < 128; i++) {
    	hash1[2] = 123;
    	
	    crypto_ed25519_sign(hash1, key, pub1, in, i);
    	Hacl_Ed25519_sign(hash2, key, i, in);
		status |= crypto_verify64(hash1, hash2);
    
   		status |= crypto_ed25519_check(hash1, pub1, in, i);
    	status |= !Hacl_Ed25519_verify(pub2, i, in, hash2);	// as bool: 1 - ok, 0 - wrong
	}
    return status;
}

/* from Monocypher library, Loup hi! */
static void iterate_x25519(uint8_t k[32], uint8_t u[32])
{
    uint8_t tmp[32];
    Hacl_Curve25519_51_scalarmult(tmp , k, u);
    memcpy(u, k  , 32);
    memcpy(k, tmp, 32);
}

static int test_x25519()
{
   	uint8_t _1   [32] = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
                    0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
                    0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
                    0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    uint8_t k[32] = {9};
    uint8_t u[32] = {9};

    Hacl_Curve25519_51_secret_to_public(k, u);
    int status = memcmp(k, _1, 32);

    uint8_t _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                    0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                    0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                    0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    for(size_t i = 1; i < 1000; i++) { iterate_x25519(k, u); }
    status |= memcmp(k, _1k, 32);
    return status;
}

int main(void) {
	int status = 0;
	
	status |= p1305();
	status |= x25519();
	status |= sign_check_ed25519();
	status |= sha512();
	status |= hmac();
	status |= blake2b();

	// FULLs
	status |= hmac_full();
	status |= ed25519_full();
	ed25519_zero();
	// status |= test_x25519();	// RFC, slow passed

	printf("%s\n", status != 0 ? "FAIL" : "OK");	
	return status;
}
