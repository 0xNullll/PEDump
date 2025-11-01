#ifndef MD5_IMP_H
#define MD5_IMP_H

#include "libs.h"
#include "file_defs.h"


#define MD5_DIGEST_LENGTH 16

#define INIT_DATA_A (uint32_t)0x67452301L
#define INIT_DATA_B (uint32_t)0xefcdab89L
#define INIT_DATA_C (uint32_t)0x98badcfeL
#define INIT_DATA_D (uint32_t)0x10325476L

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// F, G, H and I are basic MD5 functions.
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// ROTATE_LEFT rotates x left n bits.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
}

typedef struct {
    uint32_t state[4];   // A, B, C, D — current hash state
    uint64_t bitlen;     // total number of bits processed
    uint8_t buffer[64];  // data buffer (one 512-bit block)
    size_t buffer_len;   // current buffer length in bytes
} MD5_CTX;

int MD5Init
(
    IN MD5_CTX *c
);

void MD5Update
(
    INOUT MD5_CTX       *ctx,
    IN    const uint8_t *data,
    IN    size_t         len
);

void MD5Final
(
    INOUT MD5_CTX *ctx,
    OUT   uint8_t  digest[16]
);

void MD5Transform
(
    IN    uint32_t      state[4],
    INOUT const uint8_t block[64]
);

// Convenience function to compute MD5 in one shot
uint8_t *MD5
(
    IN  const uint8_t *data,
    IN  size_t         len, 
    OUT uint8_t       *md5
);

// Convert MD5 digest to hex string
void md5_to_hex
(
    IN    const uint8_t digest[MD5_DIGEST_LENGTH],
    INOUT char          out[33]
);

// Compute MD5 for a file
uint8_t *compute_md5_file
(
    IN  const char *filename,
    OUT uint8_t     out[MD5_DIGEST_LENGTH]
);

// Compare two digests, returns 1 if equal, 0 otherwise
inline int md5_compare
(
    IN const uint8_t a[MD5_DIGEST_LENGTH],
    IN const uint8_t b[MD5_DIGEST_LENGTH]
) {
    return memcmp(a, b, MD5_DIGEST_LENGTH);
}

#endif