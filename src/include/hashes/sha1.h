#ifndef SHA_IMP_H
#define SHA_IMP_H

#include "../libs.h"

#define SHA1_LBLOCK 16  // 16 words per 512-bit block
#define SHA1_DIGEST_LENGTH 20

// SHA-1 context structure
typedef struct SHAstate_st {
    uint32_t h0, h1, h2, h3, h4;    // hash state (5 × 32-bit words)
    uint32_t Nl, Nh;                // bit counters (low and high)
    uint32_t data[SHA1_LBLOCK];     // data block buffer
    uint32_t num;                   // number of bytes in data[]
} SHA_CTX;

// Initial hash values (H0..H4)
#define INIT_DATA_H0 0x67452301UL
#define INIT_DATA_H1 0xefcdab89UL
#define INIT_DATA_H2 0x98badcfeUL
#define INIT_DATA_H3 0x10325476UL
#define INIT_DATA_H4 0xc3d2e1f0UL

// Rotate left macro
#define ROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))

// SHA-1 round functions f(t; B, C, D)
#define F_00_19(B,C,D)  (((B) & (C)) | ((~(B)) & (D)))           // Ch, rounds 0–19
#define F_20_39(B,C,D)  ((B) ^ (C) ^ (D))                        // Parity, rounds 20–39
#define F_40_59(B,C,D)  (((B) & (C)) | ((B) & (D)) | ((C) & (D)))// Maj, rounds 40–59
#define F_60_79(B,C,D)  F_20_39((B),(C),(D))                     // Parity again, rounds 60–79

// SHA-1 constants
#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

// Initialize SHA-1 context
static inline void SHA1Init(SHA_CTX *c) {
    memset(c, 0, sizeof(*c));
    c->h0 = INIT_DATA_H0;
    c->h1 = INIT_DATA_H1;
    c->h2 = INIT_DATA_H2;
    c->h3 = INIT_DATA_H3;
    c->h4 = INIT_DATA_H4;
}

// Process a single 512-bit block
static void SHA1ProcessBlock(SHA_CTX *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t A,B,C,D,E,TEMP;

    // Copy block to W[0..15] (big-endian)
    for(int i=0;i<16;i++) {
        W[i] = ((uint32_t)block[i*4 + 0] << 24) |
               ((uint32_t)block[i*4 + 1] << 16) |
               ((uint32_t)block[i*4 + 2] << 8)  |
               ((uint32_t)block[i*4 + 3]);
    }

    // Expand W[16..79]
    for(int t=16;t<80;t++) {
        W[t] = ROTATE(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    // Initialize working variables
    A = ctx->h0; B = ctx->h1; C = ctx->h2; D = ctx->h3; E = ctx->h4;

    // Main loop
    for(int t=0;t<80;t++) {
        uint32_t f,k;
        if(t<=19) {
            f=F_00_19(B,C,D); k=K_00_19;
        }
        else if(t<=39) {
            f=F_20_39(B,C,D); k=K_20_39;
        }
        else if(t<=59) {
            f=F_40_59(B,C,D); k=K_40_59;
        }
        else {
            f=F_60_79(B,C,D); k=K_60_79;
        }

        TEMP = ROTATE(A,5) + f + E + W[t] + k;
        E = D;
        D = C;
        C = ROTATE(B,30);
        B = A;
        A = TEMP;
    }

    // Update hash state
    ctx->h0 += A; ctx->h1 += B; ctx->h2 += C; ctx->h3 += D; ctx->h4 += E;
}

static void SHA1Final(SHA_CTX *ctx, uint8_t *digest) {
    uint64_t total_bits = ((uint64_t)ctx->Nh << 32) | ctx->Nl;
    uint32_t i = ctx->num;

    uint8_t block[64] = {0};
    memcpy(block, ctx->data, i);
    block[i++] = 0x80;  // append '1' bit

    if (i > 56) {
        SHA1ProcessBlock(ctx, block);
        memset(block, 0, 64);
        i = 0;
    }

    // Append original message length in bits (big-endian)
    block[56] = (uint8_t)((total_bits >> 56) & 0xFF);
    block[57] = (total_bits >> 48) & 0xFF;
    block[58] = (total_bits >> 40) & 0xFF;
    block[59] = (total_bits >> 32) & 0xFF;
    block[60] = (total_bits >> 24) & 0xFF;
    block[61] = (total_bits >> 16) & 0xFF;
    block[62] = (total_bits >> 8) & 0xFF;
    block[63] = (total_bits) & 0xFF;

    SHA1ProcessBlock(ctx, block);

    // Output hash (big-endian)
    digest[0]  = (uint8_t)((ctx->h0 >> 24) & 0xFF); digest[1]  = (ctx->h0 >> 16) & 0xFF;
    digest[2]  = (ctx->h0 >> 8) & 0xFF;  digest[3]  = ctx->h0 & 0xFF;

    digest[4]  = (uint8_t)((ctx->h1 >> 24) & 0xFF); digest[5]  = (ctx->h1 >> 16) & 0xFF;
    digest[6]  = (ctx->h1 >> 8) & 0xFF;  digest[7]  = ctx->h1 & 0xFF;

    digest[8]  = (uint8_t)((ctx->h2 >> 24) & 0xFF); digest[9]  = (ctx->h2 >> 16) & 0xFF;
    digest[10] = (ctx->h2 >> 8) & 0xFF;  digest[11] = ctx->h2 & 0xFF;

    digest[12] = (uint8_t)((ctx->h3 >> 24) & 0xFF); digest[13] = (ctx->h3 >> 16) & 0xFF;
    digest[14] = (ctx->h3 >> 8) & 0xFF;  digest[15] = ctx->h3 & 0xFF;

    digest[16] = (uint8_t)((ctx->h4 >> 24) & 0xFF); digest[17] = (ctx->h4 >> 16) & 0xFF;
    digest[18] = (ctx->h4 >> 8) & 0xFF;  digest[19] = ctx->h4 & 0xFF;
}

// SHA-1 update for any buffer
static void SHA1Update(SHA_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->Nl += (uint32_t)(len*8);
    if(ctx->Nl < (len*8)) ctx->Nh++;

    while(len > 0) {
        uint32_t to_copy = 64 - ctx->num;
        if(to_copy > len) to_copy = (uint32_t)len;
        memcpy((uint8_t*)ctx->data + ctx->num, data, to_copy);
        ctx->num += to_copy;
        data += to_copy;
        len -= to_copy;

        if(ctx->num == 64) {
            SHA1ProcessBlock(ctx, (uint8_t*)ctx->data);
            ctx->num = 0;
        }
    }
}

// Wrapper function for SHA-1
static void SHA1(const uint8_t *data, size_t len, uint8_t *digest) {
    SHA_CTX ctx;

    SHA1Init(&ctx);          // initialize context
    SHA1Update(&ctx, data, len); // process buffer
    SHA1Final(&ctx, digest); // finalize and output 20-byte digest
}

// Convert SHA-1 digest to hex string
static void SHA1ToHex(const uint8_t digest[SHA1_DIGEST_LENGTH], char out[41]) {
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[40] = '\0';
}

// Compare two SHA-1 digests
static inline int SHA1Compare(const uint8_t a[SHA1_DIGEST_LENGTH],
                               const uint8_t b[SHA1_DIGEST_LENGTH]) {
    return memcmp(a, b, SHA1_DIGEST_LENGTH);
}

#endif
