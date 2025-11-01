#include "../include/md5.h"

static const uint8_t PADDING[64] = { 0x80, 0 };

// Memory set macro (no endianness issue)
static void Encode(uint8_t *output, const uint32_t *input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j]   = (uint8_t)( input[i]        & 0xff);
        output[j+1] = (uint8_t)((input[i] >> 8)  & 0xff);
        output[j+2] = (uint8_t)((input[i] >> 16) & 0xff);
        output[j+3] = (uint8_t)((input[i] >> 24) & 0xff);
    }
}

// Memory set macro (no endianness issue)
static void Decode(uint32_t *output, const uint8_t *input, unsigned int len) {
    unsigned int i, j;
    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((uint32_t)input[j]) |
                    ((uint32_t)input[j+1] << 8) |
                    ((uint32_t)input[j+2] << 16) |
                    ((uint32_t)input[j+3] << 24);
    }
}

#define MD5_MEMCPY(dest, src, len) memcpy(dest, src, len)
#define MD5_MEMSET(dest, val, len) memset(dest, val, len)
#define MD5_DECODE(dest, src, len) Decode(dest, src, len)
#define MD5_ENCODE(dest, src, len) Encode(dest, src, len)

int MD5Init(MD5_CTX *c) {
    if (!c) return 0;
    c->bitlen = 0;
    c->buffer_len = 0;   // << important
    c->state[0] = INIT_DATA_A;
    c->state[1] = INIT_DATA_B;
    c->state[2] = INIT_DATA_C;
    c->state[3] = INIT_DATA_D;
    return 1;
}

void MD5Update(MD5_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;

    while (i < len) {
        size_t space = 64 - ctx->buffer_len;
        size_t to_copy = (len - i < space) ? len - i : space;

        MD5_MEMCPY(ctx->buffer + ctx->buffer_len, data + i, to_copy);
        ctx->buffer_len += to_copy;
        ctx->bitlen += to_copy * 8; // total bits
        i += to_copy;

        if (ctx->buffer_len == 64) {
            MD5Transform(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void MD5Final(MD5_CTX *ctx, uint8_t digest[16]) {
    uint8_t bits[8];
    size_t index, padLen;

    // Save number of bits
    bits[0] = (uint8_t)(ctx->bitlen & 0xff);
    bits[1] = (uint8_t)((ctx->bitlen >> 8) & 0xff);
    bits[2] = (uint8_t)((ctx->bitlen >> 16) & 0xff);
    bits[3] = (uint8_t)((ctx->bitlen >> 24) & 0xff);
    bits[4] = (uint8_t)((ctx->bitlen >> 32) & 0xff);
    bits[5] = (uint8_t)((ctx->bitlen >> 40) & 0xff);
    bits[6] = (uint8_t)((ctx->bitlen >> 48) & 0xff);
    bits[7] = (uint8_t)((ctx->bitlen >> 56) & 0xff);

    // Pad out to 56 mod 64
    index = ctx->buffer_len;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(ctx, PADDING, padLen);

    // Append length (before padding)
    MD5Update(ctx, bits, 8);

    // Store state in digest (little-endian)
    Encode(digest, ctx->state, 16);

    // Zeroize sensitive information
    MD5_MEMSET(ctx, 0, sizeof(*ctx));
}

void MD5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    MD5_DECODE(x, block, 64);

    // Round 1
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478); // 1
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); // 2
    FF (c, d, a, b, x[ 2], S13, 0x242070db); // 3
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); // 4
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); // 5
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a); // 6
    FF (c, d, a, b, x[ 6], S13, 0xa8304613); // 7
    FF (b, c, d, a, x[ 7], S14, 0xfd469501); // 8
    FF (a, b, c, d, x[ 8], S11, 0x698098d8); // 9
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); // 10
    FF (c, d, a, b, x[10], S13, 0xffff5bb1); // 11
    FF (b, c, d, a, x[11], S14, 0x895cd7be); // 12
    FF (a, b, c, d, x[12], S11, 0x6b901122); // 13
    FF (d, a, b, c, x[13], S12, 0xfd987193); // 14
    FF (c, d, a, b, x[14], S13, 0xa679438e); // 15
    FF (b, c, d, a, x[15], S14, 0x49b40821); // 16

    // Round 2
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562); // 17
    GG (d, a, b, c, x[ 6], S22, 0xc040b340); // 18
    GG (c, d, a, b, x[11], S23, 0x265e5a51); // 19
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); // 20
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d); // 21
    GG (d, a, b, c, x[10], S22,  0x2441453); // 22
    GG (c, d, a, b, x[15], S23, 0xd8a1e681); // 23
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); // 24
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); // 25
    GG (d, a, b, c, x[14], S22, 0xc33707d6); // 26
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); // 27

    GG (b, c, d, a, x[ 8], S24, 0x455a14ed); // 28
    GG (a, b, c, d, x[13], S21, 0xa9e3e905); // 29
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); // 30
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9); // 31
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); // 32

    // Round 3
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942); // 33
    HH (d, a, b, c, x[ 8], S32, 0x8771f681); // 34
    HH (c, d, a, b, x[11], S33, 0x6d9d6122); // 35
    HH (b, c, d, a, x[14], S34, 0xfde5380c); // 36
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44); // 37
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); // 38
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); // 39
    HH (b, c, d, a, x[10], S34, 0xbebfbc70); // 40
    HH (a, b, c, d, x[13], S31, 0x289b7ec6); // 41
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); // 42
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); // 43
    HH (b, c, d, a, x[ 6], S34,  0x4881d05); // 44
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); // 45
    HH (d, a, b, c, x[12], S32, 0xe6db99e5); // 46
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8); // 47
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); // 48

    // Round 4
    II (a, b, c, d, x[ 0], S41, 0xf4292244); // 49
    II (d, a, b, c, x[ 7], S42, 0x432aff97); // 50
    II (c, d, a, b, x[14], S43, 0xab9423a7); // 51
    II (b, c, d, a, x[ 5], S44, 0xfc93a039); // 52
    II (a, b, c, d, x[12], S41, 0x655b59c3); // 53
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); // 54
    II (c, d, a, b, x[10], S43, 0xffeff47d); // 55
    II (b, c, d, a, x[ 1], S44, 0x85845dd1); // 56
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); // 57
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0); // 58
    II (c, d, a, b, x[ 6], S43, 0xa3014314); // 59
    II (b, c, d, a, x[13], S44, 0x4e0811a1); // 60
    II (a, b, c, d, x[ 4], S41, 0xf7537e82); // 61
    II (d, a, b, c, x[11], S42, 0xbd3af235); // 62
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); // 63
    II (b, c, d, a, x[ 9], S44, 0xeb86d391); // 64

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Zeroize sensitive information.
    MD5_MEMSET(x, 0, sizeof (x));
}

uint8_t *MD5(const uint8_t *data, size_t len, uint8_t *md) {
    MD5_CTX ctx;
    static uint8_t default_md[MD5_DIGEST_LENGTH];

    if (!md) md = default_md;
    if (!MD5Init(&ctx)) return NULL;

    MD5Update(&ctx, data, len);
    MD5Final(&ctx, md);

    return md;
}


void md5_to_hex(const uint8_t digest[MD5_DIGEST_LENGTH], char out[33]) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(out + i * 2, "%02x", digest[i]);
    out[32] = '\0';
}

uint8_t *compute_md5_file(const char *filename, uint8_t out[MD5_DIGEST_LENGTH]) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    MD5_CTX ctx;
    MD5Init(&ctx);

    uint8_t buffer[1024];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        MD5Update(&ctx, buffer, n);
    }

    fclose(f);
    MD5Final(&ctx, out);
    return out;
}

