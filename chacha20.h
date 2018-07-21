/* ChaCha20 (C99)
 * This is free and unencumbered software released into the public domain.
 */
#include <stdint.h>

#define CHACHA20_KEYSIZE  32
#define CHACHA20_IVSIZE   8
#ifndef CHACHA20_ROUNDS
#  define CHACHA20_ROUNDS 20
#endif

struct chacha20 {
    uint32_t input[16];
    unsigned char output[64];
    int outlen;
};

static void chacha20_init(struct chacha20 *, const void *key, const void *iv);
static void chacha20_keystream_bytes(struct chacha20 *, void *, size_t);

/* Implementation */

#define CHACHA20_ROTATE(v,n) (((v) << (n)) | ((v) >> (32 - (n))))
#define CHACHA20_QUARTERROUND(a,b,c,d) \
    x[a] += x[b]; x[d] = CHACHA20_ROTATE(x[d] ^ x[a],16); \
    x[c] += x[d]; x[b] = CHACHA20_ROTATE(x[b] ^ x[c],12); \
    x[a] += x[b]; x[d] = CHACHA20_ROTATE(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = CHACHA20_ROTATE(x[b] ^ x[c], 7)

static void
chacha20_store_u32le(void *buf, uint32_t x)
{
    unsigned char *p = buf;
    p[0] = x >>  0;
    p[1] = x >>  8;
    p[2] = x >> 16;
    p[3] = x >> 24;
}

static uint32_t
chacha20_load_u32le(const void *buf)
{
    const unsigned char *p = buf;
    return (uint32_t)p[0] <<  0 |
           (uint32_t)p[1] <<  8 |
           (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static void
salsa20_wordtobyte(unsigned char output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; ++i)
        x[i] = input[i];
    for (i = CHACHA20_ROUNDS; i > 0; i -= 2) {
        CHACHA20_QUARTERROUND( 0, 4, 8,12);
        CHACHA20_QUARTERROUND( 1, 5, 9,13);
        CHACHA20_QUARTERROUND( 2, 6,10,14);
        CHACHA20_QUARTERROUND( 3, 7,11,15);
        CHACHA20_QUARTERROUND( 0, 5,10,15);
        CHACHA20_QUARTERROUND( 1, 6,11,12);
        CHACHA20_QUARTERROUND( 2, 7, 8,13);
        CHACHA20_QUARTERROUND( 3, 4, 9,14);
    }
    for (i = 0; i < 16; i++)
        x[i] += input[i];
    for (i = 0; i < 16; i++)
        chacha20_store_u32le(output + 4 * i, x[i]);
}

static void
chacha20_init(struct chacha20 *x, const void *key, const void *iv)
{
    static const char sigma[16] = "expand 32-byte k";
    const unsigned char *k = key;
    const unsigned char *p = iv;
    x->input[0]  = chacha20_load_u32le(sigma + 0);
    x->input[1]  = chacha20_load_u32le(sigma + 4);
    x->input[2]  = chacha20_load_u32le(sigma + 8);
    x->input[3]  = chacha20_load_u32le(sigma + 12);
    x->input[4]  = chacha20_load_u32le(k + 0);
    x->input[5]  = chacha20_load_u32le(k + 4);
    x->input[6]  = chacha20_load_u32le(k + 8);
    x->input[7]  = chacha20_load_u32le(k + 12);
    x->input[8]  = chacha20_load_u32le(k + 16);
    x->input[9]  = chacha20_load_u32le(k + 20);
    x->input[10] = chacha20_load_u32le(k + 24);
    x->input[11] = chacha20_load_u32le(k + 28);
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = chacha20_load_u32le(p + 0);
    x->input[15] = chacha20_load_u32le(p + 4);
    x->outlen = 0;
}

static void
chacha20_keystream_bytes(struct chacha20 *x, void *buf, size_t bytes)
{
    unsigned char *p = buf;

    while (x->outlen && bytes) {
        int i = 64 - x->outlen;
        *p++ = x->output[i];
        x->output[i] = 0;
        bytes--;
        x->outlen--;
    }

    while (bytes) {
        unsigned char *dest = bytes < 64 ? x->output : p;
        salsa20_wordtobyte(dest, x->input);
        if (!++x->input[12])
            x->input[13]++;
        if (bytes < 64) {
            size_t i;
            for (i = 0; i < bytes; i++) {
                p[i] = x->output[i];
                x->output[i] = 0;
            }
            x->outlen = 64 - bytes;
            return;
        }
        bytes -= 64;
        p += 64;
    }
}
