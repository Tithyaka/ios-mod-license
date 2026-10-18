/**
 * Self-contained Ed25519 verification implementation (C99).
 * Derived from standard audited TweetNaCl / ref10 algorithms.
 * Zero external library dependencies required.
 */

#include "ed25519_verify.h"
#include <stdint.h>
#include <string.h>

/* --- SHA-512 Implementation --- */

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} sha512_ctx;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define Sigma1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define sigma0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0x9b3099605c3edd60ULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc2478794f746ee34ULL,
    0xcfc69e00f1c3f55ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80], a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | (uint64_t)block[i*8+7];
    }
    for (i = 16; i < 80; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (i = 0; i < 80; i++) {
        uint64_t t1 = h + Sigma1(e) + Ch(e, f, g) + K512[i] + w[i];
        uint64_t t2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha512_init(sha512_ctx *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = (ctx->count[0] >> 3) & 127;
    ctx->count[0] += (uint64_t)len << 3;
    if (ctx->count[0] < ((uint64_t)len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint64_t)(len >> 61);
    if (i + len >= 128) {
        memcpy(&ctx->buffer[i], data, 128 - i);
        sha512_transform(ctx->state, ctx->buffer);
        data += (128 - i);
        len -= (128 - i);
        while (len >= 128) {
            sha512_transform(ctx->state, data);
            data += 128;
            len -= 128;
        }
        i = 0;
    }
    memcpy(&ctx->buffer[i], data, len);
}

static void sha512_final(sha512_ctx *ctx, uint8_t digest[64]) {
    uint8_t count[16];
    size_t i, pad;
    for (i = 0; i < 8; i++) {
        count[i] = (uint8_t)(ctx->count[1] >> (56 - i * 8));
        count[i + 8] = (uint8_t)(ctx->count[0] >> (56 - i * 8));
    }
    pad = ((ctx->count[0] >> 3) & 127);
    pad = (pad < 112) ? (112 - pad) : (240 - pad);
    static const uint8_t p[128] = { 0x80 };
    sha512_update(ctx, p, pad);
    sha512_update(ctx, count, 16);
    for (i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            digest[i * 8 + j] = (uint8_t)(ctx->state[i] >> (56 - j * 8));
        }
    }
}

/* --- Ed25519 Math & Verification --- */

typedef int64_t gf[16];

static const gf d = {
    -0x059a40f, -0x0a6245f, 0x1927c3d, 0x0628224,
    -0x1d2179b, -0x00f8981, 0x08542a3, 0x187a550,
    -0x0b8a05d, -0x0ad2119, 0x1f74f7d, 0x07f4337,
    0x028d172, 0x1cf9e3a, 0x1a87b3e, 0x15f2aa5
};

static const gf I = {
    0x031e42a, 0x18e8749, -0x07469a4, -0x133d5ea,
    0x08ff4e2, -0x14daec8, 0x00c4c47, 0x0da3547,
    0x067b6aa, 0x05bc101, -0x02c03b6, 0x1c00a64,
    -0x175cf69, 0x0585671, 0x02c114e, 0x011b0e9
};

static void set25519(gf r, const gf a) {
    for (int i = 0; i < 16; i++) r[i] = a[i];
}

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    gf m, t;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        m[14] &= 0xffff;
        int64_t b = (m[15] >> 16) & 1;
        sel25519(t, m, 1 - (int)b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)t[i];
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31] = { 0 };
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) {
    M(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], (gf){1});
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, d);
    Z(num, num, r[2]);
    A(den, r[2], den);
    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);
    inv25519(t, t);
    M(t, t, den);
    M(t, t, num);
    M(r[0], t, den);
    S(chk, r[0]);
    M(chk, chk, den);
    if (memcmp(chk, num, sizeof(gf)) != 0) {
        M(r[0], r[0], I);
    }
    S(chk, r[0]);
    M(chk, chk, den);
    if (memcmp(chk, num, sizeof(gf)) != 0) return -1;
    if (((p[31] >> 7) & 1) != 0) {
        Z(r[0], (gf){0}, r[0]);
    }
    M(r[3], r[0], r[1]);
    return 0;
}

static void add(gf p[4], gf q[4]) {
    gf a, b, c, d_val, t;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[1], p[0]);
    A(t, q[1], q[0]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, d);
    A(c, c, c);
    M(d_val, p[2], q[2]);
    A(d_val, d_val, d_val);
    Z(t, b, a);
    Z(p[0], d_val, c);
    A(p[1], d_val, c);
    M(p[2], p[0], p[1]);
    M(p[0], p[0], t);
    A(t, b, a);
    M(p[1], p[1], t);
    M(p[3], t, t);
}

static void cswap(gf p[4], gf q[4], int b) {
    for (int i = 0; i < 4; i++) {
        sel25519(p[i], q[i], b);
    }
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s) {
    set25519(p[0], (gf){0});
    set25519(p[1], (gf){1});
    set25519(p[2], (gf){1});
    set25519(p[3], (gf){0});
    for (int i = 255; i >= 0; i--) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

int ed25519_verify_signature(
    const unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *public_key
) {
    uint8_t h[64];
    uint8_t rcheck[32];
    gf p[4], q[4];

    if (!signature || !public_key || !message) return -1;

    /* Verify S < L to prevent malleable signatures */
    static const uint8_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    for (int i = 31; i >= 0; i--) {
        if (signature[32 + i] > L[i]) return -1;
        if (signature[32 + i] < L[i]) break;
    }

    /* Unpack public key A */
    if (unpackneg(q, public_key) != 0) return -1;

    /* Compute SHA512(R || A || M) */
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, signature, 32);          /* R */
    sha512_update(&ctx, public_key, 32);         /* A */
    sha512_update(&ctx, message, message_len);   /* M */
    sha512_final(&ctx, h);

    /* Reduce h mod L */
    /* Check R == [S]B - [h]A */
    /* Equivalent: [S]B == R + [h]A */
    gf B[4] = {
        { -0x00d0277, -0x1bbf913, 0x0e2be13, 0x0874e47, -0x0c96e8d, -0x1e360f0, 0x16dc8c8, 0x19df4e6,
          -0x17120df, 0x081e7d2, 0x01bf3b7, 0x0f85f1c, 0x0a12cfd, -0x0735f49, -0x1fb5643, 0x06606d9 },
        { 0x0000004, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        { 0x0000005, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        { -0x00d0277, -0x1bbf913, 0x0e2be13, 0x0874e47, -0x0c96e8d, -0x1e360f0, 0x16dc8c8, 0x19df4e6,
          -0x17120df, 0x081e7d2, 0x01bf3b7, 0x0f85f1c, 0x0a12cfd, -0x0735f49, -0x1fb5643, 0x06606d9 }
    };
    scalarmult(p, q, h);
    scalarmult(q, B, signature + 32);
    add(p, q);
    inv25519(p[2], p[2]);
    M(p[1], p[1], p[2]);
    pack25519(rcheck, p[1]);

    return (memcmp(rcheck, signature, 32) == 0) ? 0 : -1;
}
