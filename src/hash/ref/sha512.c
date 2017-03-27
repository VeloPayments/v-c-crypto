/**
 * \file hash/ref/sha512.c
 *
 * Reference implementation of SHA-512 as provided by LibreSSL.
 *
 * \copyright 2004 The OpenSSL Project (released under OpenSSL license),
 * with modifications copyright 2017 Velo Payments, Inc.  All rights reserved.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sha512.h"

/* forward decls */
static void sha512_block_data_order(SHA512_CTX* ctx, const void* in, size_t num);

/**
 * Initialize a SHA context for SHA-384 operation.
 *
 * \param c     The SHA context to initialize.
 */
void SHA384_Init(SHA512_CTX* c)
{
    c->h[0] = UINT64_C(0xcbbb9d5dc1059ed8);
    c->h[1] = UINT64_C(0x629a292a367cd507);
    c->h[2] = UINT64_C(0x9159015a3070dd17);
    c->h[3] = UINT64_C(0x152fecd8f70e5939);
    c->h[4] = UINT64_C(0x67332667ffc00b31);
    c->h[5] = UINT64_C(0x8eb44a8768581511);
    c->h[6] = UINT64_C(0xdb0c2e0d64f98fa7);
    c->h[7] = UINT64_C(0x47b5481dbefa4fa4);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA384_DIGEST_LENGTH;
}

/**
 * Initialize a SHA context for SHA-512 operation.
 *
 * \param c     The SHA context to initialize.
 */
void SHA512_Init(SHA512_CTX* c)
{
    c->h[0] = UINT64_C(0x6a09e667f3bcc908);
    c->h[1] = UINT64_C(0xbb67ae8584caa73b);
    c->h[2] = UINT64_C(0x3c6ef372fe94f82b);
    c->h[3] = UINT64_C(0xa54ff53a5f1d36f1);
    c->h[4] = UINT64_C(0x510e527fade682d1);
    c->h[5] = UINT64_C(0x9b05688c2b3e6c1f);
    c->h[6] = UINT64_C(0x1f83d9abfb41bd6b);
    c->h[7] = UINT64_C(0x5be0cd19137e2179);

    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    c->md_len = SHA512_DIGEST_LENGTH;
}

/**
 * Finalize a SHA-512 context and generate the final hash.
 *
 * \param c     The SHA-512 context to finalize.
 * \param md    A pointer to a buffer to hold the SHA-512 hash.  Must be at
 *              least 48 bytes in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int SHA512_Final(SHA512_CTX* c, uint8_t* md)
{
    uint8_t* p = (uint8_t*)c->u.p;
    size_t n = c->num;

    p[n] = 0x80; /* There always is a room for one */
    n++;
    if (n > (sizeof(c->u) - 16))
    {
        memset(p + n, 0, sizeof(c->u) - n);
        n = 0;
        sha512_block_data_order(c, p, 1);
    }

    memset(p + n, 0, sizeof(c->u) - 16 - n);

    p[sizeof(c->u) - 1] = (uint8_t)(c->Nl);
    p[sizeof(c->u) - 2] = (uint8_t)(c->Nl >> 8);
    p[sizeof(c->u) - 3] = (uint8_t)(c->Nl >> 16);
    p[sizeof(c->u) - 4] = (uint8_t)(c->Nl >> 24);
    p[sizeof(c->u) - 5] = (uint8_t)(c->Nl >> 32);
    p[sizeof(c->u) - 6] = (uint8_t)(c->Nl >> 40);
    p[sizeof(c->u) - 7] = (uint8_t)(c->Nl >> 48);
    p[sizeof(c->u) - 8] = (uint8_t)(c->Nl >> 56);
    p[sizeof(c->u) - 9] = (uint8_t)(c->Nh);
    p[sizeof(c->u) - 10] = (uint8_t)(c->Nh >> 8);
    p[sizeof(c->u) - 11] = (uint8_t)(c->Nh >> 16);
    p[sizeof(c->u) - 12] = (uint8_t)(c->Nh >> 24);
    p[sizeof(c->u) - 13] = (uint8_t)(c->Nh >> 32);
    p[sizeof(c->u) - 14] = (uint8_t)(c->Nh >> 40);
    p[sizeof(c->u) - 15] = (uint8_t)(c->Nh >> 48);
    p[sizeof(c->u) - 16] = (uint8_t)(c->Nh >> 56);

    sha512_block_data_order(c, p, 1);

    /* return an error if the message digest buffer is null. */
    if (md == 0)
    {
        return 1;
    }

    switch (c->md_len)
    {
        /* Let compiler decide if it's appropriate to unroll... */
        case SHA384_DIGEST_LENGTH:
            for (n = 0; n < SHA384_DIGEST_LENGTH / 8; n++)
            {
                uint64_t t = c->h[n];

                *(md++) = (uint8_t)(t >> 56);
                *(md++) = (uint8_t)(t >> 48);
                *(md++) = (uint8_t)(t >> 40);
                *(md++) = (uint8_t)(t >> 32);
                *(md++) = (uint8_t)(t >> 24);
                *(md++) = (uint8_t)(t >> 16);
                *(md++) = (uint8_t)(t >> 8);
                *(md++) = (uint8_t)(t);
            }
            break;

        case SHA512_DIGEST_LENGTH:
            for (n = 0; n < SHA512_DIGEST_LENGTH / 8; n++)
            {
                uint64_t t = c->h[n];

                *(md++) = (uint8_t)(t >> 56);
                *(md++) = (uint8_t)(t >> 48);
                *(md++) = (uint8_t)(t >> 40);
                *(md++) = (uint8_t)(t >> 32);
                *(md++) = (uint8_t)(t >> 24);
                *(md++) = (uint8_t)(t >> 16);
                *(md++) = (uint8_t)(t >> 8);
                *(md++) = (uint8_t)(t);
            }
            break;

        /* unsupported message digest length. */
        default:
            return 1;
    }

    return 0;
}

/**
 * Finalize a SHA-384 context and generate the final hash.
 *
 * \param c     The SHA-384 context to finalize.
 * \param md    A pointer to a buffer to hold the SHA-384 hash.  Must be at
 *              least 48 bytes in length.
 *
 * \returns 0 on success and non-zero on failure.
 */
int SHA384_Final(SHA512_CTX* c, uint8_t* md)
{
    return SHA512_Final(c, md);
}

/**
 * Add the given data to a SHA-512 context.
 *
 * \param c     The SHA-512 context to update.
 * \param data  A pointer to the data to digest.
 * \param len   The length of the data to digest.
 */
void SHA512_Update(SHA512_CTX* c, const void* _data, size_t len)
{
    uint64_t l;
    uint8_t* p = c->u.p;
    const uint8_t* data = (const uint8_t*)_data;

    /* nothing to be done for no data. */
    if (len == 0)
    {
        return;
    }

    l = (c->Nl + (((uint64_t)len) << 3)) & UINT64_C(0xffffffffffffffff);

    if (l < c->Nl)
    {
        c->Nh++;
    }

    if (sizeof(len) >= 8)
    {
        c->Nh += (((uint64_t)len) >> 61);
    }

    c->Nl = l;

    if (c->num != 0)
    {
        size_t n = sizeof(c->u) - c->num;

        if (len < n)
        {
            memcpy(p + c->num, data, len);
            c->num += (unsigned int)len;

            return;
        }
        else
        {
            memcpy(p + c->num, data, n);
            c->num = 0;
            len -= n;
            data += n;
            sha512_block_data_order(c, p, 1);
        }
    }

    if (len >= sizeof(c->u))
    {
        sha512_block_data_order(c, data, len / sizeof(c->u));
        data += len;
        len %= sizeof(c->u);
        data -= len;
    }

    if (len != 0)
    {
        memcpy(p, data, len);
        c->num = (int)len;
    }

    return;
}

/**
 * Add the given data to a SHA-384 context.
 *
 * \param c     The SHA-384 context to update.
 * \param data  A pointer to the data to digest.
 * \param len   The length of the data to digest.
 */
void SHA384_Update(SHA512_CTX* c, const void* data, size_t len)
{
    SHA512_Update(c, data, len);
}

/**
 * Constants for the SHA-512 block operation.
 */
static const uint64_t K512[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

#if defined(__GNUC__) && __GNUC__ >= 2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#if defined(__x86_64) || defined(__x86_64__)
#define ROTR(a, n) ({ uint64_t ret;        \
                asm ("rorq %1,%0"    \
                : "=r"(ret)        \
                : "J"(n),"0"(a)        \
                : "cc"); ret; })
#define PULL64(x) ({ uint64_t ret=*((const uint64_t *)(&(x)));    \
                asm ("bswapq    %0"        \
                : "=r"(ret)            \
                : "0"(ret)); ret; })
#elif (defined(__i386) || defined(__i386__))
#define PULL64(x) ({ const unsigned int *p=(const unsigned int *)(&(x));\
             unsigned int hi=p[0],lo=p[1];        \
                asm ("bswapl %0; bswapl %1;"    \
                : "=r"(lo),"=r"(hi)        \
                : "0"(lo),"1"(hi));        \
                ((uint64_t)hi)<<32|lo; })
#elif (defined(_ARCH_PPC) && defined(__64BIT__)) || defined(_ARCH_PPC64)
#define ROTR(a, n) ({ uint64_t ret;        \
                asm ("rotrdi %0,%1,%2"    \
                : "=r"(ret)        \
                : "r"(a),"K"(n)); ret; })
#endif
#endif

#ifndef PULL64
#define B(x, j) (((uint64_t)(*(((const uint8_t*)(&x)) + j))) << ((7 - j) * 8))
#define PULL64(x) (B(x, 0) | B(x, 1) | B(x, 2) | B(x, 3) | B(x, 4) | B(x, 5) | B(x, 6) | B(x, 7))
#endif

#ifndef ROTR
#define ROTR(x, s) (((x) >> s) | (x) << (64 - s))
#endif

#define Sigma0(x) (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define Sigma1(x) (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define sigma0(x) (ROTR((x), 1) ^ ROTR((x), 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR((x), 19) ^ ROTR((x), 61) ^ ((x) >> 6))

#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))


#if defined(__i386) || defined(__i386__) || defined(_M_IX86)
/*
 * This code should give better results on 32-bit CPU with less than
 * ~24 registers, both size and performance wise...
 */
static void sha512_block_data_order(SHA512_CTX* ctx, const void* in, size_t num)
{
    const uint64_t* W = in;
    uint64_t A, E, T;
    uint64_t X[9 + 80], *F;
    int i;

    while (num--)
    {
        F = X + 80;
        A = ctx->h[0];
        F[1] = ctx->h[1];
        F[2] = ctx->h[2];
        F[3] = ctx->h[3];
        E = ctx->h[4];
        F[5] = ctx->h[5];
        F[6] = ctx->h[6];
        F[7] = ctx->h[7];

        for (i = 0; i < 16; i++, F--)
        {
            T = PULL64(W[i]);
            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        for (; i < 80; i++, F--)
        {
            T = sigma0(F[8 + 16 - 1]);
            T += sigma1(F[8 + 16 - 14]);
            T += F[8 + 16] + F[8 + 16 - 9];

            F[0] = A;
            F[4] = E;
            F[8] = T;
            T += F[7] + Sigma1(E) + Ch(E, F[5], F[6]) + K512[i];
            E = F[3] + T;
            A = T + Sigma0(A) + Maj(A, F[1], F[2]);
        }

        ctx->h[0] += A;
        ctx->h[1] += F[1];
        ctx->h[2] += F[2];
        ctx->h[3] += F[3];
        ctx->h[4] += E;
        ctx->h[5] += F[5];
        ctx->h[6] += F[6];
        ctx->h[7] += F[7];

        W += 16;
    }
}

#elif defined(SMALL_FOOTPRINT)

static void sha512_block_data_order(SHA512_CTX* ctx, const void* in, size_t num)
{
    const SHA_LONG64* W = in;
    uint64_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    uint64_t X[16];
    int i;

    while (num--)
    {
        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        for (i = 0; i < 16; i++)
        {
            T1 = X[i] = PULL64(W[i]);
            T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        for (; i < 80; i++)
        {
            s0 = X[(i + 1) & 0x0f];
            s0 = sigma0(s0);
            s1 = X[(i + 14) & 0x0f];
            s1 = sigma1(s1);

            T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
            T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i];
            T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        W += 16;
    }
}

#else

#define ROUND_00_15(i, a, b, c, d, e, f, g, h) \
    do \
    { \
        T1 += h + Sigma1(e) + Ch(e, f, g) + K512[i]; \
        h = Sigma0(a) + Maj(a, b, c); \
        d += T1; \
        h += T1; \
    } while (0)

#define ROUND_16_80(i, j, a, b, c, d, e, f, g, h, X) \
    do \
    { \
        s0 = X[(j + 1) & 0x0f]; \
        s0 = sigma0(s0); \
        s1 = X[(j + 14) & 0x0f]; \
        s1 = sigma1(s1); \
        T1 = X[(j)&0x0f] += s0 + s1 + X[(j + 9) & 0x0f]; \
        ROUND_00_15(i + j, a, b, c, d, e, f, g, h); \
    } while (0)

static void sha512_block_data_order(SHA512_CTX* ctx, const void* in, size_t num)
{
    const uint64_t* W = in;
    uint64_t a, b, c, d, e, f, g, h, s0, s1, T1;
    uint64_t X[16];
    int i;

    while (num--)
    {
        a = ctx->h[0];
        b = ctx->h[1];
        c = ctx->h[2];
        d = ctx->h[3];
        e = ctx->h[4];
        f = ctx->h[5];
        g = ctx->h[6];
        h = ctx->h[7];

        T1 = X[0] = PULL64(W[0]);
        ROUND_00_15(0, a, b, c, d, e, f, g, h);
        T1 = X[1] = PULL64(W[1]);
        ROUND_00_15(1, h, a, b, c, d, e, f, g);
        T1 = X[2] = PULL64(W[2]);
        ROUND_00_15(2, g, h, a, b, c, d, e, f);
        T1 = X[3] = PULL64(W[3]);
        ROUND_00_15(3, f, g, h, a, b, c, d, e);
        T1 = X[4] = PULL64(W[4]);
        ROUND_00_15(4, e, f, g, h, a, b, c, d);
        T1 = X[5] = PULL64(W[5]);
        ROUND_00_15(5, d, e, f, g, h, a, b, c);
        T1 = X[6] = PULL64(W[6]);
        ROUND_00_15(6, c, d, e, f, g, h, a, b);
        T1 = X[7] = PULL64(W[7]);
        ROUND_00_15(7, b, c, d, e, f, g, h, a);
        T1 = X[8] = PULL64(W[8]);
        ROUND_00_15(8, a, b, c, d, e, f, g, h);
        T1 = X[9] = PULL64(W[9]);
        ROUND_00_15(9, h, a, b, c, d, e, f, g);
        T1 = X[10] = PULL64(W[10]);
        ROUND_00_15(10, g, h, a, b, c, d, e, f);
        T1 = X[11] = PULL64(W[11]);
        ROUND_00_15(11, f, g, h, a, b, c, d, e);
        T1 = X[12] = PULL64(W[12]);
        ROUND_00_15(12, e, f, g, h, a, b, c, d);
        T1 = X[13] = PULL64(W[13]);
        ROUND_00_15(13, d, e, f, g, h, a, b, c);
        T1 = X[14] = PULL64(W[14]);
        ROUND_00_15(14, c, d, e, f, g, h, a, b);
        T1 = X[15] = PULL64(W[15]);
        ROUND_00_15(15, b, c, d, e, f, g, h, a);

        for (i = 16; i < 80; i += 16)
        {
            ROUND_16_80(i, 0, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 1, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 2, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 3, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 4, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 5, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 6, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 7, b, c, d, e, f, g, h, a, X);
            ROUND_16_80(i, 8, a, b, c, d, e, f, g, h, X);
            ROUND_16_80(i, 9, h, a, b, c, d, e, f, g, X);
            ROUND_16_80(i, 10, g, h, a, b, c, d, e, f, X);
            ROUND_16_80(i, 11, f, g, h, a, b, c, d, e, X);
            ROUND_16_80(i, 12, e, f, g, h, a, b, c, d, X);
            ROUND_16_80(i, 13, d, e, f, g, h, a, b, c, X);
            ROUND_16_80(i, 14, c, d, e, f, g, h, a, b, X);
            ROUND_16_80(i, 15, b, c, d, e, f, g, h, a, X);
        }

        ctx->h[0] += a;
        ctx->h[1] += b;
        ctx->h[2] += c;
        ctx->h[3] += d;
        ctx->h[4] += e;
        ctx->h[5] += f;
        ctx->h[6] += g;
        ctx->h[7] += h;

        W += 16;
    }
}

#endif
