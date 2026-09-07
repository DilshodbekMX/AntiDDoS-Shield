#ifndef COMMON_SIPHASH_H
#define COMMON_SIPHASH_H

/*
 * SipHash-2-4 reference implementation (public domain).
 * Adapted from https://github.com/veorq/SipHash
 *
 * Used for cryptographic hashing in SYN cookie generation,
 * replacing CRC32C which is not collision-resistant.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SIPHASH_ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPHASH_ROUND          \
    do {                       \
        v0 += v1;              \
        v1 = SIPHASH_ROTL(v1, 13); \
        v1 ^= v0;             \
        v0 = SIPHASH_ROTL(v0, 32); \
        v2 += v3;              \
        v3 = SIPHASH_ROTL(v3, 16); \
        v3 ^= v2;             \
        v0 += v3;              \
        v3 = SIPHASH_ROTL(v3, 21); \
        v3 ^= v0;             \
        v2 += v1;              \
        v1 = SIPHASH_ROTL(v1, 17); \
        v1 ^= v2;             \
        v2 = SIPHASH_ROTL(v2, 32); \
    } while (0)

/**
 * SipHash-2-4: cryptographic PRF suitable for short inputs.
 *
 * @param data   Input data
 * @param len    Input length in bytes
 * @param key    128-bit key (two uint64_t values)
 * @return       64-bit hash
 */
static inline uint64_t siphash_2_4(const void *data, size_t len,
                                    const uint64_t key[2]) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
    uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
    uint64_t v3 = 0x7465646279746573ULL ^ key[1];

    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *end = p + (len & ~7ULL);
    uint64_t m;
    uint64_t b = ((uint64_t)len) << 56;

    while (p < end) {
        memcpy(&m, p, 8);
        v3 ^= m;
        SIPHASH_ROUND;
        SIPHASH_ROUND;
        v0 ^= m;
        p += 8;
    }

    /* Process remaining bytes */
    switch (len & 7) {
    case 7: b |= ((uint64_t)p[6]) << 48; /* fallthrough */
    case 6: b |= ((uint64_t)p[5]) << 40; /* fallthrough */
    case 5: b |= ((uint64_t)p[4]) << 32; /* fallthrough */
    case 4: b |= ((uint64_t)p[3]) << 24; /* fallthrough */
    case 3: b |= ((uint64_t)p[2]) << 16; /* fallthrough */
    case 2: b |= ((uint64_t)p[1]) << 8;  /* fallthrough */
    case 1: b |= ((uint64_t)p[0]);        break;
    case 0: break;
    }

    v3 ^= b;
    SIPHASH_ROUND;
    SIPHASH_ROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SIPHASH_ROUND;
    SIPHASH_ROUND;
    SIPHASH_ROUND;
    SIPHASH_ROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

#endif /* COMMON_SIPHASH_H */
