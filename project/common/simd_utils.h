/**
 * @file simd_utils.h
 * @brief SIMD utility functions for performance-critical operations
 *
 * This header provides SIMD-optimized implementations of common operations
 * used throughout the anti-DDoS system. Functions automatically fall back
 * to scalar implementations when SIMD is not available.
 *
 * Supported instruction sets:
 * - AVX2 (256-bit vectors)
 * - SSE4.2 (128-bit vectors + CRC32)
 * - Scalar fallback
 */

#ifndef SIMD_UTILS_H
#define SIMD_UTILS_H

#include <stdint.h>
#include <string.h>

/* Detect SIMD support */
#ifdef __AVX2__
#include <immintrin.h>
#define HAVE_AVX2 1
#else
#define HAVE_AVX2 0
#endif

#ifdef __SSE4_2__
#include <nmmintrin.h>
#define HAVE_SSE42 1
#else
#define HAVE_SSE42 0
#endif

/* Compiler hints */
#ifdef __GNUC__
#define SIMD_LIKELY(x)   __builtin_expect(!!(x), 1)
#define SIMD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define SIMD_INLINE      static inline __attribute__((always_inline))
#define SIMD_ALIGNED(n)  __attribute__((aligned(n)))
#else
#define SIMD_LIKELY(x)   (x)
#define SIMD_UNLIKELY(x) (x)
#define SIMD_INLINE      static inline
#define SIMD_ALIGNED(n)
#endif

/* ========================================================================== */
/*                           Memory Operations                                 */
/* ========================================================================== */

/**
 * Zero a buffer using SIMD when available
 * Optimized for buffers >= 32 bytes
 */
SIMD_INLINE void simd_memzero(void *dst, size_t len) {
#if HAVE_AVX2
    if (len >= 32) {
        __m256i zero = _mm256_setzero_si256();
        uint8_t *p = (uint8_t *)dst;
        size_t chunks = len / 32;

        for (size_t i = 0; i < chunks; i++) {
            _mm256_storeu_si256((__m256i *)(p + i * 32), zero);
        }

        /* Handle remaining bytes */
        size_t done = chunks * 32;
        if (len > done) {
            memset(p + done, 0, len - done);
        }
        return;
    }
#endif
    memset(dst, 0, len);
}

/**
 * Prefetch data for reading
 */
SIMD_INLINE void simd_prefetch_read(const void *addr) {
#ifdef __GNUC__
    __builtin_prefetch(addr, 0, 3);  /* Read, high temporal locality */
#endif
}

/**
 * Prefetch data for writing
 */
SIMD_INLINE void simd_prefetch_write(void *addr) {
#ifdef __GNUC__
    __builtin_prefetch(addr, 1, 3);  /* Write, high temporal locality */
#endif
}

/* ========================================================================== */
/*                           Byte Array Operations                             */
/* ========================================================================== */

/**
 * Find maximum value in a byte array using SIMD
 * Useful for HyperLogLog register scanning
 *
 * @param data  Pointer to byte array
 * @param len   Length of array (must be > 0)
 * @return Maximum byte value
 */
SIMD_INLINE uint8_t simd_max_u8(const uint8_t *data, size_t len) {
    if (SIMD_UNLIKELY(len == 0)) {
        return 0;
    }

    uint8_t max_val = 0;

#if HAVE_AVX2
    if (len >= 32) {
        __m256i max_vec = _mm256_setzero_si256();
        size_t chunks = len / 32;

        for (size_t i = 0; i < chunks; i++) {
            __m256i data_vec = _mm256_loadu_si256((const __m256i *)(data + i * 32));
            max_vec = _mm256_max_epu8(max_vec, data_vec);
        }

        /* Reduce 256-bit to scalar */
        __m128i max_lo = _mm256_castsi256_si128(max_vec);
        __m128i max_hi = _mm256_extracti128_si256(max_vec, 1);
        __m128i max128 = _mm_max_epu8(max_lo, max_hi);

        /* Further reduce 128-bit */
        max128 = _mm_max_epu8(max128, _mm_srli_si128(max128, 8));
        max128 = _mm_max_epu8(max128, _mm_srli_si128(max128, 4));
        max128 = _mm_max_epu8(max128, _mm_srli_si128(max128, 2));
        max128 = _mm_max_epu8(max128, _mm_srli_si128(max128, 1));
        max_val = (uint8_t)_mm_cvtsi128_si32(max128);

        /* Handle remaining bytes */
        for (size_t i = chunks * 32; i < len; i++) {
            if (data[i] > max_val) {
                max_val = data[i];
            }
        }
        return max_val;
    }
#endif

    /* Scalar fallback */
    for (size_t i = 0; i < len; i++) {
        if (data[i] > max_val) {
            max_val = data[i];
        }
    }
    return max_val;
}

/**
 * Count bytes equal to zero in an array using SIMD
 * Useful for HyperLogLog linear counting correction
 *
 * @param data  Pointer to byte array
 * @param len   Length of array
 * @return Number of zero bytes
 */
SIMD_INLINE uint32_t simd_count_zero_u8(const uint8_t *data, size_t len) {
    if (SIMD_UNLIKELY(len == 0)) {
        return 0;
    }

    uint32_t count = 0;

#if HAVE_AVX2
    if (len >= 32) {
        __m256i zero_vec = _mm256_setzero_si256();
        size_t chunks = len / 32;

        for (size_t i = 0; i < chunks; i++) {
            __m256i data_vec = _mm256_loadu_si256((const __m256i *)(data + i * 32));
            __m256i cmp = _mm256_cmpeq_epi8(data_vec, zero_vec);
            uint32_t mask = (uint32_t)_mm256_movemask_epi8(cmp);
            count += __builtin_popcount(mask);
        }

        /* Handle remaining bytes */
        for (size_t i = chunks * 32; i < len; i++) {
            if (data[i] == 0) {
                count++;
            }
        }
        return count;
    }
#endif

    /* Scalar fallback */
    for (size_t i = 0; i < len; i++) {
        if (data[i] == 0) {
            count++;
        }
    }
    return count;
}

/*
 * HyperLogLog: this header has no register update or estimator code. Every HLL
 * user goes through hll_add() and hll_count() in layer1/telemetry/hyperloglog.c,
 * which mix the key and count rho over the bits left after the register index.
 * The two copies that lived here, simd_hll_batch_add() and
 * simd_hll_harmonic_sum(), had no caller and were removed: the batch update
 * counted the index bits in rho (every register at least 15) and wrote unmixed
 * CRC keys, and the harmonic sum served the classic estimator that hll_count()
 * replaced. tests/unit/test_simd_utils.c fails to compile if either returns.
 */

/* ========================================================================== */
/*                           Bit Operations                                    */
/* ========================================================================== */

/**
 * Population count (number of set bits) for 64-bit value
 */
SIMD_INLINE int simd_popcount64(uint64_t x) {
#ifdef __GNUC__
    return __builtin_popcountll(x);
#else
    /* Fallback using Kernighan's algorithm */
    int count = 0;
    while (x) {
        x &= x - 1;
        count++;
    }
    return count;
#endif
}

/**
 * Count leading zeros for 64-bit value
 */
SIMD_INLINE int simd_clz64(uint64_t x) {
    if (x == 0) return 64;
#ifdef __GNUC__
    return __builtin_clzll(x);
#else
    /* Fallback using binary search */
    int n = 0;
    if ((x & 0xFFFFFFFF00000000ULL) == 0) { n += 32; x <<= 32; }
    if ((x & 0xFFFF000000000000ULL) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF00000000000000ULL) == 0) { n += 8;  x <<= 8;  }
    if ((x & 0xF000000000000000ULL) == 0) { n += 4;  x <<= 4;  }
    if ((x & 0xC000000000000000ULL) == 0) { n += 2;  x <<= 2;  }
    if ((x & 0x8000000000000000ULL) == 0) { n += 1; }
    return n;
#endif
}

/* ========================================================================== */
/*                           Hash Operations                                   */
/* ========================================================================== */

#if HAVE_SSE42

/**
 * CRC32C hash for 32-bit value using hardware intrinsics
 */
SIMD_INLINE uint32_t simd_crc32c_u32(uint32_t crc, uint32_t data) {
    return _mm_crc32_u32(crc, data);
}

/**
 * CRC32C hash for 64-bit value using hardware intrinsics
 */
SIMD_INLINE uint32_t simd_crc32c_u64(uint32_t crc, uint64_t data) {
    return (uint32_t)_mm_crc32_u64(crc, data);
}

#else

/**
 * Software CRC32C fallback (not used when SSE4.2 available)
 */
SIMD_INLINE uint32_t simd_crc32c_u32(uint32_t crc, uint32_t data) {
    /* Simple polynomial multiplication - not optimized */
    crc ^= data;
    for (int i = 0; i < 32; i++) {
        crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1));
    }
    return crc;
}

SIMD_INLINE uint32_t simd_crc32c_u64(uint32_t crc, uint64_t data) {
    crc = simd_crc32c_u32(crc, (uint32_t)data);
    crc = simd_crc32c_u32(crc, (uint32_t)(data >> 32));
    return crc;
}

#endif /* HAVE_SSE42 */

#endif /* SIMD_UTILS_H */
