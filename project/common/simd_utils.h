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

/**
 * Compute sum of 2^(-register[i]) for HyperLogLog harmonic mean
 * This is the expensive part of HLL count estimation
 *
 * @param registers  HLL register array
 * @param len        Number of registers
 * @return Sum of 2^(-register[i])
 */
SIMD_INLINE double simd_hll_harmonic_sum(const uint8_t *registers, size_t len) {
    double sum = 0.0;

    /* Precomputed powers of 2^(-i) for i = 0..63 */
    static const double pow2_neg[64] = {
        1.0, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.015625, 0.0078125,
        0.00390625, 0.001953125, 0.0009765625, 0.00048828125,
        0.000244140625, 0.0001220703125, 6.103515625e-05, 3.0517578125e-05,
        1.52587890625e-05, 7.62939453125e-06, 3.814697265625e-06, 1.9073486328125e-06,
        9.5367431640625e-07, 4.76837158203125e-07, 2.384185791015625e-07, 1.1920928955078125e-07,
        5.9604644775390625e-08, 2.9802322387695312e-08, 1.4901161193847656e-08, 7.450580596923828e-09,
        3.725290298461914e-09, 1.862645149230957e-09, 9.313225746154785e-10, 4.656612873077393e-10,
        2.3283064365386963e-10, 1.1641532182693481e-10, 5.820766091346741e-11, 2.9103830456733704e-11,
        1.4551915228366852e-11, 7.275957614183426e-12, 3.637978807091713e-12, 1.8189894035458565e-12,
        9.094947017729282e-13, 4.547473508864641e-13, 2.2737367544323206e-13, 1.1368683772161603e-13,
        5.684341886080802e-14, 2.842170943040401e-14, 1.4210854715202004e-14, 7.105427357601002e-15,
        3.552713678800501e-15, 1.7763568394002505e-15, 8.881784197001252e-16, 4.440892098500626e-16,
        2.220446049250313e-16, 1.1102230246251565e-16, 5.551115123125783e-17, 2.7755575615628914e-17,
        1.3877787807814457e-17, 6.938893903907228e-18, 3.469446951953614e-18, 1.734723475976807e-18,
        8.673617379884035e-19, 4.336808689942018e-19, 2.168404344971009e-19, 1.0842021724855044e-19,
    };

    /* Unrolled loop for better pipelining */
    size_t i = 0;
    size_t len_unroll = len & ~3UL;

    for (; i < len_unroll; i += 4) {
        sum += pow2_neg[registers[i]];
        sum += pow2_neg[registers[i + 1]];
        sum += pow2_neg[registers[i + 2]];
        sum += pow2_neg[registers[i + 3]];
    }

    for (; i < len; i++) {
        sum += pow2_neg[registers[i]];
    }

    return sum;
}

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

/* ========================================================================== */
/*                           Batch Processing                                  */
/* ========================================================================== */

/**
 * Batch update HLL registers with multiple IPs
 * Amortizes function call overhead and improves cache locality
 *
 * @param registers  HLL register array (modified in place)
 * @param ips        Array of IP addresses (network byte order)
 * @param count      Number of IPs
 * @param p_mask     HLL register index mask (e.g., 0x3FFF for 16384 registers)
 * @param p_shift    HLL precision shift (e.g., 14 for 16384 registers)
 */
SIMD_INLINE void simd_hll_batch_add(uint8_t *registers,
                                     const uint32_t *ips,
                                     size_t count,
                                     uint32_t p_mask,
                                     uint32_t p_shift) {
    for (size_t i = 0; i < count; i++) {
        /* Hash IP to 64-bit value */
        uint32_t lo = simd_crc32c_u32(0x12345678, ips[i]);
        uint32_t hi = simd_crc32c_u32(0x87654321, ips[i]);
        uint64_t hash = ((uint64_t)hi << 32) | lo;

        /* Extract register index and value */
        uint32_t index = hash & p_mask;
        uint64_t remaining = hash >> p_shift;

        /* Count leading zeros + 1 */
        uint8_t rho = (remaining == 0) ? 64 : (uint8_t)(simd_clz64(remaining) + 1);
        if (rho > 63) rho = 63;

        /* Max update */
        if (rho > registers[index]) {
            registers[index] = rho;
        }
    }
}

#endif /* SIMD_UTILS_H */
