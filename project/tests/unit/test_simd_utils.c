/**
 * @file test_simd_utils.c
 * @brief common/simd_utils.h compiles, its helpers match scalar references, and
 *        it carries no second HyperLogLog implementation.
 *
 * Nothing else includes simd_utils.h, so this is the only build that compiles it.
 * The header used to define simd_hll_batch_add(), an HLL register update that
 * counted the index bits in rho and wrote unmixed CRC keys, and
 * simd_hll_harmonic_sum(), the classic estimator's sum. Every HLL user must go
 * through hll_add() and hll_count(). The enum below reuses both names, so this
 * file stops compiling if either function comes back.
 *
 * Pure C, no DPDK. The vector paths run when the build targets AVX2 / SSE4.2
 * (-march=native), the scalar fallbacks otherwise.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common/simd_utils.h"

enum removed_hll_helpers {
    simd_hll_batch_add = 0,
    simd_hll_harmonic_sum = 0,
};

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(expr, msg) do { \
    tests_run++; \
    if (!(expr)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
    } \
} while (0)

static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static uint64_t next_rand(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

// Reflected CRC32-C (polynomial 0x82F63B78), no pre- or post-inversion: what
// the SSE4.2 crc32 instruction computes
static uint32_t ref_crc32c_u32(uint32_t crc, uint32_t data) {
    crc ^= data;
    for (int i = 0; i < 32; i++) {
        crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
    }
    return crc;
}

static int ref_clz64(uint64_t x) {
    int n = 0;
    for (uint64_t bit = 1ULL << 63; bit != 0 && !(x & bit); bit >>= 1) {
        n++;
    }
    return n;
}

static int ref_popcount64(uint64_t x) {
    int n = 0;
    for (; x; x >>= 1) {
        n += (int)(x & 1);
    }
    return n;
}

#define BUF_LEN 16384u  // one HLL register array

static uint8_t g_buf[BUF_LEN + 64];

int main(void) {
    printf("simd_utils.h: AVX2 %d, SSE4.2 %d\n", HAVE_AVX2, HAVE_SSE42);

    // Lengths around the 32-byte vector width, at every alignment offset
    int memzero_bad = 0, max_bad = 0, zero_bad = 0;
    for (size_t off = 0; off < 32; off++) {
        for (size_t len = 0; len <= 100; len++) {
            for (size_t i = 0; i < sizeof(g_buf); i++) {
                g_buf[i] = (uint8_t)(next_rand() | 1);  // no zero bytes
            }
            simd_memzero(g_buf + off, len);
            for (size_t i = 0; i < sizeof(g_buf); i++) {
                int inside = i >= off && i < off + len;
                if ((g_buf[i] == 0) != inside) {
                    memzero_bad++;
                    break;
                }
            }

            for (size_t i = 0; i < len; i++) {
                uint64_t r = next_rand();
                g_buf[off + i] = (r & 3) == 0 ? 0 : (uint8_t)(r >> 8);
            }
            uint8_t want_max = 0;
            uint32_t want_zero = 0;
            for (size_t i = 0; i < len; i++) {
                if (g_buf[off + i] > want_max) want_max = g_buf[off + i];
                want_zero += g_buf[off + i] == 0;
            }
            max_bad += simd_max_u8(g_buf + off, len) != want_max;
            zero_bad += simd_count_zero_u8(g_buf + off, len) != want_zero;
        }
    }
    CHECK(memzero_bad == 0, "simd_memzero clears exactly [p, p + len)");
    CHECK(max_bad == 0, "simd_max_u8 matches the scalar maximum");
    CHECK(zero_bad == 0, "simd_count_zero_u8 matches the scalar count");

    // A whole register array, the size the HLL helpers were written for
    for (size_t i = 0; i < BUF_LEN; i++) {
        g_buf[i] = (uint8_t)(next_rand() % 52);
    }
    uint8_t want_max = 0;
    uint32_t want_zero = 0;
    for (size_t i = 0; i < BUF_LEN; i++) {
        if (g_buf[i] > want_max) want_max = g_buf[i];
        want_zero += g_buf[i] == 0;
    }
    CHECK(simd_max_u8(g_buf, BUF_LEN) == want_max, "simd_max_u8 over 16384 bytes");
    CHECK(simd_count_zero_u8(g_buf, BUF_LEN) == want_zero, "simd_count_zero_u8 over 16384 bytes");

    int bit_bad = 0, crc_bad = 0;
    for (int i = 0; i < 100000; i++) {
        uint64_t x = next_rand() >> (next_rand() % 64);  // every leading-zero count
        if (i == 0) x = 0;
        bit_bad += simd_clz64(x) != (x ? ref_clz64(x) : 64);
        bit_bad += simd_popcount64(x) != ref_popcount64(x);

        uint32_t crc = (uint32_t)next_rand();
        uint32_t want32 = ref_crc32c_u32(crc, (uint32_t)x);
        uint32_t want64 = ref_crc32c_u32(ref_crc32c_u32(crc, (uint32_t)x), (uint32_t)(x >> 32));
        crc_bad += simd_crc32c_u32(crc, (uint32_t)x) != want32;
        crc_bad += simd_crc32c_u64(crc, x) != want64;
    }
    CHECK(bit_bad == 0, "simd_clz64 and simd_popcount64 match bit loops");
    CHECK(crc_bad == 0, "simd_crc32c_u32 and simd_crc32c_u64 match the bitwise CRC32-C");

    printf("checks run: %d, failed: %d\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
