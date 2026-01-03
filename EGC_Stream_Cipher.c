/*
 * EGC-Stream: Expander-Graph-Based Stream Cipher
 * Reference Implementation in C 
 *
 * Copyright (c) 2025 W.A. Susantha Wijesinghe
 * Department of Electronics, Wayamba University of Sri Lanka
 *
 * 03rd January 2026
 *
 * This code accompanies the paper:
 *     W.A. Susantha Wijesinghe, "EGC-Stream: Design, Cryptanalysis, and 
 *     Hardware Evaluation of an Expander-Graph–Based Stream Cipher,"
 *     IEEE Transactions on Information Forensics and Security, 2025
 *     (submitted for publication)
 *
 * License: MIT License
 * Repository: https://github.com/yourusername/egc-stream
 *
 * ============================================================================
 * ALGORITHM OVERVIEW
 * ============================================================================
 *
 * EGC-Stream is a synchronous stream cipher with:
 * - 128-bit key and 128-bit nonce
 * - 128-bit internal state (64-bit primary + 64-bit LFSR)
 * - 4-regular Cayley graph topology on Z_64
 * - 256-round initialization, 1-bit-per-cycle output
 *
 * See paper Section 3 for complete specification.
 *
 * ============================================================================
 * SECURITY NOTICE
 * ============================================================================
 *
 * This is a REFERENCE IMPLEMENTATION for research purposes.
 * DO NOT use for protecting real-world data without:
 *   1. Independent security audit
 *   2. Side-channel attack analysis
 *   3. Constant-time implementation review
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define PRIMARY_N 64
#define LFSR_N    64
#define WARMUP_ROUNDS 256

/* Rule-A LUT (0x036F) */
static const uint8_t RULE_A_LUT[16] = {
    1, 1, 1, 1,
    0, 1, 1, 0,
    1, 1, 0, 0,
    0, 0, 0, 0
};

/* PI constants (32-bit words) */
static const uint32_t PI_CONSTANTS[16] = {
    0x243F6A88u, 0x85A308D3u, 0x13198A2Eu, 0x03707344u,
    0xA4093822u, 0x299F31D0u, 0x082EFA98u, 0xEC4E6C89u,
    0x452821E6u, 0x38D01377u, 0xBE5466CFu, 0x34E90C6Cu,
    0xC0AC29B7u, 0xC97C50DDu, 0x3F84D5B5u, 0xB5470917u
};

typedef struct {
    uint8_t primary[PRIMARY_N]; /* bits 0/1 */
    uint8_t lfsr[LFSR_N];       /* bits 0/1 */
} egc_hw_t;

/* --- Helpers --- */

static uint8_t rule_a(uint8_t x0, uint8_t x1, uint8_t x2, uint8_t x3) {
    uint8_t idx = (x0 & 1u) | ((x1 & 1u) << 1) | ((x2 & 1u) << 2) | ((x3 & 1u) << 3);
    return RULE_A_LUT[idx] & 1u;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    c = (char)toupper((unsigned char)c);
    if (c >= 'A' && c <= 'F') return 10 + (int)(c - 'A');
    return -1;
}

static void hex_to_bits_128(const char *hex_in, uint8_t bits_out[128]) {
    char clean[256];
    size_t w = 0;
    size_t i;

    for (i = 0; hex_in[i] != '\0' && w + 1 < sizeof(clean); i++) {
        char c = hex_in[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        if (c == '0' && (hex_in[i+1] == 'x' || hex_in[i+1] == 'X')) {
            i += 1;
            continue;
        }
        if (isxdigit((unsigned char)c)) {
            clean[w++] = c;
        }
    }
    clean[w] = '\0';

    char z[33];
    size_t clen = strlen(clean);
    if (clen >= 32) {
        memcpy(z, clean + (clen - 32), 32);
        z[32] = '\0';
    } else {
        size_t pad = 32 - clen;
        for (i = 0; i < pad; i++) z[i] = '0';
        memcpy(z + pad, clean, clen);
        z[32] = '\0';
    }

    /* parse 16 bytes */
    uint8_t bytes[16];
    for (i = 0; i < 16; i++) {
        int hi = hex_nibble(z[2*i]);
        int lo = hex_nibble(z[2*i + 1]);
        if (hi < 0) hi = 0;
        if (lo < 0) lo = 0;
        bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    /* bytes -> bits, MSB first */
    size_t b = 0;
    for (i = 0; i < 16; i++) {
        int bp;
        for (bp = 7; bp >= 0; bp--) {
            bits_out[b++] = (uint8_t)((bytes[i] >> bp) & 1u);
        }
    }
}

static void bits_to_hex(const uint8_t *bits, size_t nbits, char *hex_out /* must fit 2*(nbits/8)+1 */) {
    size_t i, j;
    size_t out = 0;
    for (i = 0; i < nbits; i += 8) {
        uint8_t byte_val = 0;
        for (j = 0; j < 8; j++) {
            byte_val = (uint8_t)((byte_val << 1) | (bits[i + j] & 1u));
        }
        static const char HEX[] = "0123456789ABCDEF";
        hex_out[out++] = HEX[(byte_val >> 4) & 0xFu];
        hex_out[out++] = HEX[byte_val & 0xFu];
    }
    hex_out[out] = '\0';
}

static void lfsr_update(egc_hw_t *st) {
    uint8_t fb = (uint8_t)((st->lfsr[0] ^ st->lfsr[1] ^ st->lfsr[3] ^ st->lfsr[4]) & 1u);
    memmove(&st->lfsr[0], &st->lfsr[1], LFSR_N - 1);
    st->lfsr[LFSR_N - 1] = fb;
}

static void primary_update(const egc_hw_t *st, uint8_t new_primary[PRIMARY_N]) {
    int i;
    for (i = 0; i < PRIMARY_N; i++) {
        int i0 = i;
        int i1 = (i - 1 + PRIMARY_N) % PRIMARY_N;
        int i2 = (i + 1) % PRIMARY_N;
        int i3 = (i + 16) % PRIMARY_N;
        new_primary[i] = rule_a(st->primary[i0], st->primary[i1], st->primary[i2], st->primary[i3]);
    }
}

static void cipher_init(egc_hw_t *st, const uint8_t key_bits[128], const uint8_t nonce_bits[128]) {
    const uint8_t *key_high   = &key_bits[0];
    const uint8_t *key_low    = &key_bits[64];
    const uint8_t *nonce_high = &nonce_bits[0];
    const uint8_t *nonce_low  = &nonce_bits[64];

    uint8_t lfsr[64];
    uint8_t primary[64];

    int i;
    for (i = 0; i < 64; i++) {
        int const_word_idx = i / 32;
        int const_bit_idx  = i % 32;
        uint8_t const_bit = (uint8_t)((PI_CONSTANTS[const_word_idx] >> (31 - const_bit_idx)) & 1u);

        uint8_t pos_bit0 = (uint8_t)((i >> 0) & 1);
        uint8_t pos_bit1 = (uint8_t)((i >> 1) & 1);
        uint8_t pos_bit2 = (uint8_t)((i >> 2) & 1);
        uint8_t pos_bit3 = (uint8_t)((i >> 3) & 1);

        uint8_t bit_val = 0;
        bit_val ^= key_high[i] & 1u;
        bit_val ^= key_high[(i + 7) % 64] & 1u;
        bit_val ^= key_low[i] & 1u;
        bit_val ^= nonce_high[i] & 1u;
        bit_val ^= nonce_high[(i + 13) % 64] & 1u;
        bit_val ^= nonce_low[(i + 23) % 64] & 1u;
        bit_val ^= const_bit & 1u;

        bit_val ^= (uint8_t)((key_high[i] & nonce_high[i]) & 1u);
        bit_val ^= (uint8_t)((key_low[(i + 31) % 64] & nonce_low[(i + 37) % 64]) & 1u);

        bit_val ^= (uint8_t)((pos_bit0 & key_high[i]) & 1u);
        bit_val ^= (uint8_t)((pos_bit1 & nonce_high[i]) & 1u);
        bit_val ^= (uint8_t)((pos_bit2 & key_low[i] & nonce_low[i]) & 1u);

        {
            uint8_t or_term = (uint8_t)((key_high[(i + 1) % 64] | nonce_high[(i + 1) % 64]) & 1u);
            bit_val ^= (uint8_t)((pos_bit3 & or_term) & 1u);
        }

        lfsr[i] = (uint8_t)(bit_val & 1u);
    }

    for (i = 0; i < 64; i++) {
        int const_word_idx = (i + 2) / 32;
        int const_bit_idx  = (i + 2) % 32;
        uint8_t const_bit = (uint8_t)((PI_CONSTANTS[const_word_idx] >> (31 - const_bit_idx)) & 1u);

        uint8_t pos_bit0 = (uint8_t)((i >> 0) & 1);
        uint8_t pos_bit1 = (uint8_t)((i >> 1) & 1);
        uint8_t pos_bit2 = (uint8_t)((i >> 2) & 1);
        uint8_t pos_bit3 = (uint8_t)((i >> 3) & 1);
        uint8_t pos_odd  = (uint8_t)(i & 1);

        uint8_t bit_val = 0;
        bit_val ^= key_low[i] & 1u;
        bit_val ^= key_low[(i + 11) % 64] & 1u;
        bit_val ^= key_high[(i + 17) % 64] & 1u;
        bit_val ^= nonce_low[i] & 1u;
        bit_val ^= nonce_low[(i + 19) % 64] & 1u;
        bit_val ^= nonce_high[(i + 29) % 64] & 1u;
        bit_val ^= const_bit & 1u;

        bit_val ^= (uint8_t)((key_low[i] & nonce_low[i]) & 1u);
        bit_val ^= (uint8_t)((key_high[(i + 41) % 64] & nonce_high[(i + 43) % 64]) & 1u);

        bit_val ^= (uint8_t)((pos_bit0 & key_low[i]) & 1u);
        bit_val ^= (uint8_t)((pos_bit1 & nonce_low[i]) & 1u);
        bit_val ^= (uint8_t)((pos_bit2 & key_high[(i + 5) % 64] & nonce_high[(i + 5) % 64]) & 1u);

        {
            uint8_t or_term = (uint8_t)((key_low[(i + 3) % 64] | nonce_low[(i + 3) % 64]) & 1u);
            bit_val ^= (uint8_t)((pos_bit3 & or_term) & 1u);
        }

        {
            uint8_t and_term = (uint8_t)((key_high[i / 2] & nonce_low[i / 2]) & 1u);
            bit_val ^= (uint8_t)((pos_odd & and_term) & 1u);
        }

        primary[i] = (uint8_t)(bit_val & 1u);
    }

    memcpy(st->lfsr, lfsr, 64);
    memcpy(st->primary, primary, 64);
}

static void egc_init_from_hex(egc_hw_t *st, const char *key_hex, const char *nonce_hex) {
    uint8_t key_bits[128];
    uint8_t nonce_bits[128];
    uint8_t new_primary[64];

    hex_to_bits_128(key_hex, key_bits);
    hex_to_bits_128(nonce_hex, nonce_bits);

    cipher_init(st, key_bits, nonce_bits);

    /* Warmup rounds */
    for (int r = 0; r < WARMUP_ROUNDS; r++) {
        primary_update(st, new_primary);
        lfsr_update(st);

        for (int i = 0; i < 8; i++) {
            uint8_t rk = st->lfsr[i * 8] & 1u;
            new_primary[i] = (uint8_t)((new_primary[i] ^ rk) & 1u);
        }

        memcpy(st->primary, new_primary, 64);
    }
}

static uint8_t egc_clock(egc_hw_t *st) {
    uint8_t new_primary[64];
    primary_update(st, new_primary);
    lfsr_update(st);

    for (int i = 0; i < 8; i++) {
        uint8_t rk = st->lfsr[i * 8] & 1u;
        new_primary[i] = (uint8_t)((new_primary[i] ^ rk) & 1u);
    }

    memcpy(st->primary, new_primary, 64);

    uint8_t out = 0;
    for (int i = 0; i < 64; i++) out ^= (st->primary[i] & 1u);
    return (uint8_t)(out & 1u);
}

static void egc_generate_bits(egc_hw_t *st, uint8_t *out_bits, size_t n_bits) {
    for (size_t i = 0; i < n_bits; i++) {
        out_bits[i] = egc_clock(st);
    }
}

/* --- Self-test --- */

typedef struct {
    const char *name;
    const char *key_hex;
    const char *nonce_hex;
    const char *expected_hex;
} tv_t;

int main(void) {
    const tv_t tvs[] = {
        {"TV0", "00000000000000000000000000000000", "00000000000000000000000000000000", "C002BEBCC449743DB0139754D8DDDAC8"},
        {"TV1", "00000000000000000000000000000000", "00000000000000000000000000000001", "8D2BD8932407D1B62ABBBE129E53F69C"},
        {"TV2", "00000000000000000000000000000000", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "813FCECC60B6588D6CE9A9F7B5B37111"},
        {"TV3", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "00000000000000000000000000000000", "A1CA26563BA41AA8EB46E82932817B90"},
        {"TV4", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "184AD96D5CAF74594632C0AFA2973170"},
        {"TV5", "00112233445566778899AABBCCDDEEFF", "00000000000000000000000000000000", "BBE91A9D3FDBAD6BD0C6BE84677F769A"},
        {"TV6", "00000000000000000000000000000000", "00112233445566778899AABBCCDDEEFF", "91B0024AA0104B448FB13C5AAD4B83C2"},
        {"TV7", "0123456789ABCDEFFEDCBA9876543210", "0F1E2D3C4B5A69788796A5B4C3D2E1F0", "F0E5CF3D8C50678856308843D15ED5C8"},
        {"TV8", "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3", "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C", "53809F85D4CE8F9652CC4F191A7278E6"},
        {"TV9", "13579BDF2468ACE013579BDF2468ACE0", "00000000000000000000000000000000", "415D605489039C62C89EDC2861A32A14"},
    };

    int all_match = 1;

    printf("======================================================================\n");
    printf("EGC-Stream Cipher TEST (C)\n");
    printf("======================================================================\n\n");

    for (size_t i = 0; i < sizeof(tvs)/sizeof(tvs[0]); i++) {
        egc_hw_t st;
        uint8_t ks_bits[128];
        char ks_hex[33];

        egc_init_from_hex(&st, tvs[i].key_hex, tvs[i].nonce_hex);
        egc_generate_bits(&st, ks_bits, 128);
        bits_to_hex(ks_bits, 128, ks_hex);

        const char *mark = (strcmp(ks_hex, tvs[i].expected_hex) == 0) ? "YES" : "NO";
        printf("%s: %s %s\n", tvs[i].name, ks_hex, mark);

        if (strcmp(ks_hex, tvs[i].expected_hex) != 0) {
            all_match = 0;
            printf("  Expected: %s\n", tvs[i].expected_hex);
        }
    }

    printf("\n======================================================================\n");
    if (all_match) {
        printf("### EGC-Stream Cipher VERIFIED! ###\n");
    } else {
        printf("??? Mismatch detected - debugging needed\n");
    }
    printf("======================================================================\n");

    return all_match ? 0 : 1;
}