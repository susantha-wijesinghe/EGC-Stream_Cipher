#!/usr/bin/env python3
"""
EGC-Stream: Expander-Graph-Based Stream Cipher
Reference Implementation in Python

Copyright (c) 2025 W.A. Susantha Wijesinghe
Department of Electronics, Wayamba University of Sri Lanka

This code accompanies the paper:
    W.A. Susantha Wijesinghe, "EGC-Stream: Design, Cryptanalysis, and 
    Hardware Evaluation of an Expander-Graph–Based Stream Cipher,"
    IEEE Transactions on Information Forensics and Security, 2025
    (submitted for publication)

License: MIT License
Repository: https://github.com/yourusername/egc-stream

================================================================================
ALGORITHM OVERVIEW
================================================================================

EGC-Stream is a synchronous stream cipher with:
- 128-bit key and 128-bit nonce
- 128-bit internal state (64-bit primary + 64-bit LFSR)
- 4-regular Cayley graph topology on Z_64 with generators {±1, ±16}
- Uniform nonlinear update via Rule-A Boolean function (0x036F)
- 256-round initialization phase
- 1-bit-per-cycle output via global parity function

Graph Properties:
    - Vertices: 64
    - Degree: 4 (regular)
    - Edges: 128 (64 ring + 64 stride-16)
    - Diameter: 9
    - Generators: {±1, ±16} on Z_64

Rule-A (4-input Boolean function):
    Truth table: 0x036F
    ANF: f(x0,x1,x2,x3) = 1 ⊕ x2 ⊕ x0x2 ⊕ x1x2 ⊕ x1x3 ⊕ x0x2x3
    Degree: 3, Nonlinearity: 4, Balance: 8/16

LFSR Polynomial:
    p(x) = x^64 + x^4 + x^3 + x + 1 (primitive)

================================================================================
SECURITY NOTICE
================================================================================

This is a REFERENCE IMPLEMENTATION for research and educational purposes.

DO NOT use this code to protect real-world sensitive data without:
1. Independent third-party security audit
2. Side-channel attack analysis (timing, power, EM)
3. Constant-time implementation review
4. Formal verification of security properties

This implementation prioritizes clarity and correctness over performance.
For production use, consider constant-time operations and hardware acceleration.

================================================================================
IMPLEMENTATION NOTES
================================================================================

This reference implementation:
- Uses Python's native integer types (no performance optimization)
- Implements exact algorithm from paper specification (Section 3)
- Includes all 10 test vectors from Table 3
- Uses little-endian byte ordering
- State representation: LSB = bit 0

================================================================================
"""

RULE_A_LUT = [1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0]

def rule_a(x0, x1, x2, x3):
    idx = (x0 & 1) | ((x1 & 1) << 1) | ((x2 & 1) << 2) | ((x3 & 1) << 3)
    return RULE_A_LUT[idx]

def hex_to_bits(hex_str):
    hex_str = hex_str.replace('0x', '').replace(' ', '').zfill(32)
    bits = []
    for i in range(0, 32, 2):
        byte_val = int(hex_str[i:i+2], 16)
        for bit_pos in range(7, -1, -1):
            bits.append((byte_val >> bit_pos) & 1)
    return bits

def bits_to_hex(bits):
    hex_str = ""
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | (bits[i + j] & 1)
        hex_str += f"{byte_val:02X}"
    return hex_str

class EGCStreamCipher:

    def __init__(self, key_hex, nonce_hex):
        self.PRIMARY_N = 64
        self.LFSR_N = 64
        self.WARMUP_ROUNDS = 256
        
        key_bits = hex_to_bits(key_hex)
        nonce_bits = hex_to_bits(nonce_hex)
        
        self.lfsr, self.primary = self.cipher_init(key_bits, nonce_bits)
        
        for _ in range(self.WARMUP_ROUNDS):
            self.warmup_round()
    
    def cipher_init(self, key_bits, nonce_bits):
        
        PI_CONSTANTS = [
            0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
            0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
            0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
            0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
        ]
        
        key_high = key_bits[:64]
        key_low = key_bits[64:]
        nonce_high = nonce_bits[:64]
        nonce_low = nonce_bits[64:]
        
        lfsr = [0] * 64
        primary = [0] * 64
        
        # ============================================================
        # LFSR: Pure combinational logic (NO CONDITIONALS)
        # ============================================================
        for i in range(64):
            # Extract constant bit
            const_word_idx = i // 32
            const_bit_idx = i % 32
            const_bit = (PI_CONSTANTS[const_word_idx] >> (31 - const_bit_idx)) & 1
            
            # Compute position masks (these are CONSTANTS, not runtime conditionals!)
            pos_bit0 = (i >> 0) & 1  # i & 1
            pos_bit1 = (i >> 1) & 1  # i & 2
            pos_bit2 = (i >> 2) & 1  # i & 4
            pos_bit3 = (i >> 3) & 1  # i & 8
            
            # Standard XOR mixing
            bit_val = 0
            bit_val ^= key_high[i]
            bit_val ^= key_high[(i + 7) % 64]
            bit_val ^= key_low[i]
            bit_val ^= nonce_high[i]
            bit_val ^= nonce_high[(i + 13) % 64]
            bit_val ^= nonce_low[(i + 23) % 64]
            bit_val ^= const_bit
            
            # Nonlinear terms
            bit_val ^= (key_high[i] & nonce_high[i])
            bit_val ^= (key_low[(i + 31) % 64] & nonce_low[(i + 37) % 64])
            
            bit_val ^= (pos_bit0 & key_high[i])
            
            bit_val ^= (pos_bit1 & nonce_high[i])
            
            bit_val ^= (pos_bit2 & key_low[i] & nonce_low[i])
            
            or_term = key_high[(i+1)%64] | nonce_high[(i+1)%64]
            bit_val ^= (pos_bit3 & or_term)
            
            lfsr[i] = bit_val & 1
        
        # ============================================================
        # Primary: Pure combinational logic
        # ============================================================
        for i in range(64):
            const_word_idx = (i + 2) // 32
            const_bit_idx = (i + 2) % 32
            const_bit = (PI_CONSTANTS[const_word_idx] >> (31 - const_bit_idx)) & 1
            
            # Position masks
            pos_bit0 = (i >> 0) & 1
            pos_bit1 = (i >> 1) & 1
            pos_bit2 = (i >> 2) & 1
            pos_bit3 = (i >> 3) & 1
            pos_odd = i & 1  # i % 2 == 1
            
            bit_val = 0
            bit_val ^= key_low[i]
            bit_val ^= key_low[(i + 11) % 64]
            bit_val ^= key_high[(i + 17) % 64]
            bit_val ^= nonce_low[i]
            bit_val ^= nonce_low[(i + 19) % 64]
            bit_val ^= nonce_high[(i + 29) % 64]
            bit_val ^= const_bit
            
            bit_val ^= (key_low[i] & nonce_low[i])
            bit_val ^= (key_high[(i + 41) % 64] & nonce_high[(i + 43) % 64])
            
            # Position-weighted terms (combinational)
            bit_val ^= (pos_bit0 & key_low[i])
            bit_val ^= (pos_bit1 & nonce_low[i])
            bit_val ^= (pos_bit2 & key_high[(i+5)%64] & nonce_high[(i+5)%64])
            
            or_term = key_low[(i+3)%64] | nonce_low[(i+3)%64]
            bit_val ^= (pos_bit3 & or_term)
            
            # Odd position term
            and_term = key_high[i//2] & nonce_low[i//2]
            bit_val ^= (pos_odd & and_term)
            
            primary[i] = bit_val & 1
        
        return lfsr, primary
    
    def lfsr_update(self):
        fb = (self.lfsr[0] ^ self.lfsr[1] ^ self.lfsr[3] ^ self.lfsr[4]) & 1
        self.lfsr = self.lfsr[1:] + [fb]
    
    def primary_update(self):
        new_primary = [0] * self.PRIMARY_N
        for i in range(self.PRIMARY_N):
            i0 = i
            i1 = (i - 1) % self.PRIMARY_N
            i2 = (i + 1) % self.PRIMARY_N
            i3 = (i + 16) % self.PRIMARY_N
            new_primary[i] = rule_a(
                self.primary[i0],
                self.primary[i1],
                self.primary[i2],
                self.primary[i3]
            )
        return new_primary
    
    def warmup_round(self):
        new_primary = self.primary_update()
        self.lfsr_update()
        
        rk = [self.lfsr[i * 8] for i in range(8)]
        for i in range(8):
            if rk[i]:
                new_primary[i] ^= 1
        
        self.primary = new_primary
    
    def generate_keystream(self, n_bits):
        keystream = []
        for _ in range(n_bits):
            new_primary = self.primary_update()
            self.lfsr_update()
            
            rk = [self.lfsr[i * 8] for i in range(8)]
            for i in range(8):
                if rk[i]:
                    new_primary[i] ^= 1
            
            self.primary = new_primary
            
            output_bit = 0
            for bit in self.primary:
                output_bit ^= bit
            
            keystream.append(output_bit & 1)
        
        return keystream


def hw_test():
    print("="*70)
    print("EGC-Stream Cipher TEST")
    print("="*70)
    print()
    
    test_vectors = [
        ("TV0", "00000000000000000000000000000000", "00000000000000000000000000000000"),
        ("TV1", "00000000000000000000000000000000", "00000000000000000000000000000001"),
        ("TV2", "00000000000000000000000000000000", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        ("TV3", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "00000000000000000000000000000000"),
        ("TV4", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        ("TV5", "00112233445566778899AABBCCDDEEFF", "00000000000000000000000000000000"),
        ("TV6", "00000000000000000000000000000000", "00112233445566778899AABBCCDDEEFF"),
        ("TV7", "0123456789ABCDEFFEDCBA9876543210", "0F1E2D3C4B5A69788796A5B4C3D2E1F0"),
        ("TV8", "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3", "5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C"),
        ("TV9", "13579BDF2468ACE013579BDF2468ACE0", "00000000000000000000000000000000"),
    ]
    
    expected = [
        "C002BEBCC449743DB0139754D8DDDAC8",
        "8D2BD8932407D1B62ABBBE129E53F69C",
        "813FCECC60B6588D6CE9A9F7B5B37111",
        "A1CA26563BA41AA8EB46E82932817B90",
        "184AD96D5CAF74594632C0AFA2973170",
        "BBE91A9D3FDBAD6BD0C6BE84677F769A",
        "91B0024AA0104B448FB13C5AAD4B83C2",
        "F0E5CF3D8C50678856308843D15ED5C8",
        "53809F85D4CE8F9652CC4F191A7278E6",
        "415D605489039C62C89EDC2861A32A14",
    ]
    
    all_match = True
    for i, (name, key, nonce) in enumerate(test_vectors):
        cipher = EGCStreamCipher(key, nonce)
        ks = cipher.generate_keystream(128)
        ks_hex = bits_to_hex(ks)
        
        match = "YES" if ks_hex == expected[i] else "NO"
        print(f"{name}: {ks_hex} {match}")
        
        if ks_hex != expected[i]:
            all_match = False
            print(f"  Expected: {expected[i]}")
    
    print()
    print("="*70)
    if all_match:
        print("### EGC-Stream Cipher VERIFIED! ###")
        print()
    else:
        print("??? Mismatch detected - debugging needed")
    print("="*70)


if __name__ == "__main__":
    hw_test()