# EGC-Stream: Expander-Graph-Based Stream Cipher

Reference implementation of EGC-Stream, a hardware-oriented synchronous stream cipher based on expander graph topology.

## Overview

EGC-Stream is a lightweight 128-bit stream cipher designed for resource-constrained platforms. The cipher uses a 4-regular Cayley graph on Z₆₄ for structural diffusion combined with a uniform nonlinear Boolean update function.

**Key Parameters:**
- Key size: 128 bits
- Nonce size: 128 bits
- Internal state: 128 bits (64-bit primary state + 64-bit LFSR)
- Output: 1 bit per cycle after 256-round initialization

## Installation

### Python Implementation
```bash
# Clone repository
git clone https://github.com/yourusername/egc-stream.git
cd egc-stream

# Run Python implementation
python EGC_Stream_Cipher.py
```

**Requirements:** Python 3.8 or later

### C Implementation
```bash
# Compile
gcc -O3 -o egc_stream EGC_Stream_Cipher.c

# Run
./egc_stream
```

## Usage

### Python
```python
from EGC_Stream_Cipher import EGCStreamCipher

# Initialize with 128-bit key and nonce
key = bytes(16)    # 16 bytes = 128 bits
nonce = bytes(16)

cipher = EGCStreamCipher(key, nonce)

# Generate keystream bits
keystream_bits = cipher.generate(1000)  # Generate 1000 bits

# Or generate keystream bytes
keystream_bytes = cipher.generate_bytes(128)  # Generate 128 bytes
```

### C
```c
#include "egc_stream.h"

uint8_t key[16] = {0};
uint8_t nonce[16] = {0};
egc_stream_ctx ctx;

// Initialize cipher
egc_stream_init(&ctx, key, nonce);

// Generate keystream
uint8_t keystream[1000];
egc_stream_generate(&ctx, keystream, 1000);
```

## Test Vectors

Selected test vectors from the paper (first 128 keystream bits in hexadecimal):

| Test | Key (hex) | Nonce (hex) | Keystream Z[0:127] (hex) |
|------|-----------|-------------|--------------------------|
| TV0  | 00000000000000000000000000000000 | 00000000000000000000000000000000 | C002BEBCC449743DB0139754D8DDDAC8 |
| TV4  | FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF | FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF | 184AD96D5CAF74594632C0AFA2973170 |
| TV7  | 0123456789ABCDEFFEDCBA9876543210 | 0F1E2D3C4B5A69788796A5B4C3D2E1F0 | F0E5CF3D8C50678856308843D15ED5C8 |

Complete test vectors are included in the source files.

## Citation

This code accompanies the paper:

> **W.A. Susantha Wijesinghe**, "EGC-Stream: Design, Cryptanalysis, and Hardware 
> Evaluation of an Expander-Graph–Based Stream Cipher," *IEEE Transactions on 
> Information Forensics and Security*, 2025 (submitted for publication).
```bibtex
@article{wijesinghe2025egcstream,
  author   = {Wijesinghe, W. A. Susantha},
  title    = {{EGC-Stream}: Design, Cryptanalysis, and Hardware Evaluation 
              of an Expander-Graph--Based Stream Cipher},
  journal  = {IEEE Transactions on Information Forensics and Security},
  year     = {2025},
  note     = {Submitted for publication},
  url      = {https://github.com/yourusername/egc-stream},
  keywords = {stream cipher, lightweight cryptography, expander graphs, 
              FPGA implementation, hardware security}
}
```

If you use this code in your research, please cite the paper above.

## Algorithm Specification

**Graph Topology:** 4-regular Cayley graph on Z₆₄ with generators {±1, ±16}
- Each vertex i connects to: (i-1) mod 64, (i+1) mod 64, (i+16) mod 64
- Graph diameter: 9
- Total edges: 128 (64 ring + 64 stride-16)

**Update Function (Rule-A):** 4-input Boolean function with truth table 0x036F
```
f(x₀, x₁, x₂, x₃) = 1 ⊕ x₂ ⊕ x₀x₂ ⊕ x₁x₂ ⊕ x₁x₃ ⊕ x₀x₂x₃
```

**Key Schedule:** 64-bit LFSR with primitive polynomial x⁶⁴ + x⁴ + x³ + x + 1

**Output Function:** XOR (parity) of all 64 primary state bits

See the paper for complete specification details.

## Security Notice

⚠️ **This is a reference implementation for research and educational purposes.**

**DO NOT** use this code to protect real-world sensitive data without:
- Independent security audit
- Side-channel attack analysis
- Constant-time implementation review
- Formal security verification

The cipher has undergone initial cryptanalysis as described in the accompanying paper, but further evaluation by the cryptographic community is necessary before any production use.

## License

MIT License - see [LICENSE](LICENSE) file for details.

Copyright (c) 2025 W.A. Susantha Wijesinghe

## Contact

**W.A. Susantha Wijesinghe, Ph.D.**  
Department of Electronics  
Wayamba University of Sri Lanka  
Email: susantha@wyb.ac.lk

## Updates

This repository will be expanded with additional materials including:
- Hardware implementations (Verilog RTL)
- FPGA/ASIC synthesis results
- Extended documentation

Citation information will be updated upon paper publication.

---

**Repository Status:** Initial release with reference implementations  
**Paper Status:** Submitted to IEEE Transactions on Information Forensics and Security
```
