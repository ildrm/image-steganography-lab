# Image Steganography Lab

A single-file, menu-driven image steganography laboratory for **Python 3.11+**. The project provides a common payload format, compression, optional authenticated encryption, capacity checks, verification, self-tests, and a registry of **128 steganography techniques** spanning file/container storage, spatial-domain methods, PVD, edge-adaptive methods, transform-domain methods, coding techniques, palette methods, and model-dependent modern approaches.

The implementation is designed for legitimate **education, research, privacy, watermarking, and data-hiding experiments**. Recovered content is treated strictly as inert data and is never executed.

> **Important:** The registry intentionally distinguishes practical implementations from educational approximations and unavailable model/provider techniques. A technique marked `EDUCATIONAL` is not claimed to be bit-compatible or mathematically identical to the canonical research implementation with the same name.

## Table of Contents

- [Highlights](#highlights)
- [Project Layout](#project-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Interactive Mode](#interactive-mode)
- [Command-Line Interface](#command-line-interface)
- [Algorithm Selection](#algorithm-selection)
- [Implementation Statuses](#implementation-statuses)
- [Complete Algorithm Catalog](#complete-algorithm-catalog)
- [What the Educational Implementations Mean](#what-the-educational-implementations-mean)
- [Payload Format](#payload-format)
- [Compression](#compression)
- [Password Encryption](#password-encryption)
- [Carrier Keys vs Encryption Passwords](#carrier-keys-vs-encryption-passwords)
- [Image and File Format Behavior](#image-and-file-format-behavior)
- [Capacity Estimation](#capacity-estimation)
- [Verification and Integrity Checking](#verification-and-integrity-checking)
- [Output Naming and Overwrite Protection](#output-naming-and-overwrite-protection)
- [Self-Test Suite](#self-test-suite)
- [Programmatic Use](#programmatic-use)
- [Architecture](#architecture)
- [Security and Safety Model](#security-and-safety-model)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Extending the Lab](#extending-the-lab)
- [License](#license)

## Highlights

- One Python file: `image_steganography_lab.py`
- Python 3.11+
- Cross-platform terminal application for macOS, Linux, and Windows
- Interactive menu plus `argparse` CLI
- 128 registered algorithms across 15 categories
- IDs **1-105** have executable local carrier implementations or explicitly labeled educational delegates
- IDs **106-128** are provider/model/corpus-dependent registry entries and intentionally refuse to fake an implementation
- UTF-8 text support, including Persian, Arabic, emoji, and multiline messages
- Shared binary payload framing with magic bytes, versioning, algorithm ID, flags, lengths, and CRC32
- `zlib` compression enabled by default
- Optional AES-256-GCM authenticated encryption using `cryptography`
- PBKDF2-HMAC-SHA256 password derivation with random salt
- Deterministic keyed carrier ordering based on SHA-256-derived seeds
- Capacity estimation before writing
- Source overwrite protection in CLI mode
- Lossless-output enforcement for fragile pixel-domain methods
- Verification mode for header, CRC, algorithm identity, and optional expected text
- Built-in self-test suite
- No automatic package installation
- No automatic model downloads
- No execution of extracted data

## Project Layout

The project is intentionally minimal:

```text
.
├── image_steganography_lab.py
└── README.md
```

There are no required project-specific modules, model files, configuration files, or databases.

## Requirements

### Required

- Python **3.11+**
- `Pillow`
- `NumPy`

Install the minimum runtime dependencies with:

```bash
python -m pip install pillow numpy
```

### Optional

| Package | Purpose |
|---|---|
| `cryptography` | AES-256-GCM password protection and PBKDF2-HMAC-SHA256 key derivation |
| `opencv-python` | True Canny edge selection for algorithm 36 |
| `PyWavelets` | Detected as an optional wavelet research dependency; the built-in Haar DWT/IWT implementation does **not** require it |

Install all optional packages with:

```bash
python -m pip install cryptography opencv-python PyWavelets
```

Or install everything in one command:

```bash
python -m pip install pillow numpy cryptography opencv-python PyWavelets
```

The program never installs dependencies automatically. Missing optional packages are reported at startup with installation guidance.

> `SciPy` is not required by the current implementation.

## Installation

### macOS / Linux

```bash
mkdir image-steganography-lab
cd image-steganography-lab

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install pillow numpy cryptography opencv-python PyWavelets
```

Place `image_steganography_lab.py` in the directory, then verify the installation:

```bash
python image_steganography_lab.py --self-test
```

### Windows PowerShell

```powershell
mkdir image-steganography-lab
cd image-steganography-lab

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install pillow numpy cryptography opencv-python PyWavelets
python image_steganography_lab.py --self-test
```

### Windows Command Prompt

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install pillow numpy cryptography opencv-python PyWavelets
python image_steganography_lab.py --self-test
```

## Quick Start

### Open the interactive application

```bash
python image_steganography_lab.py
```

### List all algorithms

```bash
python image_steganography_lab.py algorithms
```

### Inspect one algorithm

```bash
python image_steganography_lab.py info lsb
```

You may use an ID instead:

```bash
python image_steganography_lab.py info 16
```

### Encode a message with LSB replacement

```bash
python image_steganography_lab.py encode \
  --algorithm lsb \
  --input photo.png \
  --message "Hello world" \
  --output encoded.png
```

Compression is enabled by default.

### Decode it

```bash
python image_steganography_lab.py decode \
  --algorithm lsb \
  --input encoded.png
```

### Encrypt before embedding

```bash
python image_steganography_lab.py encode \
  --algorithm lsb \
  --input photo.png \
  --message "Confidential message" \
  --output encrypted-stego.png \
  --encrypt
```

The password is requested securely with `getpass` when running in a terminal.

## Interactive Mode

Running the script without a subcommand opens this menu:

```text
==================================================
IMAGE STEGANOGRAPHY LAB
==================================================
1. Encode message
2. Decode message
3. Algorithm information
4. Compare algorithms
5. Estimate image capacity
6. Verify encoded image
7. Exit
```

### Interactive encode flow

The encoder:

1. Shows the complete 128-entry algorithm menu.
2. Shows detailed information for the selected algorithm.
3. Asks for an input image.
4. Warns before RGB/RGBA conversion when needed.
5. Accepts a multiline UTF-8 message; enter a line containing only `.` to finish.
6. Asks whether to compress the message; default is **yes**.
7. Asks whether to encrypt the message; default is **no**.
8. Requests a carrier key for algorithms that require one.
9. Suggests an output path.
10. Calculates capacity before encoding.
11. Writes the encoded image/file.
12. Prints an encoding report with input/output size, capacity, payload size, utilization, compression, and encryption state.

### Interactive decode flow

The decoder:

1. Asks for the algorithm.
2. Asks for the encoded file.
3. Requests a carrier key where appropriate.
4. Extracts and validates the common payload frame.
5. Prompts for an encryption password only when required.
6. Verifies the payload checksum.
7. Decrypts and decompresses in the correct order.
8. Decodes UTF-8 text.
9. Prints the recovered message.
10. Optionally saves the recovered text to a file.

## Command-Line Interface

General syntax:

```text
python image_steganography_lab.py [--debug] [--self-test] <command> [options]
```

Global options must be placed before a subcommand when applicable.

### `encode`

```text
python image_steganography_lab.py encode \
  --algorithm <id|slug|exact-name> \
  --input <file> \
  [--output <file>] \
  [--message <text> | --message-file <file>] \
  [--key <carrier-key>] \
  [--no-compress] \
  [--encrypt] \
  [--allow-conversion] \
  [--overwrite]
```

If neither `--message` nor `--message-file` is supplied:

- interactive terminals prompt for a message;
- non-interactive stdin is read as the message.

Example using a text file:

```bash
python image_steganography_lab.py encode \
  -a lsb \
  -i cover.png \
  --message-file secret.txt \
  -o encoded.png
```

Example using stdin:

```bash
printf 'hello from stdin' | python image_steganography_lab.py encode \
  -a lsb \
  -i cover.png \
  -o encoded.png
```

Disable payload compression:

```bash
python image_steganography_lab.py encode \
  -a lsb \
  -i cover.png \
  --message "uncompressed" \
  -o encoded.png \
  --no-compress
```

### `decode`

```text
python image_steganography_lab.py decode \
  --algorithm <id|slug|exact-name> \
  --input <file> \
  [--key <carrier-key>] \
  [--save-message <file>]
```

Example:

```bash
python image_steganography_lab.py decode \
  -a keyed-lsb \
  -i encoded.png \
  --key "carrier passphrase" \
  --save-message recovered.txt
```

### `algorithms`

Print the complete registry:

```bash
python image_steganography_lab.py algorithms
```

### `info`

Show detailed metadata for one algorithm:

```bash
python image_steganography_lab.py info dct
python image_steganography_lab.py info 49
```

The information screen includes concept, mathematical idea, encoding/decoding description, advantages, disadvantages, recommended formats, capacity, detectability, robustness, reversibility, implementation status, and notes.

### `compare`

Compare all algorithms:

```bash
python image_steganography_lab.py compare
```

Compare a subset by IDs and/or slugs:

```bash
python image_steganography_lab.py compare 16 keyed-lsb 26 dct dwt qim
```

The comparison ratings are qualitative engineering guidance, not benchmark-derived scientific scores.

### `capacity`

Estimate available carrier capacity:

```bash
python image_steganography_lab.py capacity \
  -a lsb \
  -i photo.png
```

Estimate capacity for a specific message, including the complete payload frame:

```bash
python image_steganography_lab.py capacity \
  -a lsb \
  -i photo.png \
  --message "سلام دنیا"
```

For keyed algorithms:

```bash
python image_steganography_lab.py capacity \
  -a keyed-lsb \
  -i photo.png \
  --key "carrier passphrase" \
  --message "Hello"
```

### `verify`

Verify an encoded image/file:

```bash
python image_steganography_lab.py verify \
  -a lsb \
  -i encoded.png
```

Also compare the recovered text against an expected value:

```bash
python image_steganography_lab.py verify \
  -a lsb \
  -i encoded.png \
  --expected "Hello world"
```

Verification reports:

```text
Payload header:   VALID
Payload checksum: VALID
Algorithm:        LSB Replacement / LSB Substitution
Compression:      YES
Encryption:       NO
Message size:     ... bytes
Decode result:    SUCCESS
Expected text:    MATCH
```

### `--self-test`

```bash
python image_steganography_lab.py --self-test
```

### `--debug`

Normal mode prints concise errors. Debug mode includes exception tracebacks and DEBUG logging:

```bash
python image_steganography_lab.py --debug encode \
  -a lsb \
  -i cover.png \
  --message "test"
```

## Algorithm Selection

`--algorithm` accepts any of the following:

1. Numeric algorithm ID, for example `16`
2. Slug, for example `lsb`
3. Unique exact algorithm name, matched case-insensitively

Slugs are the most convenient choice for scripts because they are short and stable within this file.

Examples:

```bash
-a 16
-a lsb
-a "LSB Replacement / LSB Substitution"
```

## Implementation Statuses

| Status | Meaning |
|---|---|
| `FULL` | The standalone file contains a practical executable implementation of the lab's defined carrier. This does not imply compatibility with every research paper that may use a similar name. |
| `EDUCATIONAL` | Executable approximation or demonstration. It intentionally does not claim canonical/reference compatibility. |
| `EXPERIMENTAL` | Registered concept that requires an external corpus/provider or additional infrastructure in the current standalone build. |
| `REQUIRES_OPTIONAL_DEPENDENCY` | Status type supported by the code. No current registry entry is assigned this status. |
| `REQUIRES_TRAINED_MODEL` | Execution is intentionally blocked until compatible local trained weights/provider infrastructure is supplied. |

With OpenCV installed, the current registry contains **44 `FULL`** and **61 `EDUCATIONAL`** entries among algorithms 1-105. Without OpenCV, algorithm 36 falls back from true Canny to Sobel and is labeled `EDUCATIONAL`, producing **43 `FULL`** and **62 `EDUCATIONAL`** entries. Algorithms 106-128 consist of **17 `REQUIRES_TRAINED_MODEL`** entries and **6 `EXPERIMENTAL`** entries.

### Category summary

| Category | IDs | Count |
|---|---:|---:|
| A. File / Container Techniques | 1-15 | 15 |
| B. Basic Spatial-Domain Techniques | 16-25 | 10 |
| C. Pixel Difference Techniques | 26-29 | 4 |
| D. Modification-Direction Techniques | 30-33 | 4 |
| E. Edge / Texture Adaptive | 34-39 | 6 |
| F. Histogram Methods | 40-42 | 3 |
| G. Reversible Data Hiding | 43-48 | 6 |
| H. DCT / JPEG-Domain | 49-61 | 13 |
| I. Transform Domain | 62-73 | 12 |
| J. Spread-Spectrum / Quantization | 74-80 | 7 |
| K. Content-Adaptive / Distortion-Based | 81-92 | 12 |
| L. Embedding Coding Techniques | 93-100 | 8 |
| M. Palette / Indexed Image Methods | 101-105 | 5 |
| N. Neural / Modern Methods | 106-119 | 14 |
| O. Coverless / Generative Approaches | 120-128 | 9 |
| **Total** | **1-128** | **128** |

## Complete Algorithm Catalog

The following table mirrors the registry in `image_steganography_lab.py`.

`FULL* / EDUCATIONAL*` on algorithm 36 means the runtime status depends on whether OpenCV is installed.

### A. File / Container Techniques

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 1 | `exif` | EXIF metadata embedding | `FULL` |
| 2 | `xmp` | XMP metadata embedding | `FULL` |
| 3 | `iptc-style` | IPTC-style metadata embedding where supported | `EDUCATIONAL` |
| 4 | `jpeg-com` | JPEG COM/comment segment embedding | `FULL` |
| 5 | `jpeg-app` | JPEG APP segment embedding | `FULL` |
| 6 | `png-text` | PNG tEXt chunk embedding | `FULL` |
| 7 | `png-ztxt` | PNG zTXt chunk embedding | `FULL` |
| 8 | `png-itxt` | PNG iTXt chunk embedding | `FULL` |
| 9 | `png-custom` | PNG private/custom chunk embedding | `FULL` |
| 10 | `gif-comment` | GIF comment/extension embedding | `FULL` |
| 11 | `eof` | EOF/trailing-data embedding | `FULL` |
| 12 | `padding` | File padding/slack-style storage where safely applicable | `EDUCATIONAL` |
| 13 | `alpha-lsb` | Alpha-channel embedding | `FULL` |
| 14 | `transparent-pixel` | Transparent-pixel embedding | `FULL` |
| 15 | `safe-polyglot` | Safe polyglot-style payload container demonstration | `EDUCATIONAL` |

### B. Basic Spatial-Domain Techniques

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 16 | `lsb` | LSB Replacement / LSB Substitution | `FULL` |
| 17 | `lsb-matching` | LSB Matching / ±1 Embedding | `FULL` |
| 18 | `lsbmr` | LSB Matching Revisited / LSBMR | `FULL` |
| 19 | `modified-lsb` | Modified LSB / MLSB | `FULL` |
| 20 | `inverted-lsb` | Inverted LSB | `FULL` |
| 21 | `keyed-lsb` | Keyed / Pseudorandom LSB | `FULL` |
| 22 | `multi-bit-lsb` | Multi-bit LSB | `FULL` |
| 23 | `bit-plane` | Bit-plane embedding | `FULL` |
| 24 | `pixel-indicator` | Pixel Indicator Technique | `FULL` |
| 25 | `parity` | Parity embedding | `FULL` |

### C. Pixel Difference Techniques

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 26 | `pvd` | Pixel Value Differencing / PVD | `FULL` |
| 27 | `adaptive-pvd` | Adaptive PVD | `FULL` |
| 28 | `multi-directional-pvd` | Multi-Directional PVD | `EDUCATIONAL` |
| 29 | `pvd-lsb-hybrid` | PVD + LSB Hybrid | `EDUCATIONAL` |

### D. Modification-Direction Techniques

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 30 | `emd` | Exploiting Modification Direction / EMD | `EDUCATIONAL` |
| 31 | `generalized-emd` | Generalized EMD | `EDUCATIONAL` |
| 32 | `diamond-encoding` | Diamond Encoding | `EDUCATIONAL` |
| 33 | `enhanced-emd` | Modified / Enhanced EMD | `EDUCATIONAL` |

### E. Edge / Texture Adaptive

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 34 | `edge-adaptive-lsb` | Edge-Adaptive LSB | `FULL` |
| 35 | `sobel-lsb` | Sobel-Adaptive LSB | `FULL` |
| 36 | `canny-lsb` | Canny-Adaptive LSB | `FULL* / EDUCATIONAL*` |
| 37 | `laplacian-lsb` | Laplacian-Adaptive LSB | `FULL` |
| 38 | `texture-lsb` | Texture-Adaptive LSB | `FULL` |
| 39 | `bpcs` | Bit-Plane Complexity Segmentation / BPCS | `EDUCATIONAL` |

### F. Histogram Methods

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 40 | `histogram-shifting` | Histogram Shifting | `EDUCATIONAL` |
| 41 | `difference-histogram` | Difference Histogram Shifting | `EDUCATIONAL` |
| 42 | `prediction-error-histogram` | Prediction-Error Histogram Shifting | `EDUCATIONAL` |

### G. Reversible Data Hiding

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 43 | `difference-expansion` | Difference Expansion / DE | `EDUCATIONAL` |
| 44 | `prediction-error-expansion` | Prediction Error Expansion / PEE | `EDUCATIONAL` |
| 45 | `pvo` | Pixel Value Ordering / PVO | `EDUCATIONAL` |
| 46 | `ipvo` | Improved Pixel Value Ordering / IPVO | `EDUCATIONAL` |
| 47 | `reversible-contrast-mapping` | Reversible Contrast Mapping | `EDUCATIONAL` |
| 48 | `compression-rdh` | Lossless Compression-Based RDH | `EDUCATIONAL` |

### H. DCT / JPEG-Domain

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 49 | `dct` | Basic DCT Coefficient Embedding | `FULL` |
| 50 | `dct-parity` | DCT Coefficient Parity | `FULL` |
| 51 | `dct-quantization` | DCT Quantization Embedding | `FULL` |
| 52 | `jsteg` | JSteg | `EDUCATIONAL` |
| 53 | `f3` | F3 | `EDUCATIONAL` |
| 54 | `f4` | F4 | `EDUCATIONAL` |
| 55 | `f5-style` | F5-Style Matrix Encoding | `EDUCATIONAL` |
| 56 | `nsf5-style` | nsF5-Style Embedding | `EDUCATIONAL` |
| 57 | `outguess-style` | OutGuess-Style Statistical Embedding | `EDUCATIONAL` |
| 58 | `yass-style` | YASS-Style Randomized Block Embedding | `EDUCATIONAL` |
| 59 | `ued-style` | UED-Style JPEG Distortion Embedding | `EDUCATIONAL` |
| 60 | `uerd-style` | UERD-Style JPEG Distortion Embedding | `EDUCATIONAL` |
| 61 | `j-uniward-style` | J-UNIWARD-Style JPEG Adaptive Embedding | `EDUCATIONAL` |

### I. Transform Domain

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 62 | `dwt` | DWT Embedding | `FULL` |
| 63 | `iwt` | Integer Wavelet Transform / IWT | `FULL` |
| 64 | `dft` | DFT Embedding | `FULL` |
| 65 | `fft` | FFT Frequency-Domain Embedding | `FULL` |
| 66 | `walsh-hadamard` | Walsh-Hadamard Transform Embedding | `FULL` |
| 67 | `svd` | SVD Embedding | `FULL` |
| 68 | `contourlet-style` | Contourlet-Style Transform Embedding | `EDUCATIONAL` |
| 69 | `curvelet-style` | Curvelet-Style Transform Embedding | `EDUCATIONAL` |
| 70 | `dwt-dct` | DWT + DCT Hybrid | `EDUCATIONAL` |
| 71 | `dwt-svd` | DWT + SVD Hybrid | `EDUCATIONAL` |
| 72 | `dct-svd` | DCT + SVD Hybrid | `EDUCATIONAL` |
| 73 | `dwt-dct-svd` | DWT + DCT + SVD Hybrid | `EDUCATIONAL` |

### J. Spread-Spectrum / Quantization

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 74 | `spread-spectrum` | Spread Spectrum Steganography | `EDUCATIONAL` |
| 75 | `dsss` | Direct-Sequence Spread Spectrum | `EDUCATIONAL` |
| 76 | `transform-spread-spectrum` | Transform-Domain Spread Spectrum | `EDUCATIONAL` |
| 77 | `qim` | Quantization Index Modulation / QIM | `FULL` |
| 78 | `dither-modulation` | Dither Modulation | `FULL` |
| 79 | `patchwork` | Patchwork | `EDUCATIONAL` |
| 80 | `correlation` | Correlation-Based Embedding | `EDUCATIONAL` |

### K. Content-Adaptive / Distortion-Based

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 81 | `hugo-style` | HUGO-Style Adaptive Embedding | `EDUCATIONAL` |
| 82 | `wow-style` | WOW-Style Wavelet Cost Embedding | `EDUCATIONAL` |
| 83 | `s-uniward-style` | S-UNIWARD-Style Embedding | `EDUCATIONAL` |
| 84 | `si-uniward-style` | SI-UNIWARD-Style Embedding | `EDUCATIONAL` |
| 85 | `hill-style` | HILL-Style Embedding | `EDUCATIONAL` |
| 86 | `mipod-style` | MiPOD-Style Embedding | `EDUCATIONAL` |
| 87 | `multivariate-gaussian` | Multivariate Gaussian Cost Embedding | `EDUCATIONAL` |
| 88 | `gmrf-style` | GMRF-Style Embedding | `EDUCATIONAL` |
| 89 | `cmd` | CMD / Clustering Modification Directions | `EDUCATIONAL` |
| 90 | `modification-direction-sync` | Modification Direction Synchronization | `EDUCATIONAL` |
| 91 | `hill-cmd` | HILL + CMD Hybrid | `EDUCATIONAL` |
| 92 | `adversarial-cost-demo` | Adversarial-Cost Demonstration | `EDUCATIONAL` |

### L. Embedding Coding Techniques

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 93 | `matrix-encoding` | Matrix Encoding | `FULL` |
| 94 | `hamming-matrix` | Hamming-Code Matrix Embedding | `FULL` |
| 95 | `syndrome-coding` | Syndrome Coding | `EDUCATIONAL` |
| 96 | `wet-paper-demo` | Simplified Wet-Paper Coding Demonstration | `EDUCATIONAL` |
| 97 | `stc-inspired` | Syndrome-Trellis-Code-Inspired Embedding | `EDUCATIONAL` |
| 98 | `bch-assisted` | BCH-Assisted Embedding | `EDUCATIONAL` |
| 99 | `reed-solomon-assisted` | Reed-Solomon-Assisted Embedding | `EDUCATIONAL` |
| 100 | `ldpc-inspired` | LDPC-Inspired Embedding | `EDUCATIONAL` |

### M. Palette / Indexed Image Methods

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 101 | `palette-lsb` | Palette LSB | `FULL` |
| 102 | `palette-parity` | Palette Parity | `FULL` |
| 103 | `palette-permutation` | Palette Permutation | `EDUCATIONAL` |
| 104 | `color-pair-substitution` | Color-Pair Substitution | `EDUCATIONAL` |
| 105 | `ezstego-style` | EZStego-Style Embedding | `EDUCATIONAL` |

### N. Neural / Modern Methods

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 106 | `neural-encoder-decoder` | Neural Encoder/Decoder Architecture Demonstration | `REQUIRES_TRAINED_MODEL` |
| 107 | `cnn-stego` | CNN-Based Steganography Demonstration | `REQUIRES_TRAINED_MODEL` |
| 108 | `autoencoder-stego` | Autoencoder Steganography Demonstration | `REQUIRES_TRAINED_MODEL` |
| 109 | `baluja-style` | Baluja-Style Deep Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 110 | `hidden-style` | HiDDeN-Style Architecture | `REQUIRES_TRAINED_MODEL` |
| 111 | `steganogan-style` | SteganoGAN-Style Architecture | `REQUIRES_TRAINED_MODEL` |
| 112 | `gan-stego` | GAN-Based Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 113 | `adversarial-stego` | Adversarial Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 114 | `invertible-nn` | Invertible Neural Network Architecture | `REQUIRES_TRAINED_MODEL` |
| 115 | `normalizing-flow` | Normalizing-Flow Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 116 | `attention-stego` | Attention-Based Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 117 | `transformer-stego` | Transformer-Based Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 118 | `diffusion-stego` | Diffusion-Based Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 119 | `neural-distortion-cost` | Neural Distortion-Cost Estimation | `REQUIRES_TRAINED_MODEL` |

### O. Coverless / Generative Approaches

| ID | Slug | Algorithm | Status |
|---:|---|---|---|
| 120 | `coverless-feature-mapping` | Coverless Feature Mapping | `EXPERIMENTAL` |
| 121 | `hash-coverless` | Hash-Based Coverless Mapping | `EXPERIMENTAL` |
| 122 | `image-selection-mapping` | Image-Selection / Retrieval Mapping Demonstration | `EXPERIMENTAL` |
| 123 | `texture-synthesis` | Texture-Synthesis Steganography Demonstration | `EXPERIMENTAL` |
| 124 | `generative-stego` | Generative Steganography Architecture | `REQUIRES_TRAINED_MODEL` |
| 125 | `gan-cover-synthesis` | GAN Cover Synthesis Architecture | `REQUIRES_TRAINED_MODEL` |
| 126 | `diffusion-cover-synthesis` | Diffusion Cover Synthesis Architecture | `REQUIRES_TRAINED_MODEL` |
| 127 | `semantic-stego` | Semantic Steganography Demonstration | `EXPERIMENTAL` |
| 128 | `feature-sequence-mapping` | Feature-Sequence Mapping | `EXPERIMENTAL` |

## What the Educational Implementations Mean

Several research algorithm names require substantially more infrastructure than a correct single-file implementation can reasonably provide. This project keeps those names visible while explicitly mapping them to independent educational carriers.

### File/container approximations

- **3 — IPTC-style metadata**: stores the framed payload in a JPEG APP13/Photoshop-style segment. It is not a complete IPTC-IIM metadata stack.
- **12 — Padding/slack-style storage**: uses a safe appended trailer. It does not manipulate filesystem slack space.
- **15 — Safe polyglot-style container**: appends a benign ZIP archive containing `hidden_message.bin` and a text notice. Nothing is executed.

### PVD and modification-direction approximations

- **28-29** delegate to the implemented horizontal PVD carrier.
- **30-33** use the Hamming/matrix carrier to demonstrate low-change modification-direction concepts. They are not canonical EMD/diamond implementations.

### Edge, BPCS, histogram, and RDH approximations

- **39 — BPCS** uses bit-plane transition complexity for candidate selection; canonical block conjugation is not implemented.
- **40 — Histogram Shifting** performs histogram-aware shifting but uses a non-reversible LSB bootstrap for metadata, so it is deliberately not labeled reversible.
- **41-42** delegate to the implemented histogram-shifting carrier.
- **43-48** are non-reference educational RDH entries backed by matrix embedding. They recover the message but **do not guarantee restoration of the pristine original image**.

### JPEG/DCT research-name approximations

- **52-61** use the lab's 8×8 DCT AC-coefficient QIM carrier. They do not reproduce canonical JSteg, F3, F4, F5, nsF5, OutGuess, YASS, UED, UERD, or J-UNIWARD behavior.

### Transform-domain approximations

- **62-63** contain a real integer Haar lifting implementation with LL/LH/HL/HH coefficients.
- **64-66** use a deterministic 2×2 high-frequency parity relation appropriate to the lab's DFT/FFT/Walsh demonstration.
- **67** performs an actual NumPy SVD on 8×8 blue-channel blocks and embeds parity in a quantized leading singular value.
- **68-73** delegate to the DCT carrier and do not reproduce full contourlet, curvelet, or multi-transform hybrid pipelines.

### Spread-spectrum and quantization approximations

- **74-76** implement an independent deterministic correlation/spreading demonstration.
- **77 — QIM** is a concrete scalar quantization-index carrier.
- **78 — Dither Modulation** adds deterministic key-derived lattice offsets and requires the same key for extraction.
- **79-80** delegate to the spread-spectrum/correlation carrier.

### Content-adaptive research-name approximations

- **81-92** use local texture as a distortion proxy and embed through the edge/texture-adaptive LSB carrier. Published HUGO/WOW/UNIWARD/HILL/MiPOD cost functions, STC optimizers, GMRF models, and related reference machinery are not reproduced.

### Coding approximations

- **93-94** implement concrete Hamming-style matrix/syndrome embedding: 3 message bits per 7 cover samples with at most one LSB flip per group.
- **95-100** delegate to that Hamming carrier. They do not claim BCH, Reed-Solomon, LDPC, wet-paper, or canonical STC compatibility.

### Palette approximations

- **101-102** directly modify palette component parity/LSBs.
- **103-105** use the palette carrier as an educational approximation rather than reproducing canonical palette permutation or EZStego ordering.

### Neural and coverless entries

- **106-119** are `REQUIRES_TRAINED_MODEL` registry/provider stubs.
- **120-123, 127-128** are `EXPERIMENTAL` provider-required entries that need an external corpus/index/synthesis provider.
- **124-126** are generative entries requiring trained model weights.

These entries fail with a clear dependency/provider error instead of silently substituting a fake neural model or downloading large weights. The current CLI does not expose a model/provider loader argument; making these entries executable requires extending or replacing the provider stub in code.

## Payload Format

Every normal encode workflow uses the same binary frame. Raw UTF-8 message bytes are never placed into a carrier without framing.

### Binary layout

The fixed header is **18 bytes**:

| Field | Size | Description |
|---|---:|---|
| `MAGIC` | 4 bytes | `ISL1` |
| `VERSION` | 1 byte | Payload format version; currently `1` |
| `ALGORITHM_ID` | 2 bytes | Registry algorithm ID |
| `FLAGS` | 1 byte | Compression/encryption bit flags |
| `SALT_LEN` | 1 byte | Encryption salt length |
| `NONCE_LEN` | 1 byte | AES-GCM nonce length |
| `DATA_LEN` | 4 bytes | Stored payload-data length |
| `CRC32` | 4 bytes | CRC32 of the stored data bytes |
| `SALT` | variable | Empty when encryption is disabled |
| `NONCE` | variable | Empty when encryption is disabled |
| `STORED_DATA` | variable | Compressed plaintext or AES-GCM ciphertext |

The struct layout is big-endian:

```text
>4sBHBBBII
```

Flags:

```text
0x01 = compressed
0x02 = encrypted
```

### Encode pipeline

```text
UTF-8 text
    ↓
zlib compression (default)
    ↓
optional AES-256-GCM encryption
    ↓
header (including CRC32) + salt + nonce + stored data
    ↓
selected steganographic carrier
```

### Decode pipeline

```text
carrier extraction
    ↓
magic/version/algorithm/length validation
    ↓
CRC32 validation
    ↓
optional AES-GCM decryption/authentication
    ↓
optional zlib decompression
    ↓
UTF-8 decoding
    ↓
recovered text
```

The decoder rejects invalid magic, unsupported payload versions, algorithm-ID mismatches, truncated payloads, CRC failures, authentication failures, and invalid UTF-8 instead of printing arbitrary carrier bytes as a message.

## Compression

Compression is enabled by default and uses `zlib`.

Disable it with:

```bash
--no-compress
```

Compression occurs **before encryption**. This is important because encrypted bytes are intentionally high-entropy and are generally not compressible.

Compression can substantially improve effective capacity for repetitive text, but very short or already-compressed-looking text may become slightly larger because zlib has its own framing overhead.

## Password Encryption

Password protection is optional and requires the `cryptography` package.

Implementation details:

- Cipher: **AES-256-GCM**
- KDF: **PBKDF2-HMAC-SHA256**
- Derived key length: **32 bytes / 256 bits**
- PBKDF2 iterations: **240,000**
- Salt: **16 random bytes** per encryption
- Nonce: **12 random bytes** per encryption
- AES-GCM associated data: payload magic `ISL1`
- Passwords are never stored in the payload

Install encryption support:

```bash
python -m pip install cryptography
```

Use it interactively or with:

```bash
python image_steganography_lab.py encode \
  -a lsb \
  -i cover.png \
  --message "secret" \
  --encrypt
```

### Password handling recommendation

The program internally accepts a hidden `--password` argument for automation, but it is intentionally omitted from normal CLI help. Passing secrets directly on a command line can expose them through shell history or process inspection. Prefer the secure terminal prompt whenever possible.

### What encryption does not hide

The common payload header is not encrypted. The algorithm ID, flags, payload length fields, salt, and nonce remain part of the frame. AES-GCM protects the message data, not the existence of the steganographic frame itself.

## Carrier Keys vs Encryption Passwords

These are separate concepts.

### Carrier key: `--key`

A carrier key controls **where or how bits are embedded**. It does not provide cryptographic confidentiality by itself.

Required by:

- **21 — Keyed / Pseudorandom LSB**
- **78 — Dither Modulation**

Optionally useful for:

- **74 — Spread Spectrum Steganography**
- **75 — Direct-Sequence Spread Spectrum**
- **76 — Transform-Domain Spread Spectrum**
- **79 — Patchwork**
- **80 — Correlation-Based Embedding**

The carrier sequences are deterministic so the encoder and decoder can reproduce the same positions. The seed is derived from SHA-256 rather than Python's process-randomized `hash()`.

The PRNG used for carrier ordering is `random.Random`, so **do not treat a carrier key as a substitute for AES-GCM encryption**.

### Encryption password

The encryption password protects the content itself using AES-256-GCM and is independent of carrier selection.

You may use both simultaneously:

```bash
python image_steganography_lab.py encode \
  -a keyed-lsb \
  -i cover.png \
  --message "private text" \
  --key "carrier-key" \
  --encrypt \
  -o encoded.png
```

Decoding requires the same carrier key and, for encrypted payloads, the correct encryption password.

## Image and File Format Behavior

### Pixel-domain algorithms

Most spatial, PVD, adaptive, transform, QIM, coding, and related carriers require lossless output.

Recommended output formats:

- PNG
- BMP
- TIFF

JPEG output is rejected for lossless-required carrier paths because JPEG recompression can alter the exact samples or transform values used to store bits.

### JPEG input

Algorithm **49 — Basic DCT Coefficient Embedding** accepts JPEG input, decodes it to image samples, performs the lab's DCT operation, and writes a **lossless** output such as PNG/BMP/TIFF. It does not edit the JPEG entropy-coded DCT stream in place.

Container methods **1-5** can operate on JPEG-format metadata/segments without recompressing its visible scan data where applicable.

### PNG container methods

Algorithms 6-9 parse and rebuild PNG chunks with valid chunk CRCs:

- `tEXt`
- `zTXt`
- `iTXt`
- private ancillary chunk `stEg`

Existing parsed chunks are preserved and the new payload chunk is inserted before `IEND`.

### JPEG container methods

- Algorithm 4 uses a JPEG `COM` segment.
- Algorithm 5 uses APP15.
- Algorithm 2 places an XMP-style document in APP1.
- Algorithm 3 places an educational IPTC-style payload in APP13.

Each inserted JPEG segment respects the legal 16-bit segment-length limit.

### EXIF

Algorithm 1 stores base64-framed data in EXIF `UserComment` tag `37510` using Pillow. The implementation supports JPEG, TIFF, and WebP when Pillow can save the target with EXIF.

### GIF

Algorithm 10 writes a standards-compatible GIF comment extension using legal 255-byte sub-blocks.

### EOF/trailing data

Algorithms 11 and 12 append an integrity-tagged trailer without changing decoded image pixels. Some editors, upload pipelines, optimizers, and content-delivery systems may strip trailing bytes.

### Alpha-channel embedding

Algorithm 13 requires RGBA input and modifies alpha-channel samples.

### Transparent-pixel embedding

Algorithm 14 requires RGBA PNG input and uses RGB LSBs only for pixels whose alpha value is exactly zero. Image optimization software may normalize RGB values under fully transparent pixels and destroy this payload.

### Palette methods

Algorithms 101-105 require `P`-mode indexed images. Their payload capacity is small because a typical RGB palette contains only 768 component values.

### Image mode conversion

The interactive and CLI layers detect non-RGB/RGBA inputs for ordinary pixel algorithms.

In CLI mode, intentional conversion requires:

```bash
--allow-conversion
```

Example:

```bash
python image_steganography_lab.py encode \
  -a lsb \
  -i grayscale.png \
  --message "test" \
  --allow-conversion
```

When using the Python classes directly, the lower-level helper may convert compatible modes without the CLI confirmation layer. Applications embedding this module should implement their own confirmation policy if representation changes matter.

## Capacity Estimation

Before normal encoding, the program:

1. Estimates the selected carrier's capacity.
2. Builds the complete framed payload using the chosen compression/encryption settings.
3. Compares required bytes against available bytes.
4. Refuses to partially embed an oversized payload.

Example:

```text
Algorithm:              LSB Replacement / LSB Substitution
Image dimensions:       1920 × 1080
Available capacity:     ... bytes
Required capacity:      ... bytes
Utilization:            ...%
```

### Capacity is algorithm-specific

Examples from the registry:

| Technique | Approximate carrier capacity |
|---|---|
| LSB replacement | ~3 bits per RGB pixel |
| Two-bit/multi-bit LSB | ~6 bits per RGB pixel |
| Pixel Indicator | 2 bits per pixel |
| PVD | Variable, approximately 3-7 bits per eligible pair |
| Edge-adaptive LSB | ~65% of the RGB-LSB carrier |
| DCT | 1 bit per complete 8×8 block |
| Haar DWT/IWT | 1 bit per 2×2 block |
| SVD | 1 bit per 8×8 block |
| QIM | 1 bit per blue sample |
| Hamming matrix embedding | 3 payload bits per 7 cover samples |
| Palette methods | Usually at most ~96 raw carrier bytes for a 256-color RGB palette |

Container-method capacities are intentionally approximate and conservative/implementation-defined. The actual framed payload must still satisfy the method's format limits.

Remember that usable message length is smaller than raw carrier capacity because the payload frame adds at least **18 bytes**, plus encryption salt/nonce/ciphertext authentication overhead when encryption is enabled.

## Verification and Integrity Checking

`verify` is stricter than simply printing extracted bytes. It checks:

- framing magic
- framing version
- selected algorithm ID
- stored length
- CRC32
- AES-GCM authentication when encrypted
- decompression integrity
- UTF-8 decoding
- optional exact text match

If an image has been modified or the wrong algorithm/key is used, the usual result is a controlled error such as:

```text
No valid embedded message found.
```

or a checksum/algorithm/password error. The application does not print arbitrary decoded garbage as if it were a valid message.

## Output Naming and Overwrite Protection

When `--output` is omitted, the program builds a name from the input stem and algorithm slug.

Example for LSB:

```text
photo.png
→ photo_stego_lsb.png
```

Example for a container method:

```text
photo.jpg
→ photo_stego_jpeg-com.jpg
```

For algorithms marked `lossless_required`, the default extension is `.png`.

CLI mode refuses to overwrite an existing output file or the source file unless `--overwrite` is explicitly supplied.

```bash
python image_steganography_lab.py encode \
  -a lsb \
  -i cover.png \
  --message "replace existing output" \
  -o encoded.png \
  --overwrite
```

## Self-Test Suite

Run:

```bash
python image_steganography_lab.py --self-test
```

The built-in suite creates temporary in-memory/generated images and performs encode → save/reload → decode round trips.

It covers representative core algorithms including:

- LSB replacement
- LSB matching
- keyed LSB
- multi-bit LSB
- parity
- PVD
- edge-adaptive LSB
- PNG private chunk storage
- EOF storage
- DCT
- histogram shifting
- DWT
- IWT
- DFT
- Walsh-Hadamard
- SVD
- QIM
- matrix encoding
- EXIF
- alpha-channel storage
- transparent-pixel storage
- palette LSB

Payload cases include:

- ASCII: `Hello World`
- Persian: `سلام دنیا`
- Arabic: `مرحبا بالعالم`
- Emoji: `Hello 🌍 🔐`
- multiline text
- empty messages
- messages close to capacity
- oversized messages
- wrong decoding algorithm
- wrong password when `cryptography` is available
- damaged encoded image/checksum failure
- RGBA input
- grayscale conversion
- large PNG input
- JPEG input for DCT

### Current validation result

The generated project file was executed with its built-in self-test and produced:

```text
Passed: 37  Failed: 0  Total: 37
```

The wrong-password test is conditional on `cryptography`; an installation without that optional package will run one fewer test.

The self-test is a regression/symmetry check, not a scientific steganalysis, perceptual-quality, or robustness benchmark.

## Programmatic Use

Although the project is designed primarily as a CLI application, the classes and registry can also be imported.

```python
from pathlib import Path
import image_steganography_lab as isl

algorithm = isl.resolve_algorithm("lsb")

report = algorithm.encode_message(
    Path("cover.png"),
    Path("encoded.png"),
    "Hello from Python",
    compress=True,
)

result = algorithm.decode_message(Path("encoded.png"))
print(result.message)
```

### Keyed carrier

```python
algorithm = isl.resolve_algorithm("keyed-lsb")

algorithm.encode_message(
    Path("cover.png"),
    Path("encoded.png"),
    "secret",
    key="carrier-passphrase",
)

result = algorithm.decode_message(
    Path("encoded.png"),
    key="carrier-passphrase",
)
```

### Encrypted payload

```python
algorithm = isl.resolve_algorithm("lsb")

algorithm.encode_message(
    Path("cover.png"),
    Path("encoded.png"),
    "secret",
    password="strong password",
)

result = algorithm.decode_message(
    Path("encoded.png"),
    password="strong password",
)
```

For application code, avoid hard-coding real passwords in source files; the examples above only demonstrate the API shape.

## Architecture

The file is structured around a small set of reusable abstractions.

### Core data structures

- `AlgorithmStatus`
- `AlgorithmInfo`
- `DecodedPayload`
- `EncodeReport`

### Error types

- `StegoError`
- `InvalidPayloadError`
- `CapacityError`
- `DependencyError`
- `ImageCompatibilityError`
- `PasswordError`

### Payload/security layer

- `CryptoHelper`
- `PayloadCodec`

### Image utility layer

- `ImageHelper`

### Algorithm interface

Every algorithm object conforms to:

```python
class SteganographyAlgorithm(ABC):
    def estimate_capacity(...): ...
    def encode_payload(...): ...
    def extract_payload(...): ...
```

`encode_message()` and `decode_message()` live on the base class and provide shared framing, capacity enforcement, integrity validation, compression, and encryption behavior.

### Concrete carrier classes

- `LSBAlgorithm`
- `LSBMRAlgorithm`
- `PixelIndicatorAlgorithm`
- `TransparentPixelAlgorithm`
- `PVDAlgorithm`
- `EdgeAdaptiveAlgorithm`
- `HistogramShiftAlgorithm`
- `DCTAlgorithm`
- `TransformParityAlgorithm`
- `HaarWaveletAlgorithm`
- `SVDAlgorithm`
- `QIMAlgorithm`
- `SpreadSpectrumAlgorithm`
- `HammingMatrixAlgorithm`
- `ContainerAlgorithm`
- `PaletteLSBAlgorithm`
- `EducationalAdapter`
- `ProviderRequiredAlgorithm`

### Registry

The registry is data-driven:

```python
ALGORITHMS: dict[int, SteganographyAlgorithm]
SLUG_TO_ID: dict[str, int]
```

All 128 requested IDs are checked at startup. Registry construction raises an error if an ID is missing.

This design avoids a large algorithm-selection `if/elif` chain and makes it possible to extend the project by adding a class or delegate plus an `AlgorithmInfo` entry.

## Security and Safety Model

The project deliberately treats hidden content only as **data**.

It does **not**:

- execute recovered content;
- use `eval()` or `exec()` on payload data;
- execute shell commands from extracted content;
- call `os.system()` for payload execution;
- spawn subprocesses to execute recovered payloads;
- dynamically import code named by a payload;
- create exploit-oriented malformed image files;
- implement persistence, command-and-control, malware delivery, or automatic execution;
- automatically download neural weights or large external models.

The safe polyglot demonstration stores a framed payload inside an appended ZIP archive as inert bytes only.

### Steganography is not encryption

A hidden message may still be detectable by metadata inspection, statistical steganalysis, known-format scanning, or comparison against the original image. If message confidentiality matters, enable AES-GCM encryption as well.

### Integrity is not the same as secrecy

CRC32 detects accidental/intentional payload changes but is not a cryptographic authentication mechanism. Encrypted payloads additionally receive AES-GCM authentication.

## Known Limitations

1. **No automatic algorithm detection.** Decode and verify require the same algorithm selection used for encoding.
2. **Most pixel-domain techniques are fragile.** JPEG recompression, resizing, filtering, color conversion, cropping, optimization, and social-media processing can destroy embedded bits.
3. **Container metadata can be stripped.** Metadata cleaners and image pipelines often remove EXIF/XMP/comments/custom chunks/trailing bytes.
4. **Educational research-name algorithms are not reference-compatible.** Use them to study concepts and encode/decode symmetry, not to reproduce published benchmark results.
5. **RDH entries 43-48 are not truly reversible in this build.** They do not restore the exact pristine cover image.
6. **Neural/generative methods are not bundled.** IDs 106-128 require external models, corpora, indices, or providers and intentionally refuse to fabricate them. The standalone CLI does not currently include a model/provider loading hook, so these entries require code extension before they can execute.
7. **No arbitrary-file CLI payload.** The normal interface is designed for UTF-8 text. Lower-level carrier methods operate on framed bytes, but the standard public workflow is text-oriented.
8. **No steganalysis detector is bundled.** The project compares qualitative properties but does not estimate probability of detection.
9. **No robustness benchmark is bundled.** Comparison-screen ratings are qualitative metadata, not measured PSNR/SSIM/BER or attack-survival scores.
10. **No error-correcting outer payload layer.** Coding algorithms in the registry illustrate embedding concepts; the common payload itself relies on checksum/authentication rather than forward error correction.
11. **Carrier keys are not cryptographic encryption.** Keyed position generation uses a deterministic standard-library PRNG seeded from SHA-256.
12. **Palette capacity is very small.** Framing overhead can consume a significant fraction of available palette carrier bytes.
13. **Histogram shifting depends on image statistics.** The educational implementation needs an empty histogram bin and sufficient peak-bin capacity.
14. **Transform methods are laboratory implementations.** DCT/SVD/Haar operations are designed for reproducible local experiments, not interchange with third-party steganography tools.
15. **Capacity estimates for some container methods are approximate.** Format limits and actual payload framing still apply.
16. **The common header is visible to a successful extractor.** Encryption protects message content, not all payload metadata.

## Troubleshooting

| Problem / message | Likely cause | Action |
|---|---|---|
| `Missing required dependencies` | Pillow or NumPy is not installed | `python -m pip install pillow numpy` |
| Encryption requires `cryptography` | AES-GCM support is unavailable | `python -m pip install cryptography` |
| Canny is shown as educational | OpenCV is unavailable | `python -m pip install opencv-python` |
| `No valid embedded message found.` | Wrong algorithm/key, unencoded file, stripped payload, or modified image | Confirm algorithm, key, and original encoded file |
| `Payload belongs to algorithm id ...` | Correct carrier bytes were found but the selected algorithm ID is wrong | Decode with the algorithm used during encoding |
| `Payload checksum verification failed.` | Embedded bytes changed after encoding | Use the original lossless output; avoid transformations |
| `Wrong password or encrypted payload is corrupted.` | Wrong AES password or damaged ciphertext | Retry with the correct password/original file |
| `Payload is too large` | Framed message exceeds carrier capacity | Use a larger image, shorter message, compression, or higher-capacity carrier |
| JPEG compression warning/error | A lossless-required algorithm was targeted at JPEG output | Save as PNG, BMP, or TIFF |
| `Alpha-channel embedding requires an RGBA image.` | Algorithm 13 needs alpha data | Use an RGBA source |
| `Not enough fully transparent pixels.` | Algorithm 14 has too few `alpha=0` pixels | Use a suitable transparent PNG or another algorithm |
| Palette method requires `P` mode | Input is not indexed-color | Use a palette PNG/GIF or another carrier |
| Histogram has no empty bin | Algorithm 40 cannot create its shift interval safely | Try a different image or technique |
| Model/provider requirement error | Selected ID is 106-128 | Choose an executable algorithm, or extend the code with a compatible local model/corpus/provider implementation; the current CLI has no provider-loader option |
| Output already exists | CLI protects existing files | Choose another output path or add `--overwrite` |

### Use debug mode for diagnosis

```bash
python image_steganography_lab.py --debug decode \
  -a lsb \
  -i encoded.png
```

Normal users receive concise error messages; debug mode prints full exception information.

## Extending the Lab

To add a new executable carrier:

1. Subclass `SteganographyAlgorithm`.
2. Implement `estimate_capacity()`.
3. Implement `encode_payload()`.
4. Implement `extract_payload()`.
5. Add a complete `AlgorithmInfo` record.
6. Register the instance in `build_algorithm_registry()`.
7. Preserve the common `PayloadCodec` instead of inventing a separate text format unless there is a strong compatibility reason.
8. Add round-trip tests to `run_self_tests()`.
9. Mark research approximations as `EDUCATIONAL` rather than claiming canonical compatibility.
10. Keep extracted content inert and never auto-execute it.
11. Do not silently download trained models or packages.
12. Keep encode/decode carrier selection deterministic when extraction requires reconstructing positions.

A minimal carrier skeleton looks like:

```python
class MyAlgorithm(SteganographyAlgorithm):
    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        ...

    def encode_payload(
        self,
        input_path: Path,
        output_path: Path,
        payload: bytes,
        **kwargs: Any,
    ) -> None:
        ...

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        ...
```

The base-class `encode_message()` / `decode_message()` methods then provide the shared framing, compression, encryption, checksum, and algorithm-ID checks.

## License

No license file is bundled with the current single-file project. Before publishing or redistributing the project, add an explicit `LICENSE` file that matches the intended usage and distribution terms.

---

## Responsible Use

Use this project only on files and systems you are authorized to modify and for legitimate educational, research, privacy, watermarking, interoperability, and data-hiding work. The project is a laboratory for studying information hiding; it is not designed to execute hidden content or to act as a malware delivery mechanism.
