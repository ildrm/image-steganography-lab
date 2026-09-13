#!/usr/bin/env python3
"""image_steganography_lab.py

A single-file, menu-driven image steganography laboratory for legitimate
education, research, privacy, watermarking, and data-hiding experiments.

Safety boundary
---------------
Embedded content is always treated as inert DATA.  This program never executes
recovered content and never uses eval(), exec(), os.system(), subprocesses,
dynamic imports based on payload content, or shell execution of extracted data.

The program deliberately distinguishes practical implementations from
educational approximations and model/provider stubs.  Published research names
are used descriptively; educational implementations are independent and are not
claimed to be bit-compatible with canonical/reference implementations.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import io
import logging
import math
import os
import random
import struct
import sys
import textwrap
import zlib
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# ---------------------------------------------------------------------------
# Dependency discovery
# ---------------------------------------------------------------------------

MISSING_REQUIRED: list[str] = []
try:
    from PIL import Image, ImageFile, PngImagePlugin
except Exception:  # pragma: no cover - handled by startup check
    MISSING_REQUIRED.append("pillow")
    Image = None  # type: ignore[assignment]
    ImageFile = None  # type: ignore[assignment]
    PngImagePlugin = None  # type: ignore[assignment]

try:
    import numpy as np
except Exception:  # pragma: no cover - handled by startup check
    MISSING_REQUIRED.append("numpy")
    np = None  # type: ignore[assignment]

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None  # type: ignore[assignment]

try:
    import pywt  # type: ignore
except Exception:
    pywt = None  # type: ignore[assignment]

try:
    from cryptography.exceptions import InvalidTag  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
except Exception:
    InvalidTag = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    AESGCM = None  # type: ignore[assignment]
    PBKDF2HMAC = None  # type: ignore[assignment]


PROGRAM_NAME = "IMAGE STEGANOGRAPHY LAB"
MAGIC = b"ISL1"
PAYLOAD_VERSION = 1
FLAG_COMPRESSED = 0x01
FLAG_ENCRYPTED = 0x02
# magic, version, algorithm id, flags, salt len, nonce len, data len, CRC32
HEADER_STRUCT = struct.Struct(">4sBHBBBII")
HEADER_SIZE = HEADER_STRUCT.size
DEFAULT_KDF_ITERATIONS = 240_000
DEFAULT_QIM_STEP = 18
LOGGER = logging.getLogger("image_steganography_lab")


# ---------------------------------------------------------------------------
# Enumerations and data classes
# ---------------------------------------------------------------------------

class AlgorithmStatus(str, Enum):
    FULL = "FULL"
    EDUCATIONAL = "EDUCATIONAL"
    EXPERIMENTAL = "EXPERIMENTAL"
    REQUIRES_OPTIONAL_DEPENDENCY = "REQUIRES_OPTIONAL_DEPENDENCY"
    REQUIRES_TRAINED_MODEL = "REQUIRES_TRAINED_MODEL"


class StegoError(Exception):
    """Base class for user-facing steganography errors."""


class InvalidPayloadError(StegoError):
    """Raised when framing, length, algorithm id, or checksum is invalid."""


class CapacityError(StegoError):
    """Raised before embedding when the complete framed payload will not fit."""


class DependencyError(StegoError):
    """Raised when a selected technique requires an unavailable dependency."""


class ImageCompatibilityError(StegoError):
    """Raised when an image format or mode is incompatible with an algorithm."""


class PasswordError(StegoError):
    """Raised for missing or incorrect encryption passwords."""


@dataclass(frozen=True)
class AlgorithmInfo:
    """Human- and machine-readable description of one registered algorithm.

    The registry is intentionally data-driven rather than a giant if/elif chain.
    Every one of the 128 requested entries has an AlgorithmInfo instance and an
    algorithm object.  `status` is especially important: FULL means the carrier
    is implemented as a practical self-contained technique; EDUCATIONAL means a
    documented approximation; REQUIRES_TRAINED_MODEL means no fabricated model
    is provided and execution is blocked until a compatible local provider exists.
    """

    id: int
    slug: str
    name: str
    category: str
    status: AlgorithmStatus
    supported_input_formats: tuple[str, ...]
    supported_output_formats: tuple[str, ...]
    lossless_required: bool
    reversible: bool
    approximate_capacity: str
    robustness: str
    notes: str
    concept: str = ""
    mathematical_idea: str = ""
    encoding_process: str = ""
    decoding_process: str = ""
    advantages: str = ""
    disadvantages: str = ""
    detectability: str = ""
    compression_resistance: str = "Low"
    resize_resistance: str = "Very Low"
    cropping_resistance: str = "Very Low"
    steganalysis_resistance: str = "Medium"
    computational_cost: str = "Low"


@dataclass
class DecodedPayload:
    message: str
    algorithm_id: int
    compressed: bool
    encrypted: bool
    stored_data_bytes: int
    plaintext_bytes: int
    checksum_valid: bool = True


@dataclass
class EncodeReport:
    algorithm: str
    input_path: Path
    output_path: Path
    dimensions: tuple[int, int] | None
    input_size: int
    output_size: int
    payload_bytes: int
    capacity_bytes: int
    compressed: bool
    encrypted: bool


# ---------------------------------------------------------------------------
# Generic bit/byte helpers
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> list[int]:
    """Expand bytes MSB-first so carrier algorithms share one bit convention."""
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack an MSB-first bit sequence; incomplete trailing bits are ignored."""
    usable = len(bits) - (len(bits) % 8)
    out = bytearray(usable // 8)
    for i in range(0, usable, 8):
        value = 0
        for bit in bits[i : i + 8]:
            value = (value << 1) | (int(bit) & 1)
        out[i // 8] = value
    return bytes(out)


def chunks(seq: Sequence[int], size: int) -> Iterator[Sequence[int]]:
    for start in range(0, len(seq), size):
        yield seq[start : start + size]


def stable_seed(secret: str, context: str = "") -> int:
    """Derive a persistent deterministic PRNG seed using SHA-256, never hash()."""
    digest = hashlib.sha256((context + "\0" + secret).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    x = float(value)
    for unit in units:
        if x < 1024.0 or unit == units[-1]:
            return f"{x:.1f} {unit}" if unit != "B" else f"{int(x)} B"
        x /= 1024.0
    return f"{value} B"


def output_default(input_path: Path, suffix: str, extension: str | None = None) -> Path:
    ext = extension if extension else input_path.suffix
    return input_path.with_name(f"{input_path.stem}_stego_{suffix}{ext}")


def safe_random_delta(value: int, rng: random.Random) -> int:
    """Return value±1 without overflowing a byte; used by matching techniques."""
    if value <= 0:
        return 1
    if value >= 255:
        return 254
    return value + (1 if rng.getrandbits(1) else -1)


def require_core_dependencies() -> None:
    if MISSING_REQUIRED:
        missing = " ".join(MISSING_REQUIRED)
        raise DependencyError(
            f"Missing required dependencies: {', '.join(MISSING_REQUIRED)}.\n"
            f"Install with: python -m pip install {missing}"
        )


def report_optional_dependencies() -> None:
    """Report unavailable optional features once at startup; never auto-install."""
    missing: list[str] = []
    if cv2 is None:
        missing.append("opencv-python (true Canny edge selection)")
    if pywt is None:
        missing.append("PyWavelets (optional wavelet research experiments)")
    if not CryptoHelper.available():
        missing.append("cryptography (AES-256-GCM password protection)")
    if missing:
        LOGGER.info("Optional dependencies unavailable: %s", "; ".join(missing))
        packages = []
        if cv2 is None:
            packages.append("opencv-python")
        if pywt is None:
            packages.append("PyWavelets")
        if not CryptoHelper.available():
            packages.append("cryptography")
        LOGGER.info("Install optional features with: python -m pip install %s", " ".join(packages))


# ---------------------------------------------------------------------------
# Payload framing, compression, encryption, integrity
# ---------------------------------------------------------------------------

class CryptoHelper:
    """Optional authenticated encryption helper using AES-256-GCM only.

    There is intentionally no home-made cipher fallback.  If `cryptography` is
    unavailable, the UI tells the user how to install it and can continue only
    without encryption.  PBKDF2-HMAC-SHA256 turns a password into a 256-bit key;
    a random salt prevents identical passwords from yielding identical keys.
    """

    @staticmethod
    def available() -> bool:
        return AESGCM is not None and PBKDF2HMAC is not None and hashes is not None

    @staticmethod
    def encrypt(data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
        if not CryptoHelper.available():
            raise DependencyError(
                "Encryption requires the 'cryptography' package. Install with: "
                "python -m pip install cryptography"
            )
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=DEFAULT_KDF_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
        return ciphertext, salt, nonce

    @staticmethod
    def decrypt(data: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
        if not CryptoHelper.available():
            raise DependencyError(
                "Decryption requires the 'cryptography' package. Install with: "
                "python -m pip install cryptography"
            )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=DEFAULT_KDF_ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        try:
            return AESGCM(key).decrypt(nonce, data, MAGIC)
        except Exception as exc:
            # InvalidTag is intentionally translated into a small user-facing error;
            # callers never receive a cryptographic traceback in normal mode.
            raise PasswordError("Wrong password or encrypted payload is corrupted.") from exc


class PayloadCodec:
    """Build and validate the common binary payload used by every carrier.

    Format::

        MAGIC(4) | VERSION(1) | ALGORITHM_ID(2) | FLAGS(1)
        SALT_LEN(1) | NONCE_LEN(1) | DATA_LEN(4) | CRC32(4)
        SALT | NONCE | STORED_DATA

    CRC32 protects exactly the stored byte sequence (compressed plaintext or
    AES-GCM ciphertext).  Authenticated encryption additionally protects the
    encrypted form.  UTF-8 conversion happens only after decryption/decompression,
    so Persian, Arabic, emoji, and multiline messages are supported naturally.
    """

    @staticmethod
    def pack(
        message: str,
        algorithm_id: int,
        compress: bool = True,
        password: str | None = None,
    ) -> bytes:
        raw = message.encode("utf-8")
        flags = 0
        data = raw
        if compress:
            data = zlib.compress(data)
            flags |= FLAG_COMPRESSED

        salt = b""
        nonce = b""
        if password is not None:
            data, salt, nonce = CryptoHelper.encrypt(data, password)
            flags |= FLAG_ENCRYPTED

        checksum = zlib.crc32(data) & 0xFFFFFFFF
        header = HEADER_STRUCT.pack(
            MAGIC,
            PAYLOAD_VERSION,
            algorithm_id,
            flags,
            len(salt),
            len(nonce),
            len(data),
            checksum,
        )
        return header + salt + nonce + data

    @staticmethod
    def expected_total_length(prefix: bytes) -> int:
        if len(prefix) < HEADER_SIZE:
            raise InvalidPayloadError("No valid embedded message found.")
        magic, version, _algorithm_id, _flags, salt_len, nonce_len, data_len, _crc = HEADER_STRUCT.unpack(
            prefix[:HEADER_SIZE]
        )
        if magic != MAGIC or version != PAYLOAD_VERSION:
            raise InvalidPayloadError("No valid embedded message found.")
        if salt_len > 64 or nonce_len > 64 or data_len > 1_000_000_000:
            raise InvalidPayloadError("No valid embedded message found.")
        return HEADER_SIZE + salt_len + nonce_len + data_len

    @staticmethod
    def unpack(
        framed: bytes,
        expected_algorithm_id: int | None = None,
        password: str | None = None,
    ) -> DecodedPayload:
        if len(framed) < HEADER_SIZE:
            raise InvalidPayloadError("No valid embedded message found.")
        magic, version, algorithm_id, flags, salt_len, nonce_len, data_len, checksum = HEADER_STRUCT.unpack(
            framed[:HEADER_SIZE]
        )
        if magic != MAGIC or version != PAYLOAD_VERSION:
            raise InvalidPayloadError("No valid embedded message found.")
        if expected_algorithm_id is not None and algorithm_id != expected_algorithm_id:
            raise InvalidPayloadError(
                f"Payload belongs to algorithm id {algorithm_id}, not {expected_algorithm_id}."
            )

        total = HEADER_SIZE + salt_len + nonce_len + data_len
        if total > len(framed):
            raise InvalidPayloadError("Embedded payload is truncated.")
        cursor = HEADER_SIZE
        salt = framed[cursor : cursor + salt_len]
        cursor += salt_len
        nonce = framed[cursor : cursor + nonce_len]
        cursor += nonce_len
        stored = framed[cursor : cursor + data_len]
        if (zlib.crc32(stored) & 0xFFFFFFFF) != checksum:
            raise InvalidPayloadError("Payload checksum verification failed.")

        encrypted = bool(flags & FLAG_ENCRYPTED)
        compressed = bool(flags & FLAG_COMPRESSED)
        data = stored
        if encrypted:
            if password is None:
                raise PasswordError("This payload is encrypted; a password is required.")
            data = CryptoHelper.decrypt(data, password, salt, nonce)
        if compressed:
            try:
                data = zlib.decompress(data)
            except zlib.error as exc:
                raise InvalidPayloadError("Compressed payload is corrupted.") from exc
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidPayloadError("Recovered payload is not valid UTF-8 text.") from exc

        return DecodedPayload(
            message=text,
            algorithm_id=algorithm_id,
            compressed=compressed,
            encrypted=encrypted,
            stored_data_bytes=len(stored),
            plaintext_bytes=len(data),
            checksum_valid=True,
        )

    @staticmethod
    def extract_framed_from_byte_stream(stream: bytes) -> bytes:
        """Validate a carrier byte stream and cut it to the exact framed length."""
        total = PayloadCodec.expected_total_length(stream[:HEADER_SIZE])
        if len(stream) < total:
            raise InvalidPayloadError("Embedded payload is truncated.")
        return stream[:total]


# ---------------------------------------------------------------------------
# Image utilities
# ---------------------------------------------------------------------------

class ImageHelper:
    @staticmethod
    def open_image(path: Path) -> Any:
        require_core_dependencies()
        if not path.exists() or not path.is_file():
            raise ImageCompatibilityError(f"Input file does not exist: {path}")
        try:
            image = Image.open(path)
            image.load()
            if image.width <= 0 or image.height <= 0:
                raise ImageCompatibilityError("Image dimensions are invalid.")
            return image
        except StegoError:
            raise
        except Exception as exc:
            raise ImageCompatibilityError(f"Cannot open image: {exc}") from exc

    @staticmethod
    def format_name(image: Any, path: Path | None = None) -> str:
        fmt = (getattr(image, "format", None) or "").upper()
        if not fmt and path is not None:
            fmt = path.suffix.lstrip(".").upper()
        if fmt == "JPG":
            fmt = "JPEG"
        return fmt

    @staticmethod
    def ensure_rgb_or_rgba(image: Any, preserve_alpha: bool = True) -> Any:
        """Return an RGB/RGBA working copy without silently dropping alpha data."""
        if image.mode in ("RGB", "RGBA"):
            return image.copy()
        if image.mode == "L":
            return image.convert("RGB")
        if image.mode == "P":
            # Palette-to-RGB changes representation, so callers should surface this
            # conversion in the UI.  It is safe for visible pixels but not reversible.
            return image.convert("RGBA" if preserve_alpha and "transparency" in image.info else "RGB")
        return image.convert("RGBA" if preserve_alpha and "A" in image.getbands() else "RGB")

    @staticmethod
    def save_lossless(image: Any, output_path: Path, source_info: dict[str, Any] | None = None) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        ext = output_path.suffix.lower()
        if ext in (".jpg", ".jpeg"):
            raise ImageCompatibilityError(
                "This pixel-domain technique requires lossless output. JPEG compression may destroy "
                "the hidden message; use PNG, BMP, or TIFF."
            )
        kwargs: dict[str, Any] = {}
        if source_info:
            if "icc_profile" in source_info:
                kwargs["icc_profile"] = source_info["icc_profile"]
            if "dpi" in source_info:
                kwargs["dpi"] = source_info["dpi"]
        image.save(output_path, **kwargs)


# ---------------------------------------------------------------------------
# Algorithm abstraction
# ---------------------------------------------------------------------------

class SteganographyAlgorithm(ABC):
    """Stable interface used by interactive mode, argparse, verification, and tests."""

    def __init__(self, info: AlgorithmInfo) -> None:
        self.info = info

    @abstractmethod
    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        """Return approximate usable payload bytes, excluding payload framing."""
        raise NotImplementedError

    @abstractmethod
    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        """Embed already-framed bytes into a carrier image/file."""
        raise NotImplementedError

    @abstractmethod
    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        """Recover framed bytes only; PayloadCodec performs integrity/text decoding."""
        raise NotImplementedError

    def encode_message(
        self,
        input_path: Path,
        output_path: Path,
        message: str,
        *,
        compress: bool = True,
        password: str | None = None,
        **kwargs: Any,
    ) -> EncodeReport:
        payload = PayloadCodec.pack(message, self.info.id, compress=compress, password=password)
        capacity = self.estimate_capacity(input_path, **kwargs)
        if len(payload) > capacity:
            raise CapacityError(
                f"ERROR: Payload is too large for this image using this algorithm. "
                f"Required {len(payload)} bytes; capacity ≈ {capacity} bytes."
            )
        image_dims: tuple[int, int] | None = None
        try:
            image = ImageHelper.open_image(input_path)
            image_dims = (image.width, image.height)
        except StegoError:
            # File-container methods can still provide a useful report for byte carriers.
            image_dims = None
        self.encode_payload(input_path, output_path, payload, **kwargs)
        return EncodeReport(
            algorithm=self.info.name,
            input_path=input_path,
            output_path=output_path,
            dimensions=image_dims,
            input_size=input_path.stat().st_size,
            output_size=output_path.stat().st_size,
            payload_bytes=len(payload),
            capacity_bytes=capacity,
            compressed=compress,
            encrypted=password is not None,
        )

    def decode_message(
        self,
        input_path: Path,
        *,
        password: str | None = None,
        **kwargs: Any,
    ) -> DecodedPayload:
        framed = self.extract_payload(input_path, **kwargs)
        return PayloadCodec.unpack(framed, expected_algorithm_id=self.info.id, password=password)


# ============================================================
# LSB / SPATIAL-DOMAIN FAMILY
# ============================================================
# Principle:
#   Payload bits are stored in low-significance sample bits.  RGB values are the
#   modified image elements; alpha is preserved unless an alpha-specific method
#   is explicitly selected.  Lossless output is mandatory because JPEG's lossy
#   quantization changes sample values and therefore destroys exact bit payloads.
# Encoding/decoding:
#   A deterministic sequence of carrier samples is chosen, optionally shuffled
#   from a SHA-256-derived key.  The encoder changes only the selected bit planes;
#   the decoder reads the same planes in the same order and validates the common
#   framing header.  More bits per sample increase capacity and detectability.
# Reversibility:
#   Ordinary LSB methods recover the message but not the original sample values.
# ============================================================

class LSBAlgorithm(SteganographyAlgorithm):
    def __init__(
        self,
        info: AlgorithmInfo,
        *,
        bits_per_channel: int = 1,
        bit_plane: int = 0,
        keyed: bool = False,
        matching: bool = False,
        invert_payload_bit: bool = False,
        channels: str = "RGB",
    ) -> None:
        super().__init__(info)
        self.bits_per_channel = bits_per_channel
        self.bit_plane = bit_plane
        self.keyed = keyed
        self.matching = matching
        self.invert_payload_bit = invert_payload_bit
        self.channels = channels

    def _array_and_positions(self, input_path: Path, key: str | None = None) -> tuple[Any, list[int], Any]:
        image = ImageHelper.open_image(input_path)
        if self.channels == "A":
            if image.mode != "RGBA":
                raise ImageCompatibilityError("Alpha-channel embedding requires an RGBA image.")
            working = image.copy()
            arr = np.array(working, dtype=np.uint8)
            flat = arr.reshape(-1, 4)
            positions = [i * 4 + 3 for i in range(flat.shape[0])]
            linear = arr.reshape(-1)
        else:
            working = ImageHelper.ensure_rgb_or_rgba(image)
            arr = np.array(working, dtype=np.uint8)
            channel_count = arr.shape[2]
            usable = 3 if channel_count >= 3 else channel_count
            positions = [p * channel_count + c for p in range(arr.shape[0] * arr.shape[1]) for c in range(usable)]
            linear = arr.reshape(-1)
        if self.keyed:
            if not key:
                raise StegoError("This algorithm requires a passphrase/key.")
            rng = random.Random(stable_seed(key, f"alg:{self.info.id}"))
            rng.shuffle(positions)
        return working, positions, (arr, linear)

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, positions, _data = self._array_and_positions(input_path, kwargs.get("key"))
        return (len(positions) * self.bits_per_channel) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        working, positions, data = self._array_and_positions(input_path, kwargs.get("key"))
        arr, linear = data
        bits = bytes_to_bits(payload)
        capacity_bits = len(positions) * self.bits_per_channel
        if len(bits) > capacity_bits:
            raise CapacityError("Insufficient carrier capacity.")
        rng = random.Random(stable_seed(kwargs.get("key") or "", f"match:{self.info.id}"))

        if self.bits_per_channel == 1:
            plane = self.bit_plane
            mask = 1 << plane
            for pos, bit in zip(positions, bits):
                desired = bit ^ (1 if self.invert_payload_bit else 0)
                value = int(linear[pos])
                current = (value >> plane) & 1
                if current == desired:
                    continue
                if self.matching and plane == 0:
                    linear[pos] = safe_random_delta(value, rng)
                else:
                    linear[pos] = (value & ~mask) | (desired << plane)
        else:
            # Multi-bit LSB places b payload bits into the b least-significant
            # bits of each sample.  The final partial group is right-padded with
            # zeros; framing length prevents those padding bits from surfacing.
            mask = (1 << self.bits_per_channel) - 1
            cursor = 0
            for pos in positions:
                if cursor >= len(bits):
                    break
                group = bits[cursor : cursor + self.bits_per_channel]
                cursor += len(group)
                value_bits = 0
                for bit in group:
                    value_bits = (value_bits << 1) | bit
                value_bits <<= self.bits_per_channel - len(group)
                linear[pos] = (int(linear[pos]) & ~mask) | value_bits

        out = Image.fromarray(arr, mode=working.mode)
        ImageHelper.save_lossless(out, output_path, getattr(working, "info", None))

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _working, positions, data = self._array_and_positions(input_path, kwargs.get("key"))
        _arr, linear = data
        bits: list[int] = []
        if self.bits_per_channel == 1:
            plane = self.bit_plane
            inv = 1 if self.invert_payload_bit else 0
            bits = [((int(linear[pos]) >> plane) & 1) ^ inv for pos in positions]
        else:
            mask = (1 << self.bits_per_channel) - 1
            for pos in positions:
                value = int(linear[pos]) & mask
                for shift in range(self.bits_per_channel - 1, -1, -1):
                    bits.append((value >> shift) & 1)
        stream = bits_to_bytes(bits)
        return PayloadCodec.extract_framed_from_byte_stream(stream)


# ============================================================
# LSB MATCHING REVISITED (LSBMR)
# ============================================================
# Principle:
#   Two message bits are represented by a pair (x1,x2): bit1 is parity(x1),
#   bit2 is parity(floor(x1/2)+x2).  The encoder uses ±1 changes, usually fewer
#   direct substitutions than simple LSB replacement.  Decoding recomputes the
#   two parity equations.  It is still fragile under lossy recompression.
# ============================================================

class LSBMRAlgorithm(SteganographyAlgorithm):
    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channels = arr.shape[2]
        positions = [p * channels + c for p in range(arr.shape[0] * arr.shape[1]) for c in range(min(3, channels))]
        return image, (arr, positions)

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _img, (arr, positions) = self._load(input_path)
        return (len(positions) // 2 * 2) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, (arr, positions) = self._load(input_path)
        linear = arr.reshape(-1)
        bits = bytes_to_bits(payload)
        if len(bits) > (len(positions) // 2) * 2:
            raise CapacityError("Insufficient LSBMR capacity.")
        rng = random.Random(0x1A5B4D)
        bit_index = 0
        for i in range(0, len(positions) - 1, 2):
            if bit_index >= len(bits):
                break
            p1, p2 = positions[i], positions[i + 1]
            m1 = bits[bit_index]
            m2 = bits[bit_index + 1] if bit_index + 1 < len(bits) else 0
            bit_index += 2
            x1, x2 = int(linear[p1]), int(linear[p2])
            if (x1 & 1) != m1:
                candidates = [v for v in (x1 - 1, x1 + 1) if 0 <= v <= 255 and (v & 1) == m1]
                rng.shuffle(candidates)
                chosen = next((v for v in candidates if (((v // 2) + x2) & 1) == m2), candidates[0])
                x1 = chosen
            if (((x1 // 2) + x2) & 1) != m2:
                x2 = safe_random_delta(x2, rng)
            linear[p1], linear[p2] = x1, x2
        out = Image.fromarray(arr, mode=image.mode)
        ImageHelper.save_lossless(out, output_path, getattr(image, "info", None))

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, (arr, positions) = self._load(input_path)
        linear = arr.reshape(-1)
        bits: list[int] = []
        for i in range(0, len(positions) - 1, 2):
            x1, x2 = int(linear[positions[i]]), int(linear[positions[i + 1]])
            bits.append(x1 & 1)
            bits.append(((x1 // 2) + x2) & 1)
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# PIXEL INDICATOR TECHNIQUE
# ============================================================
# Red's two LSBs are an explicit indicator.  Before embedding, all red indicators
# are cleared, avoiding accidental false indicators during decoding.  Used pixels
# receive indicator 0b11 and carry one bit in green plus one bit in blue.  This is
# easy to decode but modifies more samples than ordinary LSB and is not reversible.
# ============================================================

class PixelIndicatorAlgorithm(SteganographyAlgorithm):
    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        return image, arr

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        image, _arr = self._load(input_path)
        return (image.width * image.height * 2) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr = self._load(input_path)
        pixels = arr.reshape(-1, arr.shape[2])
        bits = bytes_to_bits(payload)
        if len(bits) > len(pixels) * 2:
            raise CapacityError("Insufficient Pixel Indicator capacity.")
        pixels[:, 0] &= 0xFC
        cursor = 0
        for px in pixels:
            if cursor >= len(bits):
                break
            px[0] = (int(px[0]) & 0xFC) | 0x03
            px[1] = (int(px[1]) & 0xFE) | bits[cursor]
            cursor += 1
            if cursor < len(bits):
                px[2] = (int(px[2]) & 0xFE) | bits[cursor]
                cursor += 1
        ImageHelper.save_lossless(Image.fromarray(arr, mode=image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr = self._load(input_path)
        bits: list[int] = []
        for px in arr.reshape(-1, arr.shape[2]):
            if (int(px[0]) & 0x03) == 0x03:
                bits.extend([int(px[1]) & 1, int(px[2]) & 1])
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# TRANSPARENT-PIXEL STORAGE
# ============================================================
# Only RGB values belonging to fully transparent RGBA pixels are modified.  The
# visible rendered image normally remains unchanged because alpha=0 hides the RGB
# triplet, but software that normalizes hidden RGB values may destroy the payload.
# ============================================================

class TransparentPixelAlgorithm(SteganographyAlgorithm):
    def _positions(self, path: Path) -> tuple[Any, Any, list[tuple[int, int, int]]]:
        image = ImageHelper.open_image(path)
        if image.mode != "RGBA":
            raise ImageCompatibilityError("Transparent-pixel embedding requires RGBA input.")
        arr = np.array(image, dtype=np.uint8)
        positions: list[tuple[int, int, int]] = []
        ys, xs = np.where(arr[:, :, 3] == 0)
        for y, x in zip(ys.tolist(), xs.tolist()):
            positions.extend([(y, x, 0), (y, x, 1), (y, x, 2)])
        return image, arr, positions

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _img, _arr, positions = self._positions(input_path)
        return len(positions) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, positions = self._positions(input_path)
        bits = bytes_to_bits(payload)
        if len(bits) > len(positions):
            raise CapacityError("Not enough fully transparent pixels.")
        for (y, x, c), bit in zip(positions, bits):
            arr[y, x, c] = (int(arr[y, x, c]) & 0xFE) | bit
        ImageHelper.save_lossless(Image.fromarray(arr, "RGBA"), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, positions = self._positions(input_path)
        bits = [int(arr[y, x, c]) & 1 for y, x, c in positions]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))

# ============================================================
# PIXEL VALUE DIFFERENCING (PVD) FAMILY
# ============================================================
# Principle:
#   Pixels are processed in adjacent pairs.  The absolute difference d=|p1-p2|
#   chooses a range [l,u]; wider high-contrast ranges can represent more bits.
#   The payload value is encoded as d' = l + value.  Pair values are adjusted
#   around a preserved integer midpoint so decoding can recover d' and the same
#   range.  Smooth ranges therefore carry fewer bits than textured ranges.
# Safety/capacity:
#   Only pairs whose midpoint can represent every difference in the selected
#   range while remaining within a conservative 8-bit safety band are eligible.
#   This deterministic eligibility survives embedding and prevents clipping.
# Reversibility:
#   Message extraction is deterministic, but original pixel values are not kept;
#   this implementation is not reversible data hiding.
# ============================================================

class PVDAlgorithm(SteganographyAlgorithm):
    RANGES: tuple[tuple[int, int], ...] = (
        (0, 7),
        (8, 15),
        (16, 31),
        (32, 63),
        (64, 127),
        (128, 255),
    )

    def __init__(self, info: AlgorithmInfo, adaptive: bool = False) -> None:
        super().__init__(info)
        self.adaptive = adaptive

    @classmethod
    def _range_for_difference(cls, d: int) -> tuple[int, int]:
        for low, high in cls.RANGES:
            if low <= d <= high:
                return low, high
        return cls.RANGES[-1]

    @staticmethod
    def _bits_for_range(low: int, high: int) -> int:
        return int(math.floor(math.log2(high - low + 1)))

    @classmethod
    def _eligible(cls, p1: int, p2: int, low: int, high: int, adaptive: bool) -> bool:
        if adaptive and low < 16:
            return False
        midpoint = (p1 + p2) // 2
        half = math.ceil(high / 2)
        # The 8..247 margin makes the set stable after adjustment and avoids
        # boundary behavior where a decoder could classify a pair differently.
        return midpoint - half >= 8 and midpoint + half <= 247

    def _load(self, path: Path) -> tuple[Any, Any, list[int]]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channels = arr.shape[2]
        # PVD uses the blue channel for each horizontal pixel pair.  A single
        # channel limits visible color distortion and keeps pair geometry simple.
        positions = [p * channels + 2 for p in range(arr.shape[0] * arr.shape[1])]
        return image, arr, positions

    def _capacity_bits(self, arr: Any, positions: list[int]) -> int:
        linear = arr.reshape(-1)
        total = 0
        for i in range(0, len(positions) - 1, 2):
            p1 = int(linear[positions[i]])
            p2 = int(linear[positions[i + 1]])
            low, high = self._range_for_difference(abs(p1 - p2))
            if self._eligible(p1, p2, low, high, self.adaptive):
                total += self._bits_for_range(low, high)
        return total

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, arr, positions = self._load(input_path)
        return self._capacity_bits(arr, positions) // 8

    @staticmethod
    def _adjust_pair(p1: int, p2: int, target_diff: int) -> tuple[int, int]:
        midpoint = (p1 + p2) // 2
        sign_positive = p1 >= p2
        upper = math.ceil(target_diff / 2)
        lower = math.floor(target_diff / 2)
        if sign_positive:
            a, b = midpoint + upper, midpoint - lower
        else:
            a, b = midpoint - lower, midpoint + upper
        if not (0 <= a <= 255 and 0 <= b <= 255):
            raise CapacityError("PVD adjustment would overflow a pixel.")
        return a, b

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, positions = self._load(input_path)
        linear = arr.reshape(-1)
        bits = bytes_to_bits(payload)
        if len(bits) > self._capacity_bits(arr, positions):
            raise CapacityError("Insufficient PVD capacity.")
        cursor = 0
        for i in range(0, len(positions) - 1, 2):
            if cursor >= len(bits):
                break
            pos1, pos2 = positions[i], positions[i + 1]
            p1, p2 = int(linear[pos1]), int(linear[pos2])
            low, high = self._range_for_difference(abs(p1 - p2))
            if not self._eligible(p1, p2, low, high, self.adaptive):
                continue
            nbits = self._bits_for_range(low, high)
            take = bits[cursor : cursor + nbits]
            if len(take) < nbits:
                take = take + [0] * (nbits - len(take))
            value = 0
            for bit in take:
                value = (value << 1) | bit
            # Because nbits=floor(log2(range_size)), value always occupies a
            # decodable subset [low, low+2^nbits-1] inside the chosen range.
            target = low + value
            a, b = self._adjust_pair(p1, p2, target)
            linear[pos1], linear[pos2] = a, b
            cursor += min(nbits, len(bits) - cursor)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, positions = self._load(input_path)
        linear = arr.reshape(-1)
        bits: list[int] = []
        for i in range(0, len(positions) - 1, 2):
            p1, p2 = int(linear[positions[i]]), int(linear[positions[i + 1]])
            d = abs(p1 - p2)
            low, high = self._range_for_difference(d)
            if not self._eligible(p1, p2, low, high, self.adaptive):
                continue
            nbits = self._bits_for_range(low, high)
            value = d - low
            # Encoder only uses the representable 2^nbits subset.  Values outside
            # it indicate an unmodified/non-payload pair and are skipped.
            if value >= (1 << nbits):
                continue
            bits.extend((value >> shift) & 1 for shift in range(nbits - 1, -1, -1))
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# EDGE / TEXTURE ADAPTIVE LSB FAMILY
# ============================================================
# Principle:
#   Human vision is less sensitive to tiny modifications in high-complexity
#   regions.  Candidate pixels are ranked by an edge/texture score and the payload
#   is embedded into RGB LSBs at those locations.
# Decoder synchronization:
#   The score is computed from RGB values with the target LSB cleared first.
#   Therefore embedding cannot alter the score/ranking, so encoder and decoder
#   deterministically reconstruct identical candidate positions without side data.
# ============================================================

class EdgeAdaptiveAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, method: str = "sobel", fraction: float = 0.65) -> None:
        super().__init__(info)
        self.method = method
        self.fraction = fraction

    @staticmethod
    def _conv3(gray: Any, kernel: Any) -> Any:
        padded = np.pad(gray, 1, mode="edge")
        out = np.zeros_like(gray, dtype=np.float64)
        for dy in range(3):
            for dx in range(3):
                out += kernel[dy, dx] * padded[dy : dy + gray.shape[0], dx : dx + gray.shape[1]]
        return out

    def _score(self, arr: Any) -> Any:
        rgb = arr[:, :, :3] & 0xFE
        gray = 0.299 * rgb[:, :, 0] + 0.587 * rgb[:, :, 1] + 0.114 * rgb[:, :, 2]
        if self.method == "canny":
            if cv2 is not None:
                return cv2.Canny(gray.astype(np.uint8), 80, 160).astype(np.float64)
            # Safe fallback is explicitly an approximation, not a fake Canny.
            self_method = "sobel"
        else:
            self_method = self.method
        if self_method == "laplacian":
            k = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float64)
            return np.abs(self._conv3(gray, k))
        if self_method == "texture":
            mean = self._conv3(gray, np.ones((3, 3), dtype=np.float64) / 9.0)
            mean_sq = self._conv3(gray * gray, np.ones((3, 3), dtype=np.float64) / 9.0)
            return np.maximum(mean_sq - mean * mean, 0.0)
        if self_method == "bpcs":
            # BPCS normally segments complex bit-plane regions.  This compact
            # educational carrier computes a local transition score from the
            # second-lowest bit plane (bit 1), leaving target bit 0 independent.
            plane = ((rgb[:, :, 0] >> 1) & 1).astype(np.float64)
            gx = np.abs(np.diff(plane, axis=1, prepend=plane[:, :1]))
            gy = np.abs(np.diff(plane, axis=0, prepend=plane[:1, :]))
            return gx + gy
        kx = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float64)
        ky = kx.T
        gx = self._conv3(gray, kx)
        gy = self._conv3(gray, ky)
        return np.hypot(gx, gy)

    def _load_positions(self, path: Path) -> tuple[Any, Any, list[int]]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        score = self._score(arr)
        flat_score = score.reshape(-1)
        count = max(1, int(len(flat_score) * self.fraction))
        # Stable mergesort gives deterministic tie behavior across encode/decode.
        pixels = np.argsort(-flat_score, kind="mergesort")[:count].tolist()
        channels = arr.shape[2]
        positions = [p * channels + c for p in pixels for c in range(min(3, channels))]
        return image, arr, positions

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, _arr, positions = self._load_positions(input_path)
        return len(positions) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, positions = self._load_positions(input_path)
        bits = bytes_to_bits(payload)
        if len(bits) > len(positions):
            raise CapacityError("Insufficient edge-adaptive capacity.")
        linear = arr.reshape(-1)
        for pos, bit in zip(positions, bits):
            linear[pos] = (int(linear[pos]) & 0xFE) | bit
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, positions = self._load_positions(input_path)
        linear = arr.reshape(-1)
        bits = [int(linear[pos]) & 1 for pos in positions]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# HISTOGRAM-SHIFTING EDUCATIONAL CARRIER
# ============================================================
# This implementation demonstrates histogram-aware embedding but uses a small
# deterministic LSB bootstrap region to store peak/zero metadata.  Because that
# bootstrap is not itself reversibly restored, the implementation is explicitly
# labelled EDUCATIONAL/non-reversible even though the shifted histogram region can
# be restored in principle.  It never claims canonical RDH compatibility.
# ============================================================

class HistogramShiftAlgorithm(SteganographyAlgorithm):
    BOOT_MAGIC = b"HSH1"
    BOOT_STRUCT = struct.Struct(">4sBBI")  # magic, peak, zero, payload bit length
    BOOT_SAMPLES = BOOT_STRUCT.size * 8

    def _load(self, path: Path) -> tuple[Any, Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channel = arr[:, :, 2].reshape(-1)
        return image, arr, channel

    @staticmethod
    def _peak_zero(data: Any) -> tuple[int, int]:
        hist = np.bincount(data.astype(np.uint8), minlength=256)
        peak = int(np.argmax(hist))
        zero_candidates = np.where(hist == 0)[0].tolist()
        if not zero_candidates:
            raise CapacityError("Histogram has no empty bin; educational shifting cannot embed safely.")
        zero = min(zero_candidates, key=lambda z: abs(z - peak) if z != peak else 999)
        return peak, int(zero)

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, _arr, channel = self._load(input_path)
        if len(channel) <= self.BOOT_SAMPLES:
            return 0
        peak, _zero = self._peak_zero(channel[self.BOOT_SAMPLES :])
        return int(np.count_nonzero(channel[self.BOOT_SAMPLES :] == peak)) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, channel = self._load(input_path)
        if len(channel) <= self.BOOT_SAMPLES:
            raise CapacityError("Image too small for histogram bootstrap.")
        work = channel[self.BOOT_SAMPLES :]
        peak, zero = self._peak_zero(work)
        bits = bytes_to_bits(payload)
        if len(bits) > int(np.count_nonzero(work == peak)):
            raise CapacityError("Insufficient histogram peak capacity.")
        direction = 1 if zero > peak else -1
        if direction > 0:
            mask = (work > peak) & (work < zero)
            work[mask] = work[mask] + 1
        else:
            mask = (work < peak) & (work > zero)
            work[mask] = work[mask] - 1
        peak_indices = np.where(work == peak)[0]
        for idx, bit in zip(peak_indices.tolist(), bits):
            if bit:
                work[idx] = peak + direction
        boot = self.BOOT_STRUCT.pack(self.BOOT_MAGIC, peak, zero, len(bits))
        boot_bits = bytes_to_bits(boot)
        for i, bit in enumerate(boot_bits):
            channel[i] = (int(channel[i]) & 0xFE) | bit
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, _arr, channel = self._load(input_path)
        boot_bits = [int(channel[i]) & 1 for i in range(min(self.BOOT_SAMPLES, len(channel)))]
        boot = bits_to_bytes(boot_bits)
        if len(boot) < self.BOOT_STRUCT.size:
            raise InvalidPayloadError("No valid embedded message found.")
        magic, peak, zero, bit_len = self.BOOT_STRUCT.unpack(boot[: self.BOOT_STRUCT.size])
        if magic != self.BOOT_MAGIC or bit_len > len(channel):
            raise InvalidPayloadError("No valid embedded message found.")
        direction = 1 if zero > peak else -1
        work = channel[self.BOOT_SAMPLES :]
        bits: list[int] = []
        for value in work.tolist():
            if value == peak:
                bits.append(0)
            elif value == peak + direction:
                bits.append(1)
            if len(bits) >= bit_len:
                break
        if len(bits) < bit_len:
            raise InvalidPayloadError("Embedded histogram payload is truncated.")
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits[:bit_len]))


# ============================================================
# 8x8 DCT COEFFICIENT QIM
# ============================================================
# Principle:
#   The blue channel is divided into 8x8 blocks.  A 2-D DCT separates one DC
#   coefficient (average energy) from AC coefficients (spatial frequencies).
#   We avoid DC and quantize AC coefficient (3,4) to one of two parity cosets.
#   Inverse DCT reconstructs pixels.  A moderate quantization step makes parity
#   survive integer rounding, but arbitrary JPEG recompression can still damage it.
# Capacity:
#   One payload bit per complete 8x8 block; this is much lower than spatial LSB.
# Reversibility:
#   Inverse-transform rounding loses information, so the original is not recoverable.
# ============================================================

class DCTAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, step: int = 24) -> None:
        super().__init__(info)
        self.step = step
        # Lazily initialized so a missing NumPy dependency can be reported by
        # main() with installation instructions instead of failing at import time.
        self._c: Any | None = None

    @staticmethod
    def _dct_matrix(n: int) -> Any:
        c = np.zeros((n, n), dtype=np.float64)
        factor = math.pi / (2.0 * n)
        for k in range(n):
            alpha = math.sqrt(1.0 / n) if k == 0 else math.sqrt(2.0 / n)
            for x in range(n):
                c[k, x] = alpha * math.cos((2 * x + 1) * k * factor)
        return c

    def _matrix(self) -> Any:
        require_core_dependencies()
        if self._c is None:
            self._c = self._dct_matrix(8)
        return self._c

    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        return image, arr

    def _blocks(self, arr: Any) -> list[tuple[int, int]]:
        h, w = arr.shape[:2]
        return [(y, x) for y in range(0, h - 7, 8) for x in range(0, w - 7, 8)]

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, arr = self._load(input_path)
        return len(self._blocks(arr)) // 8

    def _read_bit(self, block: Any) -> int:
        c = self._matrix()
        coeff = c @ (block.astype(np.float64) - 128.0) @ c.T
        q = int(round(float(coeff[3, 4]) / self.step))
        return q & 1

    def _embed_bit(self, block: Any, bit: int) -> Any:
        source = block.astype(np.float64) - 128.0
        c = self._matrix()
        coeff = c @ source @ c.T
        base_q = int(round(float(coeff[3, 4]) / self.step))
        candidates = [q for q in range(base_q - 4, base_q + 5) if (q & 1) == bit]
        candidates.sort(key=lambda q: abs(q * self.step - coeff[3, 4]))
        for q in candidates:
            trial = coeff.copy()
            trial[3, 4] = q * self.step
            recon = c.T @ trial @ c + 128.0
            clipped = np.clip(np.rint(recon), 0, 255).astype(np.uint8)
            if self._read_bit(clipped) == bit:
                return clipped
        # A larger step is a deterministic final fallback; it trades distortion
        # for round-trip reliability while remaining within valid pixel bounds.
        q = candidates[0] if candidates else (base_q + ((bit - base_q) & 1))
        trial = coeff.copy()
        trial[3, 4] = q * (self.step * 2)
        return np.clip(np.rint(c.T @ trial @ c + 128.0), 0, 255).astype(np.uint8)

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr = self._load(input_path)
        bits = bytes_to_bits(payload)
        blocks = self._blocks(arr)
        if len(bits) > len(blocks):
            raise CapacityError("Insufficient DCT block capacity.")
        for (y, x), bit in zip(blocks, bits):
            arr[y : y + 8, x : x + 8, 2] = self._embed_bit(arr[y : y + 8, x : x + 8, 2], bit)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr = self._load(input_path)
        bits = [self._read_bit(arr[y : y + 8, x : x + 8, 2]) for y, x in self._blocks(arr)]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# SMALL-BLOCK TRANSFORM PARITY (IWT/DFT/FFT/WALSH DEMONSTRATION)
# ============================================================
# A 2x2 transform high-frequency term can be written a-b-c+d.  Its parity is
# changed, when necessary, by a ±1 modification to d.  For a 2x2 DFT this is the
# real (1,1) coefficient; for a 2x2 Walsh-Hadamard transform it is also a signed
# high-frequency basis response.  This compact method is exact at the parity level
# and survives lossless save/reload, but it is an educational transform carrier,
# not a canonical implementation of every named transform technique.
# ============================================================

class TransformParityAlgorithm(SteganographyAlgorithm):
    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        return image, np.array(image, dtype=np.uint8)

    def _blocks(self, arr: Any) -> list[tuple[int, int]]:
        h, w = arr.shape[:2]
        return [(y, x) for y in range(0, h - 1, 2) for x in range(0, w - 1, 2)]

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, arr = self._load(input_path)
        return len(self._blocks(arr)) // 8

    @staticmethod
    def _bit(block: Any) -> int:
        a, b = int(block[0, 0]), int(block[0, 1])
        c, d = int(block[1, 0]), int(block[1, 1])
        return (a - b - c + d) & 1

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr = self._load(input_path)
        bits = bytes_to_bits(payload)
        blocks = self._blocks(arr)
        if len(bits) > len(blocks):
            raise CapacityError("Insufficient transform-block capacity.")
        rng = random.Random(0xD17A)
        for (y, x), bit in zip(blocks, bits):
            block = arr[y : y + 2, x : x + 2, 2]
            if self._bit(block) != bit:
                d = int(arr[y + 1, x + 1, 2])
                arr[y + 1, x + 1, 2] = safe_random_delta(d, rng)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr = self._load(input_path)
        bits = [self._bit(arr[y : y + 2, x : x + 2, 2]) for y, x in self._blocks(arr)]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# HAAR DWT / INTEGER WAVELET TRANSFORM
# ============================================================
# A reversible integer Haar lifting transform is applied to each 2x2 blue block.
# Row lifting creates smooth/detail pairs; column lifting then yields LL, LH, HL,
# and HH coefficients.  The payload bit is the parity of HH.  If parity differs,
# the encoder searches nearby odd/even HH values and small LL compensation values,
# performs the exact inverse lifting transform, and accepts only byte-range pixels.
# The transform itself is reversible; payload embedding is not labeled RDH because
# the original HH value is not stored and therefore the pristine image is not
# recoverable after message extraction.
# ============================================================

class HaarWaveletAlgorithm(SteganographyAlgorithm):
    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        return image, np.array(image, dtype=np.uint8)

    @staticmethod
    def _forward(block: Any) -> tuple[int, int, int, int]:
        a, b = int(block[0, 0]), int(block[0, 1])
        c, d = int(block[1, 0]), int(block[1, 1])
        d0 = a - b
        s0 = b + (d0 // 2)
        d1 = c - d
        s1 = d + (d1 // 2)
        lh = s0 - s1
        ll = s1 + (lh // 2)
        hh = d0 - d1
        hl = d1 + (hh // 2)
        return ll, lh, hl, hh

    @staticmethod
    def _inverse(coeffs: tuple[int, int, int, int]) -> Any:
        ll, lh, hl, hh = coeffs
        s1 = ll - (lh // 2)
        s0 = lh + s1
        d1 = hl - (hh // 2)
        d0 = hh + d1
        b = s0 - (d0 // 2)
        a = d0 + b
        d = s1 - (d1 // 2)
        c = d1 + d
        return np.array([[a, b], [c, d]], dtype=np.int16)

    def _blocks(self, arr: Any) -> list[tuple[int, int]]:
        h, w = arr.shape[:2]
        return [(y, x) for y in range(0, h - 1, 2) for x in range(0, w - 1, 2)]

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, arr = self._load(input_path)
        return len(self._blocks(arr)) // 8

    def _embed(self, block: Any, bit: int) -> Any:
        ll, lh, hl, hh = self._forward(block)
        if (hh & 1) == bit:
            return block.copy()
        # Search smallest coefficient changes first.  LL compensation is only
        # used at extreme 0/255 blocks where a pure ±1 HH change can overflow.
        hh_deltas = [-1, 1, -3, 3]
        ll_deltas = [0, -1, 1, -2, 2, -4, 4]
        candidates: list[tuple[int, Any]] = []
        for dh in hh_deltas:
            new_hh = hh + dh
            if (new_hh & 1) != bit:
                continue
            for dll in ll_deltas:
                recon = self._inverse((ll + dll, lh, hl, new_hh))
                if np.all((recon >= 0) & (recon <= 255)):
                    recon_u8 = recon.astype(np.uint8)
                    if (self._forward(recon_u8)[3] & 1) == bit:
                        score = abs(dh) + 2 * abs(dll)
                        candidates.append((score, recon_u8))
        if not candidates:
            # A direct ±1 bottom-right change always toggles the linear Haar HH
            # parity.  This boundary-safe fallback remains mathematically tied to
            # the same coefficient even when inverse-coefficient search is blocked.
            out = block.copy()
            value = int(out[1, 1])
            out[1, 1] = 1 if value == 0 else value - 1
            if (self._forward(out)[3] & 1) != bit:
                value = int(block[0, 0])
                out = block.copy()
                out[0, 0] = 254 if value == 255 else value + 1
            return out
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr = self._load(input_path)
        bits = bytes_to_bits(payload)
        blocks = self._blocks(arr)
        if len(bits) > len(blocks):
            raise CapacityError("Insufficient Haar DWT/IWT capacity.")
        for (y, x), bit in zip(blocks, bits):
            arr[y : y + 2, x : x + 2, 2] = self._embed(arr[y : y + 2, x : x + 2, 2], bit)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr = self._load(input_path)
        bits = [(self._forward(arr[y : y + 2, x : x + 2, 2])[3] & 1) for y, x in self._blocks(arr)]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# SVD BLOCK EMBEDDING
# ============================================================
# Each 8x8 blue block is factorized A = U Σ V^T.  The largest singular value is
# quantized to an index whose parity represents one payload bit.  The block is
# reconstructed and rounded to bytes; candidate indices are searched until the
# recomputed SVD decodes the requested parity.  This is a practical educational
# SVD carrier, not a watermark robustness benchmark, and it is not reversible.
# ============================================================

class SVDAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, step: float = 10.0) -> None:
        super().__init__(info)
        self.step = float(step)

    def _load(self, path: Path) -> tuple[Any, Any]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        return image, np.array(image, dtype=np.uint8)

    @staticmethod
    def _blocks(arr: Any) -> list[tuple[int, int]]:
        h, w = arr.shape[:2]
        return [(y, x) for y in range(0, h - 7, 8) for x in range(0, w - 7, 8)]

    def _bit(self, block: Any) -> int:
        singular = np.linalg.svd(block.astype(np.float64), compute_uv=False)
        q = int(round(float(singular[0]) / self.step))
        return q & 1

    def _embed(self, block: Any, bit: int) -> Any:
        u, singular, vt = np.linalg.svd(block.astype(np.float64), full_matrices=False)
        base = int(round(float(singular[0]) / self.step))
        candidates = [q for q in range(max(0, base - 8), base + 9) if (q & 1) == bit]
        candidates.sort(key=lambda q: abs(q * self.step - singular[0]))
        for q in candidates:
            s2 = singular.copy()
            s2[0] = q * self.step
            recon = np.clip(np.rint((u * s2) @ vt), 0, 255).astype(np.uint8)
            if self._bit(recon) == bit:
                return recon
        raise StegoError("Could not find a stable SVD quantization point for a block.")

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, arr = self._load(input_path)
        return len(self._blocks(arr)) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr = self._load(input_path)
        bits = bytes_to_bits(payload)
        blocks = self._blocks(arr)
        if len(bits) > len(blocks):
            raise CapacityError("Insufficient SVD block capacity.")
        for (y, x), bit in zip(blocks, bits):
            arr[y : y + 8, x : x + 8, 2] = self._embed(arr[y : y + 8, x : x + 8, 2], bit)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr = self._load(input_path)
        bits = [self._bit(arr[y : y + 8, x : x + 8, 2]) for y, x in self._blocks(arr)]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# QIM / DITHER MODULATION
# ============================================================
# Each blue sample is quantized to a lattice point whose quantization-index parity
# represents one bit.  QIM trades higher per-sample distortion for better noise
# tolerance than raw LSB.  Dither modulation shifts the lattice by a deterministic
# pseudo-random offset derived from a key before applying the same parity rule.
# ============================================================

class QIMAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, step: int = DEFAULT_QIM_STEP, dithered: bool = False) -> None:
        super().__init__(info)
        self.step = max(4, step)
        self.dithered = dithered

    def _load(self, path: Path) -> tuple[Any, Any, list[int]]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channels = arr.shape[2]
        positions = [p * channels + 2 for p in range(arr.shape[0] * arr.shape[1])]
        return image, arr, positions

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, _arr, positions = self._load(input_path)
        return len(positions) // 8

    def _offsets(self, n: int, key: str | None) -> list[int]:
        if not self.dithered:
            return [0] * n
        if not key:
            raise StegoError("Dither modulation requires a passphrase/key.")
        rng = random.Random(stable_seed(key, f"dither:{self.info.id}"))
        half = max(1, self.step // 4)
        return [rng.randrange(-half, half + 1) for _ in range(n)]

    def _encode_value(self, value: int, bit: int, offset: int) -> int:
        shifted = value - offset
        q0 = int(round(shifted / self.step))
        candidates = [q for q in range(q0 - 2, q0 + 3) if (q & 1) == bit]
        valid = [q * self.step + offset for q in candidates if 0 <= q * self.step + offset <= 255]
        if not valid:
            # Search all lattice points of the requested parity; byte domain is tiny.
            valid = [q * self.step + offset for q in range(-2, 258 // self.step + 3) if (q & 1) == bit and 0 <= q * self.step + offset <= 255]
        return min(valid, key=lambda candidate: abs(candidate - value))

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, positions = self._load(input_path)
        bits = bytes_to_bits(payload)
        if len(bits) > len(positions):
            raise CapacityError("Insufficient QIM capacity.")
        offsets = self._offsets(len(bits), kwargs.get("key"))
        linear = arr.reshape(-1)
        for pos, bit, offset in zip(positions, bits, offsets):
            linear[pos] = self._encode_value(int(linear[pos]), bit, offset)
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, positions = self._load(input_path)
        offsets = self._offsets(len(positions), kwargs.get("key"))
        linear = arr.reshape(-1)
        bits = [int(round((int(linear[pos]) - off) / self.step)) & 1 for pos, off in zip(positions, offsets)]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# SPREAD-SPECTRUM / PATCHWORK / CORRELATION FAMILY
# ============================================================
# One payload bit is spread over multiple blue samples using a pseudo-noise chip
# sequence.  Positive or negative correlation represents 1/0.  This substantially
# lowers capacity but provides redundancy against modest sample noise.  The
# implementation is educational and deterministic; it is not a claim of reference
# compatibility with a specific published spread-spectrum system.
# ============================================================

class SpreadSpectrumAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, chips: int = 8, delta: int = 4) -> None:
        super().__init__(info)
        self.chips = chips
        self.delta = delta

    def _load(self, path: Path) -> tuple[Any, Any, list[int]]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channels = arr.shape[2]
        positions = [p * channels + 2 for p in range(arr.shape[0] * arr.shape[1])]
        return image, arr, positions

    def _order_and_chips(self, n_positions: int, key: str | None) -> tuple[list[int], list[int]]:
        seed_text = key if key is not None else "public-educational-seed"
        rng = random.Random(stable_seed(seed_text, f"spread:{self.info.id}"))
        positions = list(range(n_positions))
        rng.shuffle(positions)
        # One pseudo-noise sign per pair/chip.  A bit is repeated over multiple
        # independent pairs, and the decoder sums signed pair differences.
        pn = [1 if rng.getrandbits(1) else -1 for _ in range(n_positions // 2 + 1)]
        return positions, pn

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, _arr, positions = self._load(input_path)
        return (len(positions) // (2 * self.chips)) // 8

    @staticmethod
    def _set_pair_difference(a: int, b: int, target: int) -> tuple[int, int]:
        """Set a signed pair difference near `target` while staying in byte range."""
        midpoint = (a + b) / 2.0
        first = int(round(midpoint + target / 2.0))
        second = int(round(midpoint - target / 2.0))
        if first < 0:
            second -= first
            first = 0
        elif first > 255:
            second -= first - 255
            first = 255
        if second < 0:
            first -= second
            second = 0
        elif second > 255:
            first -= second - 255
            second = 255
        return int(np.clip(first, 0, 255)), int(np.clip(second, 0, 255))

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, base_positions = self._load(input_path)
        bits = bytes_to_bits(payload)
        samples_per_bit = 2 * self.chips
        if len(bits) * samples_per_bit > len(base_positions):
            raise CapacityError("Insufficient spread-spectrum capacity.")
        order, pn = self._order_and_chips(len(base_positions), kwargs.get("key"))
        linear = arr.reshape(-1)
        magnitude = max(2, 2 * self.delta)
        for bit_index, bit in enumerate(bits):
            symbol = 1 if bit else -1
            start = bit_index * samples_per_bit
            for j in range(self.chips):
                idx_a = order[start + 2 * j]
                idx_b = order[start + 2 * j + 1]
                pos_a = base_positions[idx_a]
                pos_b = base_positions[idx_b]
                target = symbol * pn[bit_index * self.chips + j] * magnitude
                a, b = self._set_pair_difference(int(linear[pos_a]), int(linear[pos_b]), target)
                linear[pos_a], linear[pos_b] = a, b
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, base_positions = self._load(input_path)
        order, pn = self._order_and_chips(len(base_positions), kwargs.get("key"))
        linear = arr.reshape(-1)
        bits: list[int] = []
        samples_per_bit = 2 * self.chips
        groups = len(base_positions) // samples_per_bit
        for group in range(groups):
            start = group * samples_per_bit
            corr = 0.0
            for j in range(self.chips):
                idx_a = order[start + 2 * j]
                idx_b = order[start + 2 * j + 1]
                a = int(linear[base_positions[idx_a]])
                b = int(linear[base_positions[idx_b]])
                corr += (a - b) * pn[group * self.chips + j]
            bits.append(1 if corr >= 0 else 0)
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# MATRIX / HAMMING EMBEDDING
# ============================================================
# Seven cover LSBs encode three payload bits.  The syndrome is the XOR of 1-based
# indices whose cover bit is one.  To change the syndrome from s to desired d, at
# most one cover bit at index s XOR d is flipped.  This is a compact, concrete
# matrix-encoding demonstration and illustrates why coding can reduce changes.
# ============================================================

class HammingMatrixAlgorithm(SteganographyAlgorithm):
    def _load(self, path: Path) -> tuple[Any, Any, list[int]]:
        image = ImageHelper.ensure_rgb_or_rgba(ImageHelper.open_image(path))
        arr = np.array(image, dtype=np.uint8)
        channels = arr.shape[2]
        positions = [p * channels + c for p in range(arr.shape[0] * arr.shape[1]) for c in range(min(3, channels))]
        return image, arr, positions

    @staticmethod
    def _syndrome(values: Sequence[int]) -> int:
        syndrome = 0
        for i, value in enumerate(values, start=1):
            if int(value) & 1:
                syndrome ^= i
        return syndrome

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, _arr, positions = self._load(input_path)
        return ((len(positions) // 7) * 3) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, arr, positions = self._load(input_path)
        bits = bytes_to_bits(payload)
        groups_needed = math.ceil(len(bits) / 3)
        if groups_needed * 7 > len(positions):
            raise CapacityError("Insufficient matrix-encoding capacity.")
        linear = arr.reshape(-1)
        cursor = 0
        for g in range(groups_needed):
            group_positions = positions[g * 7 : g * 7 + 7]
            cover = [int(linear[p]) for p in group_positions]
            chunk_bits = bits[cursor : cursor + 3]
            cursor += len(chunk_bits)
            chunk_bits = chunk_bits + [0] * (3 - len(chunk_bits))
            desired = (chunk_bits[0] << 2) | (chunk_bits[1] << 1) | chunk_bits[2]
            current = self._syndrome(cover)
            flip_index = current ^ desired
            if flip_index:
                pos = group_positions[flip_index - 1]
                linear[pos] = int(linear[pos]) ^ 1
        ImageHelper.save_lossless(Image.fromarray(arr, image.mode), output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, arr, positions = self._load(input_path)
        linear = arr.reshape(-1)
        bits: list[int] = []
        for g in range(len(positions) // 7):
            vals = [int(linear[p]) for p in positions[g * 7 : g * 7 + 7]]
            s = self._syndrome(vals)
            bits.extend([(s >> 2) & 1, (s >> 1) & 1, s & 1])
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))

# ============================================================
# FILE / CONTAINER TECHNIQUES
# ============================================================
# These algorithms store the framed payload in standards-compliant metadata,
# comments, chunks, or trailing bytes instead of modifying visible pixels.
# They preserve image samples whenever possible.  PNG custom chunks include a
# correct CRC; JPEG segments use legal marker lengths; GIF comments use valid
# sub-blocks.  No malformed exploit files or executable payload behavior exists.
# ============================================================

class ContainerAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, mode: str) -> None:
        super().__init__(info)
        self.mode = mode

    @staticmethod
    def _read(path: Path) -> bytes:
        if not path.exists() or not path.is_file():
            raise ImageCompatibilityError(f"Input file does not exist: {path}")
        return path.read_bytes()

    @staticmethod
    def _png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
        signature = b"\x89PNG\r\n\x1a\n"
        if not data.startswith(signature):
            raise ImageCompatibilityError("Selected PNG chunk method requires a PNG input.")
        chunks_out: list[tuple[bytes, bytes]] = []
        cursor = len(signature)
        while cursor + 12 <= len(data):
            length = struct.unpack(">I", data[cursor : cursor + 4])[0]
            ctype = data[cursor + 4 : cursor + 8]
            end = cursor + 12 + length
            if end > len(data):
                raise ImageCompatibilityError("PNG chunk stream is truncated.")
            cdata = data[cursor + 8 : cursor + 8 + length]
            expected = struct.unpack(">I", data[cursor + 8 + length : end])[0]
            actual = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
            if expected != actual:
                raise ImageCompatibilityError("PNG contains a chunk with invalid CRC.")
            chunks_out.append((ctype, cdata))
            cursor = end
            if ctype == b"IEND":
                break
        return chunks_out

    @staticmethod
    def _make_png_chunk(ctype: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)

    @staticmethod
    def _insert_png_chunk(data: bytes, ctype: bytes, payload: bytes) -> bytes:
        signature = b"\x89PNG\r\n\x1a\n"
        chunks_parsed = ContainerAlgorithm._png_chunks(data)
        rebuilt = bytearray(signature)
        for existing_type, existing_data in chunks_parsed:
            if existing_type == b"IEND":
                rebuilt.extend(ContainerAlgorithm._make_png_chunk(ctype, payload))
            rebuilt.extend(ContainerAlgorithm._make_png_chunk(existing_type, existing_data))
        return bytes(rebuilt)

    @staticmethod
    def _jpeg_insert_segment(data: bytes, marker: int, segment_data: bytes) -> bytes:
        if not data.startswith(b"\xFF\xD8"):
            raise ImageCompatibilityError("Selected JPEG segment method requires a JPEG input.")
        if len(segment_data) > 65533:
            raise CapacityError("JPEG marker segment payload exceeds the 65,533-byte segment limit.")
        segment = bytes([0xFF, marker]) + struct.pack(">H", len(segment_data) + 2) + segment_data
        # Insert directly after SOI.  This is standards-compliant and leaves the
        # compressed scan data untouched.
        return data[:2] + segment + data[2:]

    @staticmethod
    def _jpeg_segments(data: bytes) -> Iterator[tuple[int, bytes]]:
        if not data.startswith(b"\xFF\xD8"):
            raise ImageCompatibilityError("Not a JPEG stream.")
        cursor = 2
        while cursor + 4 <= len(data):
            if data[cursor] != 0xFF:
                break
            while cursor < len(data) and data[cursor] == 0xFF:
                cursor += 1
            if cursor >= len(data):
                break
            marker = data[cursor]
            cursor += 1
            if marker in (0xD9, 0xDA):  # EOI / Start of Scan
                break
            if marker in range(0xD0, 0xD8) or marker == 0x01:
                continue
            if cursor + 2 > len(data):
                break
            length = struct.unpack(">H", data[cursor : cursor + 2])[0]
            if length < 2 or cursor + length > len(data):
                raise ImageCompatibilityError("Malformed JPEG marker length.")
            segment_data = data[cursor + 2 : cursor + length]
            yield marker, segment_data
            cursor += length

    @staticmethod
    def _gif_comment_insert(data: bytes, payload: bytes) -> bytes:
        if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
            raise ImageCompatibilityError("GIF comment embedding requires GIF input.")
        trailer = data.rfind(b"\x3B")
        if trailer < 0:
            raise ImageCompatibilityError("GIF trailer not found.")
        marker = b"ISL1" + payload
        blocks = bytearray(b"\x21\xFE")
        for i in range(0, len(marker), 255):
            chunk = marker[i : i + 255]
            blocks.append(len(chunk))
            blocks.extend(chunk)
        blocks.append(0)
        return data[:trailer] + bytes(blocks) + data[trailer:]

    @staticmethod
    def _gif_comments(data: bytes) -> Iterator[bytes]:
        # Parsing only the extension structure is sufficient for comments.  We do
        # not attempt to decode raster data or construct invalid LZW streams.
        cursor = 0
        while True:
            idx = data.find(b"\x21\xFE", cursor)
            if idx < 0:
                return
            cursor = idx + 2
            out = bytearray()
            while cursor < len(data):
                size = data[cursor]
                cursor += 1
                if size == 0:
                    break
                if cursor + size > len(data):
                    raise ImageCompatibilityError("Truncated GIF comment extension.")
                out.extend(data[cursor : cursor + size])
                cursor += size
            yield bytes(out)

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        data = self._read(input_path)
        if self.mode in {"jpeg_com", "jpeg_app", "xmp", "iptc"}:
            if not data.startswith(b"\xFF\xD8"):
                return 0
            # Reserve method-specific prefix bytes inside a legal JPEG segment.
            return 65500
        if self.mode in {"png_text", "png_ztxt", "png_itxt", "png_custom"}:
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                return 0
            return min(32 * 1024 * 1024, max(1_000_000, len(data) * 16))
        if self.mode == "gif_comment":
            return 16 * 1024 * 1024
        if self.mode == "exif":
            return 60_000
        if self.mode in {"eof", "padding", "polyglot"}:
            return 64 * 1024 * 1024
        return 0

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        data = self._read(input_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.mode == "png_text":
            stored = b"ImageSteganographyLab\x00" + base64.b64encode(payload)
            output_path.write_bytes(self._insert_png_chunk(data, b"tEXt", stored))
            return
        if self.mode == "png_ztxt":
            stored = b"ImageSteganographyLab\x00\x00" + zlib.compress(base64.b64encode(payload))
            output_path.write_bytes(self._insert_png_chunk(data, b"zTXt", stored))
            return
        if self.mode == "png_itxt":
            stored = b"ImageSteganographyLab\x00\x00\x00\x00\x00" + base64.b64encode(payload)
            output_path.write_bytes(self._insert_png_chunk(data, b"iTXt", stored))
            return
        if self.mode == "png_custom":
            output_path.write_bytes(self._insert_png_chunk(data, b"stEg", payload))
            return
        if self.mode == "jpeg_com":
            output_path.write_bytes(self._jpeg_insert_segment(data, 0xFE, b"ISL1" + payload))
            return
        if self.mode == "jpeg_app":
            output_path.write_bytes(self._jpeg_insert_segment(data, 0xEF, b"ISL-APP15\x00" + payload))
            return
        if self.mode == "xmp":
            prefix = b"http://ns.adobe.com/xap/1.0/\x00"
            xmp = (
                b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
                b"<rdf:Description xmlns:isl='https://example.invalid/isl/1.0/' isl:payload='"
                + base64.b64encode(payload)
                + b"'/></rdf:RDF></x:xmpmeta>"
            )
            output_path.write_bytes(self._jpeg_insert_segment(data, 0xE1, prefix + xmp))
            return
        if self.mode == "iptc":
            output_path.write_bytes(self._jpeg_insert_segment(data, 0xED, b"Photoshop 3.0\x00ISL-IPTC\x00" + payload))
            return
        if self.mode == "gif_comment":
            output_path.write_bytes(self._gif_comment_insert(data, payload))
            return
        if self.mode == "exif":
            image = ImageHelper.open_image(input_path)
            if ImageHelper.format_name(image, input_path) not in {"JPEG", "TIFF", "WEBP"}:
                raise ImageCompatibilityError("EXIF embedding supports JPEG/TIFF/WebP in this implementation.")
            exif = image.getexif()
            encoded = b"ASCII\x00\x00\x00ISL1" + base64.b64encode(payload)
            # 37510 = UserComment.  Pillow preserves a standards-compatible EXIF block.
            exif[37510] = encoded
            kwargs_save: dict[str, Any] = {"exif": exif.tobytes()}
            if "icc_profile" in image.info:
                kwargs_save["icc_profile"] = image.info["icc_profile"]
            image.save(output_path, **kwargs_save)
            return
        if self.mode in {"eof", "padding"}:
            label = b"ISL-EOF1" if self.mode == "eof" else b"ISL-PAD1"
            trailer = label + struct.pack(">I", len(payload)) + payload + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
            output_path.write_bytes(data + trailer)
            return
        if self.mode == "polyglot":
            # Benign polyglot demonstration: append a standards-compliant ZIP file
            # containing a single inert `hidden_message.bin`.  Nothing is executed.
            bio = io.BytesIO()
            with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("hidden_message.bin", payload)
                archive.writestr("README.txt", "Inert steganography-lab payload. Do not execute extracted data.")
            output_path.write_bytes(data + bio.getvalue())
            return
        raise StegoError(f"Unsupported container mode: {self.mode}")

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        data = self._read(input_path)
        if self.mode.startswith("png_"):
            chunks_found = self._png_chunks(data)
            for ctype, cdata in reversed(chunks_found):
                try:
                    if self.mode == "png_text" and ctype == b"tEXt" and cdata.startswith(b"ImageSteganographyLab\x00"):
                        return base64.b64decode(cdata.split(b"\x00", 1)[1], validate=True)
                    if self.mode == "png_ztxt" and ctype == b"zTXt" and cdata.startswith(b"ImageSteganographyLab\x00\x00"):
                        compressed = cdata[len(b"ImageSteganographyLab\x00\x00") :]
                        return base64.b64decode(zlib.decompress(compressed), validate=True)
                    if self.mode == "png_itxt" and ctype == b"iTXt" and cdata.startswith(b"ImageSteganographyLab\x00\x00\x00\x00\x00"):
                        encoded = cdata[len(b"ImageSteganographyLab\x00\x00\x00\x00\x00") :]
                        return base64.b64decode(encoded, validate=True)
                    if self.mode == "png_custom" and ctype == b"stEg":
                        return cdata
                except (binascii.Error, zlib.error) as exc:
                    raise InvalidPayloadError("Container payload is corrupted.") from exc
            raise InvalidPayloadError("No valid embedded message found.")
        if self.mode in {"jpeg_com", "jpeg_app", "xmp", "iptc"}:
            for marker, segment in self._jpeg_segments(data):
                if self.mode == "jpeg_com" and marker == 0xFE and segment.startswith(b"ISL1"):
                    return segment[4:]
                if self.mode == "jpeg_app" and marker == 0xEF and segment.startswith(b"ISL-APP15\x00"):
                    return segment[len(b"ISL-APP15\x00") :]
                if self.mode == "iptc" and marker == 0xED and segment.startswith(b"Photoshop 3.0\x00ISL-IPTC\x00"):
                    return segment[len(b"Photoshop 3.0\x00ISL-IPTC\x00") :]
                if self.mode == "xmp" and marker == 0xE1 and b"isl:payload='" in segment:
                    encoded = segment.split(b"isl:payload='", 1)[1].split(b"'", 1)[0]
                    try:
                        return base64.b64decode(encoded, validate=True)
                    except binascii.Error as exc:
                        raise InvalidPayloadError("XMP payload is corrupted.") from exc
            raise InvalidPayloadError("No valid embedded message found.")
        if self.mode == "gif_comment":
            for comment in reversed(list(self._gif_comments(data))):
                if comment.startswith(b"ISL1"):
                    return comment[4:]
            raise InvalidPayloadError("No valid embedded message found.")
        if self.mode == "exif":
            image = ImageHelper.open_image(input_path)
            raw = image.getexif().get(37510)
            if not raw:
                raise InvalidPayloadError("No valid embedded message found.")
            if isinstance(raw, str):
                raw_b = raw.encode("latin-1", errors="ignore")
            else:
                raw_b = bytes(raw)
            prefix = b"ASCII\x00\x00\x00ISL1"
            if not raw_b.startswith(prefix):
                raise InvalidPayloadError("No valid embedded message found.")
            try:
                return base64.b64decode(raw_b[len(prefix) :], validate=True)
            except binascii.Error as exc:
                raise InvalidPayloadError("EXIF payload is corrupted.") from exc
        if self.mode in {"eof", "padding"}:
            label = b"ISL-EOF1" if self.mode == "eof" else b"ISL-PAD1"
            idx = data.rfind(label)
            if idx < 0 or idx + len(label) + 8 > len(data):
                raise InvalidPayloadError("No valid embedded message found.")
            cursor = idx + len(label)
            length = struct.unpack(">I", data[cursor : cursor + 4])[0]
            cursor += 4
            end = cursor + length
            if end + 4 > len(data):
                raise InvalidPayloadError("Trailing payload is truncated.")
            payload = data[cursor:end]
            checksum = struct.unpack(">I", data[end : end + 4])[0]
            if (zlib.crc32(payload) & 0xFFFFFFFF) != checksum:
                raise InvalidPayloadError("Trailing payload checksum failed.")
            return payload
        if self.mode == "polyglot":
            # Search for the first local ZIP header near the end.  zipfile handles
            # only the sliced ZIP bytes, never executes anything inside it.
            idx = data.find(b"PK\x03\x04")
            if idx < 0:
                raise InvalidPayloadError("No benign ZIP payload container found.")
            try:
                with zipfile.ZipFile(io.BytesIO(data[idx:]), "r") as archive:
                    return archive.read("hidden_message.bin")
            except Exception as exc:
                raise InvalidPayloadError("Polyglot ZIP payload is corrupted.") from exc
        raise StegoError(f"Unsupported container mode: {self.mode}")


# ============================================================
# PALETTE / INDEXED IMAGE METHODS
# ============================================================
# Palette LSB and parity store bits in RGB palette-table components, not pixel
# indices.  This preserves index layout but slightly changes rendered colors.  The
# maximum carrier is normally only 256*3 bits, so payloads must be short.  Palette
# permutation/EZStego-style names below use this same independent educational
# carrier unless explicitly marked FULL.
# ============================================================

class PaletteLSBAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, matching: bool = False) -> None:
        super().__init__(info)
        self.matching = matching

    def _load(self, path: Path) -> tuple[Any, list[int]]:
        image = ImageHelper.open_image(path)
        if image.mode != "P" or image.getpalette() is None:
            raise ImageCompatibilityError("Palette method requires a P-mode indexed image.")
        palette = list(image.getpalette())
        return image, palette

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        _image, palette = self._load(input_path)
        return len(palette) // 8

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        image, palette = self._load(input_path)
        bits = bytes_to_bits(payload)
        if len(bits) > len(palette):
            raise CapacityError("Palette contains too few entries for this framed payload.")
        rng = random.Random(0xEA57E60)
        for i, bit in enumerate(bits):
            value = palette[i]
            if (value & 1) != bit:
                palette[i] = safe_random_delta(value, rng) if self.matching else ((value & 0xFE) | bit)
        out = image.copy()
        out.putpalette(palette)
        ImageHelper.save_lossless(out, output_path, image.info)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        _image, palette = self._load(input_path)
        bits = [value & 1 for value in palette]
        return PayloadCodec.extract_framed_from_byte_stream(bits_to_bytes(bits))


# ============================================================
# OPTIONAL PROVIDER / TRAINED-MODEL INTERFACE
# ============================================================
# Modern neural, GAN, invertible-network, transformer, diffusion, and some
# coverless/generative systems require trained weights, datasets, or substantial
# scientific infrastructure.  This class deliberately refuses to fabricate such a
# model.  The registry and information screens remain complete; execution produces
# an exact actionable requirement rather than crashing or pretending compatibility.
# ============================================================

class ProviderRequiredAlgorithm(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, requirement: str) -> None:
        super().__init__(info)
        self.requirement = requirement

    def _error(self) -> DependencyError:
        return DependencyError(
            f"{self.info.name} cannot execute in the standalone educational build. {self.requirement}"
        )

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        raise self._error()

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        raise self._error()

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        raise self._error()


# ============================================================
# EDUCATIONAL ADAPTER
# ============================================================
# For named research algorithms whose exact canonical reproduction would require
# reference code, training, syndrome-trellis tooling, or a complete JPEG coding
# stack, this adapter delegates to a clearly stated independent carrier.  The UI
# always labels the algorithm EDUCATIONAL and the notes identify the carrier; it
# never claims reference compatibility.
# ============================================================

class EducationalAdapter(SteganographyAlgorithm):
    def __init__(self, info: AlgorithmInfo, delegate: SteganographyAlgorithm) -> None:
        super().__init__(info)
        self.delegate = delegate

    def estimate_capacity(self, input_path: Path, **kwargs: Any) -> int:
        return self.delegate.estimate_capacity(input_path, **kwargs)

    def encode_payload(self, input_path: Path, output_path: Path, payload: bytes, **kwargs: Any) -> None:
        # Re-frame algorithm identity for this adapter: payload was already framed
        # with this algorithm's id by encode_message, while the delegate only acts
        # as a byte carrier and does not inspect algorithm ids.
        self.delegate.encode_payload(input_path, output_path, payload, **kwargs)

    def extract_payload(self, input_path: Path, **kwargs: Any) -> bytes:
        return self.delegate.extract_payload(input_path, **kwargs)

# ---------------------------------------------------------------------------
# Complete 128-entry algorithm registry
# ---------------------------------------------------------------------------

CATEGORY_A = "A. File / Container Techniques"
CATEGORY_B = "B. Basic Spatial-Domain Techniques"
CATEGORY_C = "C. Pixel Difference Techniques"
CATEGORY_D = "D. Modification-Direction Techniques"
CATEGORY_E = "E. Edge / Texture Adaptive"
CATEGORY_F = "F. Histogram Methods"
CATEGORY_G = "G. Reversible Data Hiding"
CATEGORY_H = "H. DCT / JPEG-Domain"
CATEGORY_I = "I. Transform Domain"
CATEGORY_J = "J. Spread-Spectrum / Quantization"
CATEGORY_K = "K. Content-Adaptive / Distortion-Based"
CATEGORY_L = "L. Embedding Coding Techniques"
CATEGORY_M = "M. Palette / Indexed Image Methods"
CATEGORY_N = "N. Neural / Modern Methods"
CATEGORY_O = "O. Coverless / Generative Approaches"


def _info(
    algorithm_id: int,
    slug: str,
    name: str,
    category: str,
    status: AlgorithmStatus,
    *,
    formats_in: tuple[str, ...] = ("PNG", "BMP", "TIFF"),
    formats_out: tuple[str, ...] = ("PNG", "BMP", "TIFF"),
    lossless: bool = True,
    reversible: bool = False,
    capacity: str = "Carrier-dependent",
    robustness: str = "Fragile under lossy processing",
    notes: str = "",
    concept: str = "Data is embedded in a deterministic image/file carrier and protected by common payload framing.",
    math_idea: str = "The carrier maps framed payload bits/bytes to a reproducible set of image or container elements.",
    encoding: str = "Validate the carrier, calculate capacity, frame the UTF-8 payload, embed, and save without partial writes.",
    decoding: str = "Reconstruct the same carrier order, extract framed bytes, validate magic/length/checksum, then decrypt/decompress.",
    advantages: str = "Single-file implementation with integrity-checked payloads and deterministic decoding.",
    disadvantages: str = "Robustness and detectability depend on the carrier; educational variants are not reference-compatible.",
    detectability: str = "Technique-dependent; increasing payload utilization generally increases statistical detectability.",
    compression_resistance: str = "Low",
    resize_resistance: str = "Very Low",
    cropping_resistance: str = "Very Low",
    steganalysis_resistance: str = "Medium",
    cost: str = "Low",
) -> AlgorithmInfo:
    return AlgorithmInfo(
        id=algorithm_id,
        slug=slug,
        name=name,
        category=category,
        status=status,
        supported_input_formats=formats_in,
        supported_output_formats=formats_out,
        lossless_required=lossless,
        reversible=reversible,
        approximate_capacity=capacity,
        robustness=robustness,
        notes=notes,
        concept=concept,
        mathematical_idea=math_idea,
        encoding_process=encoding,
        decoding_process=decoding,
        advantages=advantages,
        disadvantages=disadvantages,
        detectability=detectability,
        compression_resistance=compression_resistance,
        resize_resistance=resize_resistance,
        cropping_resistance=cropping_resistance,
        steganalysis_resistance=steganalysis_resistance,
        computational_cost=cost,
    )


def build_algorithm_registry() -> dict[int, SteganographyAlgorithm]:
    """Construct every menu entry and bind it to an executable carrier or provider stub."""
    algorithms: dict[int, SteganographyAlgorithm] = {}

    def add(algorithm: SteganographyAlgorithm) -> None:
        if algorithm.info.id in algorithms:
            raise RuntimeError(f"Duplicate algorithm id {algorithm.info.id}")
        algorithms[algorithm.info.id] = algorithm

    # A. FILE / CONTAINER ----------------------------------------------------
    container_specs = [
        (1, "exif", "EXIF metadata embedding", "exif", AlgorithmStatus.FULL, ("JPEG", "TIFF", "WEBP")),
        (2, "xmp", "XMP metadata embedding", "xmp", AlgorithmStatus.FULL, ("JPEG",)),
        (3, "iptc-style", "IPTC-style metadata embedding where supported", "iptc", AlgorithmStatus.EDUCATIONAL, ("JPEG",)),
        (4, "jpeg-com", "JPEG COM/comment segment embedding", "jpeg_com", AlgorithmStatus.FULL, ("JPEG",)),
        (5, "jpeg-app", "JPEG APP segment embedding", "jpeg_app", AlgorithmStatus.FULL, ("JPEG",)),
        (6, "png-text", "PNG tEXt chunk embedding", "png_text", AlgorithmStatus.FULL, ("PNG",)),
        (7, "png-ztxt", "PNG zTXt chunk embedding", "png_ztxt", AlgorithmStatus.FULL, ("PNG",)),
        (8, "png-itxt", "PNG iTXt chunk embedding", "png_itxt", AlgorithmStatus.FULL, ("PNG",)),
        (9, "png-custom", "PNG private/custom chunk embedding", "png_custom", AlgorithmStatus.FULL, ("PNG",)),
        (10, "gif-comment", "GIF comment/extension embedding", "gif_comment", AlgorithmStatus.FULL, ("GIF",)),
        (11, "eof", "EOF/trailing-data embedding", "eof", AlgorithmStatus.FULL, ("PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP")),
        (12, "padding", "File padding/slack-style storage where safely applicable", "padding", AlgorithmStatus.EDUCATIONAL, ("PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP")),
    ]
    for aid, slug, name, mode, status, fmts in container_specs:
        notes = "Preserves compressed/visible image samples. "
        if status == AlgorithmStatus.EDUCATIONAL:
            notes += "Educational safe-container approximation; not filesystem slack-space manipulation."
        add(ContainerAlgorithm(_info(aid, slug, name, CATEGORY_A, status, formats_in=fmts, formats_out=fmts, lossless=False, reversible=False, capacity="Metadata/container dependent", robustness="Usually survives pixel-preserving copies but may be stripped by metadata optimizers", notes=notes, compression_resistance="High", resize_resistance="Low", cropping_resistance="Low"), mode))

    add(LSBAlgorithm(_info(13, "alpha-lsb", "Alpha-channel embedding", CATEGORY_A, AlgorithmStatus.FULL, formats_in=("PNG", "TIFF", "WEBP"), formats_out=("PNG", "TIFF"), capacity="1 bit per alpha sample", notes="Requires RGBA; alpha values are modified by at most one in the selected bit plane."), channels="A"))
    add(TransparentPixelAlgorithm(_info(14, "transparent-pixel", "Transparent-pixel embedding", CATEGORY_A, AlgorithmStatus.FULL, formats_in=("PNG",), formats_out=("PNG",), capacity="3 bits per fully transparent pixel", notes="Stores RGB LSBs only where alpha=0; image optimizers may normalize hidden RGB and destroy data.")))
    add(ContainerAlgorithm(_info(15, "safe-polyglot", "Safe polyglot-style payload container demonstration", CATEGORY_A, AlgorithmStatus.EDUCATIONAL, formats_in=("PNG", "JPEG", "GIF"), formats_out=("PNG", "JPEG", "GIF"), lossless=False, reversible=False, capacity="Tens of MiB", robustness="Image pixels remain intact; trailing ZIP data may be stripped", notes="Benign image+ZIP demonstration containing inert data only; never creates executable malware containers."), "polyglot"))

    # B. BASIC SPATIAL -------------------------------------------------------
    add(LSBAlgorithm(_info(16, "lsb", "LSB Replacement / LSB Substitution", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Directly substitutes selected least-significant sample bits.")))
    add(LSBAlgorithm(_info(17, "lsb-matching", "LSB Matching / ±1 Embedding", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Changes a mismatching sample by +1 or -1 rather than forcing a specific substitution pattern."), matching=True))
    add(LSBMRAlgorithm(_info(18, "lsbmr", "LSB Matching Revisited / LSBMR", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Pairwise parity equations encode two bits per two carrier samples.")))
    # MLSB is represented as a concrete two-bit low-plane embedding variant.  It
    # is practical but intentionally described as this lab's independent MLSB
    # definition rather than a claim about every paper using the MLSB name.
    add(LSBAlgorithm(_info(19, "modified-lsb", "Modified LSB / MLSB", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈6 bits per RGB pixel", notes="Independent lab variant: two low bits per RGB sample. Higher capacity increases distortion/detectability."), bits_per_channel=2))
    add(LSBAlgorithm(_info(20, "inverted-lsb", "Inverted LSB", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Stores the logical complement of each payload bit; decoder inverts it back."), invert_payload_bit=True))
    add(LSBAlgorithm(_info(21, "keyed-lsb", "Keyed / Pseudorandom LSB", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="SHA-256-derived deterministic PRNG shuffles carrier positions; requires the same key to decode."), keyed=True))
    add(LSBAlgorithm(_info(22, "multi-bit-lsb", "Multi-bit LSB", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈6 bits per RGB pixel at 2 bits/channel", notes="Uses two low bits per channel by default; more low bits increase visible/statistical distortion."), bits_per_channel=2))
    add(LSBAlgorithm(_info(23, "bit-plane", "Bit-plane embedding", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Uses bit plane 1 instead of plane 0, illustrating higher-plane capacity/distortion trade-offs."), bit_plane=1))
    add(PixelIndicatorAlgorithm(_info(24, "pixel-indicator", "Pixel Indicator Technique", CATEGORY_B, AlgorithmStatus.FULL, capacity="2 bits per pixel", notes="Red low bits mark payload pixels; green/blue LSBs carry data.")))
    add(LSBAlgorithm(_info(25, "parity", "Parity embedding", CATEGORY_B, AlgorithmStatus.FULL, capacity="≈3 bits per RGB pixel", notes="Byte parity is the carrier symbol; changing the LSB is the minimal way to enforce parity.")))

    # C. PVD -----------------------------------------------------------------
    add(PVDAlgorithm(_info(26, "pvd", "Pixel Value Differencing / PVD", CATEGORY_C, AlgorithmStatus.FULL, capacity="Variable: 3–7 bits per eligible pixel pair", notes="Difference ranges allocate more bits to high-contrast pairs.")))
    add(PVDAlgorithm(_info(27, "adaptive-pvd", "Adaptive PVD", CATEGORY_C, AlgorithmStatus.FULL, capacity="Variable; favors textured/high-difference pairs", notes="Skips the smoothest PVD ranges to reduce visible change in flat regions."), adaptive=True))
    add(EducationalAdapter(_info(28, "multi-directional-pvd", "Multi-Directional PVD", CATEGORY_C, AlgorithmStatus.EDUCATIONAL, capacity="Variable", notes="Educational approximation using the validated horizontal PVD carrier; not canonical multi-directional neighborhood PVD."), PVDAlgorithm(_info(9001, "delegate-pvd", "delegate", CATEGORY_C, AlgorithmStatus.FULL))))
    add(EducationalAdapter(_info(29, "pvd-lsb-hybrid", "PVD + LSB Hybrid", CATEGORY_C, AlgorithmStatus.EDUCATIONAL, capacity="Variable", notes="Educational hybrid approximation delegates to PVD framing/carrier; it does not claim a particular published hybrid formulation."), PVDAlgorithm(_info(9002, "delegate-pvd2", "delegate", CATEGORY_C, AlgorithmStatus.FULL))))

    # D. MODIFICATION DIRECTION ---------------------------------------------
    for aid, slug, name in [
        (30, "emd", "Exploiting Modification Direction / EMD"),
        (31, "generalized-emd", "Generalized EMD"),
        (32, "diamond-encoding", "Diamond Encoding"),
        (33, "enhanced-emd", "Modified / Enhanced EMD"),
    ]:
        delegate = HammingMatrixAlgorithm(_info(9100 + aid, "delegate-matrix", "delegate", CATEGORY_D, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_D, AlgorithmStatus.EDUCATIONAL, capacity="Coding-dependent", notes="Educational modification-direction approximation backed by single-change matrix embedding; not reference-compatible EMD/diamond coding."), delegate))

    # E. EDGE / TEXTURE ------------------------------------------------------
    add(EdgeAdaptiveAlgorithm(_info(34, "edge-adaptive-lsb", "Edge-Adaptive LSB", CATEGORY_E, AlgorithmStatus.FULL, capacity="≈65% of RGB LSB carrier", notes="Ranks deterministic masked-image Sobel complexity and embeds in high-score regions."), "sobel"))
    add(EdgeAdaptiveAlgorithm(_info(35, "sobel-lsb", "Sobel-Adaptive LSB", CATEGORY_E, AlgorithmStatus.FULL, capacity="≈65% of RGB LSB carrier", notes="Sobel gradient magnitude ranks payload locations."), "sobel"))
    canny_status = AlgorithmStatus.FULL if cv2 is not None else AlgorithmStatus.EDUCATIONAL
    canny_note = "Uses OpenCV Canny on an LSB-masked grayscale image." if cv2 is not None else "OpenCV unavailable: educational fallback uses Sobel ranking. Install opencv-python for true Canny selection."
    add(EdgeAdaptiveAlgorithm(_info(36, "canny-lsb", "Canny-Adaptive LSB", CATEGORY_E, canny_status, capacity="≈65% of RGB LSB carrier", notes=canny_note), "canny"))
    add(EdgeAdaptiveAlgorithm(_info(37, "laplacian-lsb", "Laplacian-Adaptive LSB", CATEGORY_E, AlgorithmStatus.FULL, capacity="≈65% of RGB LSB carrier", notes="Absolute Laplacian response ranks candidate pixels."), "laplacian"))
    add(EdgeAdaptiveAlgorithm(_info(38, "texture-lsb", "Texture-Adaptive LSB", CATEGORY_E, AlgorithmStatus.FULL, capacity="≈65% of RGB LSB carrier", notes="Local variance ranks textured pixels."), "texture"))
    add(EdgeAdaptiveAlgorithm(_info(39, "bpcs", "Bit-Plane Complexity Segmentation / BPCS", CATEGORY_E, AlgorithmStatus.EDUCATIONAL, capacity="≈65% of RGB LSB carrier", notes="Educational BPCS-style approximation: bit-plane transition complexity selects regions; it does not perform canonical block conjugation."), "bpcs"))

    # F. HISTOGRAM -----------------------------------------------------------
    add(HistogramShiftAlgorithm(_info(40, "histogram-shifting", "Histogram Shifting", CATEGORY_F, AlgorithmStatus.EDUCATIONAL, capacity="Number of blue-channel peak-bin samples", notes="Real histogram shifting with a small non-reversible LSB bootstrap; therefore not labeled reversible.")))
    for aid, slug, name in [
        (41, "difference-histogram", "Difference Histogram Shifting"),
        (42, "prediction-error-histogram", "Prediction-Error Histogram Shifting"),
    ]:
        delegate = HistogramShiftAlgorithm(_info(9200 + aid, "delegate-hs", "delegate", CATEGORY_F, AlgorithmStatus.EDUCATIONAL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_F, AlgorithmStatus.EDUCATIONAL, capacity="Histogram-dependent", notes="Educational approximation using the implemented histogram-shifting carrier; difference/prediction-error canonical location maps are not reproduced."), delegate))

    # G. REVERSIBLE DATA HIDING ---------------------------------------------
    for aid, slug, name in [
        (43, "difference-expansion", "Difference Expansion / DE"),
        (44, "prediction-error-expansion", "Prediction Error Expansion / PEE"),
        (45, "pvo", "Pixel Value Ordering / PVO"),
        (46, "ipvo", "Improved Pixel Value Ordering / IPVO"),
        (47, "reversible-contrast-mapping", "Reversible Contrast Mapping"),
        (48, "compression-rdh", "Lossless Compression-Based RDH"),
    ]:
        delegate = HammingMatrixAlgorithm(_info(9300 + aid, "delegate-rdh", "delegate", CATEGORY_G, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_G, AlgorithmStatus.EDUCATIONAL, reversible=False, capacity="Carrier-dependent", notes="Non-reference educational mode. Message extraction works, but exact original-image recovery is NOT guaranteed, so this entry is deliberately marked non-reversible."), delegate))

    # H. DCT / JPEG-DOMAIN ---------------------------------------------------
    add(DCTAlgorithm(_info(49, "dct", "Basic DCT Coefficient Embedding", CATEGORY_H, AlgorithmStatus.FULL, formats_in=("PNG", "BMP", "TIFF", "JPEG"), formats_out=("PNG", "BMP", "TIFF"), capacity="1 bit per 8×8 block", notes="Independent 8×8 DCT AC-coefficient QIM carrier; output must remain lossless for reliable lab decoding.", compression_resistance="Medium", cost="Medium")))
    add(DCTAlgorithm(_info(50, "dct-parity", "DCT Coefficient Parity", CATEGORY_H, AlgorithmStatus.FULL, capacity="1 bit per 8×8 block", notes="Encodes payload in the parity of a quantized AC coefficient.", compression_resistance="Medium", cost="Medium")))
    add(DCTAlgorithm(_info(51, "dct-quantization", "DCT Quantization Embedding", CATEGORY_H, AlgorithmStatus.FULL, capacity="1 bit per 8×8 block", notes="Uses parity-separated coefficient quantization lattices.", compression_resistance="Medium", cost="Medium")))
    jpeg_research = [
        (52, "jsteg", "JSteg"),
        (53, "f3", "F3"),
        (54, "f4", "F4"),
        (55, "f5-style", "F5-Style Matrix Encoding"),
        (56, "nsf5-style", "nsF5-Style Embedding"),
        (57, "outguess-style", "OutGuess-Style Statistical Embedding"),
        (58, "yass-style", "YASS-Style Randomized Block Embedding"),
        (59, "ued-style", "UED-Style JPEG Distortion Embedding"),
        (60, "uerd-style", "UERD-Style JPEG Distortion Embedding"),
        (61, "j-uniward-style", "J-UNIWARD-Style JPEG Adaptive Embedding"),
    ]
    for aid, slug, name in jpeg_research:
        delegate = DCTAlgorithm(_info(9400 + aid, "delegate-dct", "delegate", CATEGORY_H, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_H, AlgorithmStatus.EDUCATIONAL, capacity="1 bit per 8×8 block in this lab approximation", notes=f"Educational approximation of {name}; uses this lab's AC-coefficient QIM carrier and is not canonical/reference compatible.", compression_resistance="Medium", cost="Medium"), delegate))

    # I. TRANSFORM DOMAIN ----------------------------------------------------
    add(HaarWaveletAlgorithm(_info(62, "dwt", "DWT Embedding", CATEGORY_I, AlgorithmStatus.FULL, capacity="1 bit per 2×2 Haar block", notes="Single-level integer Haar DWT. 2×2 lifting yields LL/LH/HL/HH bands; HH parity carries one bit and exact inverse lifting reconstructs the modified block.", cost="Low")))
    add(HaarWaveletAlgorithm(_info(63, "iwt", "Integer Wavelet Transform / IWT", CATEGORY_I, AlgorithmStatus.FULL, capacity="1 bit per 2×2 Haar block", notes="Integer Haar lifting transform with exact integer inverse; the payload changes HH parity, so the pristine original is not recoverable.", cost="Low")))
    for aid, slug, name, note in [
        (64, "dft", "DFT Embedding", "Uses parity of the exact 2×2 real (1,1) DFT coefficient a-b-c+d."),
        (65, "fft", "FFT Frequency-Domain Embedding", "For 2×2 blocks the FFT coefficient is algebraically equivalent to the implemented DFT response."),
        (66, "walsh-hadamard", "Walsh-Hadamard Transform Embedding", "Uses the 2×2 high-frequency Walsh-Hadamard response parity."),
    ]:
        add(TransformParityAlgorithm(_info(aid, slug, name, CATEGORY_I, AlgorithmStatus.FULL, capacity="1 bit per 2×2 block", notes=note, cost="Low")))
    add(SVDAlgorithm(_info(67, "svd", "SVD Embedding", CATEGORY_I, AlgorithmStatus.FULL, capacity="1 bit per 8×8 block", notes="Computes A=UΣVᵀ on blue 8×8 blocks and embeds parity in a quantized leading singular value; reconstructed output must remain lossless.", cost="High")))
    for aid, slug, name in [
        (68, "contourlet-style", "Contourlet-Style Transform Embedding"),
        (69, "curvelet-style", "Curvelet-Style Transform Embedding"),
        (70, "dwt-dct", "DWT + DCT Hybrid"),
        (71, "dwt-svd", "DWT + SVD Hybrid"),
        (72, "dct-svd", "DCT + SVD Hybrid"),
        (73, "dwt-dct-svd", "DWT + DCT + SVD Hybrid"),
    ]:
        delegate = DCTAlgorithm(_info(9500 + aid, "delegate-transform", "delegate", CATEGORY_I, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_I, AlgorithmStatus.EDUCATIONAL, capacity="1 bit per 8×8 block in this approximation", notes=f"Educational approximation of {name}; canonical multi-transform decomposition is not reproduced.", cost="Medium"), delegate))

    # J. SPREAD / QUANTIZATION ----------------------------------------------
    for aid, slug, name in [
        (74, "spread-spectrum", "Spread Spectrum Steganography"),
        (75, "dsss", "Direct-Sequence Spread Spectrum"),
        (76, "transform-spread-spectrum", "Transform-Domain Spread Spectrum"),
    ]:
        add(SpreadSpectrumAlgorithm(_info(aid, slug, name, CATEGORY_J, AlgorithmStatus.EDUCATIONAL, capacity="≈1 bit per 12 carrier samples", notes="Independent correlation/spreading demonstration; not a canonical published DSSS implementation.", compression_resistance="Medium", resize_resistance="Low", steganalysis_resistance="High", cost="Medium")))
    add(QIMAlgorithm(_info(77, "qim", "Quantization Index Modulation / QIM", CATEGORY_J, AlgorithmStatus.FULL, capacity="1 bit per blue sample", notes="Blue samples are mapped to parity-separated scalar quantization lattice points.", compression_resistance="Medium")))
    add(QIMAlgorithm(_info(78, "dither-modulation", "Dither Modulation", CATEGORY_J, AlgorithmStatus.FULL, capacity="1 bit per blue sample", notes="Key-derived deterministic dithers offset the QIM lattice; the same key is required to decode.", compression_resistance="Medium"), dithered=True))
    for aid, slug, name in [
        (79, "patchwork", "Patchwork"),
        (80, "correlation", "Correlation-Based Embedding"),
    ]:
        delegate = SpreadSpectrumAlgorithm(_info(9600 + aid, "delegate-spread", "delegate", CATEGORY_J, AlgorithmStatus.EDUCATIONAL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_J, AlgorithmStatus.EDUCATIONAL, capacity="Low; redundant correlation carrier", notes=f"Educational {name} approximation backed by the lab spread-spectrum correlation carrier."), delegate))

    # K. CONTENT-ADAPTIVE / DISTORTION-BASED --------------------------------
    adaptive_research = [
        (81, "hugo-style", "HUGO-Style Adaptive Embedding"),
        (82, "wow-style", "WOW-Style Wavelet Cost Embedding"),
        (83, "s-uniward-style", "S-UNIWARD-Style Embedding"),
        (84, "si-uniward-style", "SI-UNIWARD-Style Embedding"),
        (85, "hill-style", "HILL-Style Embedding"),
        (86, "mipod-style", "MiPOD-Style Embedding"),
        (87, "multivariate-gaussian", "Multivariate Gaussian Cost Embedding"),
        (88, "gmrf-style", "GMRF-Style Embedding"),
        (89, "cmd", "CMD / Clustering Modification Directions"),
        (90, "modification-direction-sync", "Modification Direction Synchronization"),
        (91, "hill-cmd", "HILL + CMD Hybrid"),
        (92, "adversarial-cost-demo", "Adversarial-Cost Demonstration"),
    ]
    for aid, slug, name in adaptive_research:
        delegate = EdgeAdaptiveAlgorithm(_info(9700 + aid, "delegate-adaptive", "delegate", CATEGORY_K, AlgorithmStatus.FULL), "texture")
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_K, AlgorithmStatus.EDUCATIONAL, capacity="≈65% of RGB LSB carrier in this approximation", notes=f"Educational approximation of {name}. Local texture is used as a distortion proxy; published cost functions/STC solvers are not reproduced.", steganalysis_resistance="High", cost="Medium"), delegate))

    # L. EMBEDDING CODING ----------------------------------------------------
    add(HammingMatrixAlgorithm(_info(93, "matrix-encoding", "Matrix Encoding", CATEGORY_L, AlgorithmStatus.FULL, capacity="3 payload bits per 7 cover samples", notes="Concrete Hamming(7,3)-style syndrome/matrix embedding; at most one LSB flip per 7-sample group.")))
    add(HammingMatrixAlgorithm(_info(94, "hamming-matrix", "Hamming-Code Matrix Embedding", CATEGORY_L, AlgorithmStatus.FULL, capacity="3 payload bits per 7 cover samples", notes="Hamming-style syndrome carrier with single-change embedding.")))
    coding_research = [
        (95, "syndrome-coding", "Syndrome Coding"),
        (96, "wet-paper-demo", "Simplified Wet-Paper Coding Demonstration"),
        (97, "stc-inspired", "Syndrome-Trellis-Code-Inspired Embedding"),
        (98, "bch-assisted", "BCH-Assisted Embedding"),
        (99, "reed-solomon-assisted", "Reed-Solomon-Assisted Embedding"),
        (100, "ldpc-inspired", "LDPC-Inspired Embedding"),
    ]
    for aid, slug, name in coding_research:
        delegate = HammingMatrixAlgorithm(_info(9800 + aid, "delegate-code", "delegate", CATEGORY_L, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_L, AlgorithmStatus.EDUCATIONAL, capacity="3 bits per 7 samples in this approximation", notes=f"Educational coding approximation of {name} using the implemented Hamming syndrome carrier; no false claim of BCH/RS/LDPC/STC compatibility."), delegate))

    # M. PALETTE -------------------------------------------------------------
    add(PaletteLSBAlgorithm(_info(101, "palette-lsb", "Palette LSB", CATEGORY_M, AlgorithmStatus.FULL, formats_in=("PNG", "GIF"), formats_out=("PNG", "GIF"), capacity="Up to ~96 bytes for a 256-color RGB palette", notes="Modifies low bits of palette RGB components, not image indices.")))
    add(PaletteLSBAlgorithm(_info(102, "palette-parity", "Palette Parity", CATEGORY_M, AlgorithmStatus.FULL, formats_in=("PNG", "GIF"), formats_out=("PNG", "GIF"), capacity="Up to ~96 bytes", notes="Palette component parity represents payload bits."), matching=True))
    for aid, slug, name in [
        (103, "palette-permutation", "Palette Permutation"),
        (104, "color-pair-substitution", "Color-Pair Substitution"),
        (105, "ezstego-style", "EZStego-Style Embedding"),
    ]:
        delegate = PaletteLSBAlgorithm(_info(9900 + aid, "delegate-palette", "delegate", CATEGORY_M, AlgorithmStatus.FULL))
        add(EducationalAdapter(_info(aid, slug, name, CATEGORY_M, AlgorithmStatus.EDUCATIONAL, formats_in=("PNG", "GIF"), formats_out=("PNG", "GIF"), capacity="Palette-size dependent", notes=f"Educational approximation of {name} using palette component parity; not canonical palette permutation/EZStego ordering."), delegate))

    # N. NEURAL / MODERN -----------------------------------------------------
    neural_specs = [
        (106, "neural-encoder-decoder", "Neural Encoder/Decoder Architecture Demonstration"),
        (107, "cnn-stego", "CNN-Based Steganography Demonstration"),
        (108, "autoencoder-stego", "Autoencoder Steganography Demonstration"),
        (109, "baluja-style", "Baluja-Style Deep Steganography Architecture"),
        (110, "hidden-style", "HiDDeN-Style Architecture"),
        (111, "steganogan-style", "SteganoGAN-Style Architecture"),
        (112, "gan-stego", "GAN-Based Steganography Architecture"),
        (113, "adversarial-stego", "Adversarial Steganography Architecture"),
        (114, "invertible-nn", "Invertible Neural Network Architecture"),
        (115, "normalizing-flow", "Normalizing-Flow Steganography Architecture"),
        (116, "attention-stego", "Attention-Based Steganography Architecture"),
        (117, "transformer-stego", "Transformer-Based Steganography Architecture"),
        (118, "diffusion-stego", "Diffusion-Based Steganography Architecture"),
        (119, "neural-distortion-cost", "Neural Distortion-Cost Estimation"),
    ]
    for aid, slug, name in neural_specs:
        info = _info(aid, slug, name, CATEGORY_N, AlgorithmStatus.REQUIRES_TRAINED_MODEL, lossless=False, capacity="Model-dependent", robustness="Model- and training-dependent", notes="REQUIRES TRAINED MODEL. The lab provides registry/interface/validation only and never downloads or fabricates weights.", cost="Very High")
        add(ProviderRequiredAlgorithm(info, "REQUIRES TRAINED MODEL: supply a compatible local model/provider implementation and weights; automatic model downloads are intentionally disabled."))

    # O. COVERLESS / GENERATIVE ---------------------------------------------
    coverless_specs = [
        (120, "coverless-feature-mapping", "Coverless Feature Mapping"),
        (121, "hash-coverless", "Hash-Based Coverless Mapping"),
        (122, "image-selection-mapping", "Image-Selection / Retrieval Mapping Demonstration"),
        (123, "texture-synthesis", "Texture-Synthesis Steganography Demonstration"),
        (124, "generative-stego", "Generative Steganography Architecture"),
        (125, "gan-cover-synthesis", "GAN Cover Synthesis Architecture"),
        (126, "diffusion-cover-synthesis", "Diffusion Cover Synthesis Architecture"),
        (127, "semantic-stego", "Semantic Steganography Demonstration"),
        (128, "feature-sequence-mapping", "Feature-Sequence Mapping"),
    ]
    for aid, slug, name in coverless_specs:
        status = AlgorithmStatus.REQUIRES_TRAINED_MODEL if aid in (124, 125, 126) else AlgorithmStatus.EXPERIMENTAL
        req = "Requires a local image corpus/index or generator/provider that defines deterministic feature-to-message mapping. This standalone file does not invent an external dataset."
        if status == AlgorithmStatus.REQUIRES_TRAINED_MODEL:
            req = "REQUIRES TRAINED MODEL: provide compatible local generative weights/provider. No automatic downloads or fabricated models are used."
        info = _info(aid, slug, name, CATEGORY_O, status, lossless=False, capacity="Dataset/model dependent", robustness="Mapping/provider dependent", notes=("This approach may select or synthesize a cover rather than modifying an existing image. " + req), cost="High")
        add(ProviderRequiredAlgorithm(info, req))

    if sorted(algorithms) != list(range(1, 129)):
        missing = sorted(set(range(1, 129)) - set(algorithms))
        raise RuntimeError(f"Registry construction error; missing ids: {missing}")
    return algorithms


ALGORITHMS: dict[int, SteganographyAlgorithm] = build_algorithm_registry()
SLUG_TO_ID: dict[str, int] = {alg.info.slug.lower(): aid for aid, alg in ALGORITHMS.items()}

# ---------------------------------------------------------------------------
# Registry lookup, presentation, capacity, verification
# ---------------------------------------------------------------------------

def resolve_algorithm(value: str | int) -> SteganographyAlgorithm:
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        aid = int(value)
        if aid in ALGORITHMS:
            return ALGORITHMS[aid]
    slug = str(value).strip().lower()
    if slug in SLUG_TO_ID:
        return ALGORITHMS[SLUG_TO_ID[slug]]
    # Permit a unique case-insensitive exact algorithm name for convenience.
    matches = [alg for alg in ALGORITHMS.values() if alg.info.name.lower() == slug]
    if len(matches) == 1:
        return matches[0]
    raise StegoError(f"Invalid algorithm: {value!r}. Use 'algorithms' to list valid ids/slugs.")


def print_algorithm_menu() -> None:
    current = None
    for aid in range(1, 129):
        info = ALGORITHMS[aid].info
        if info.category != current:
            current = info.category
            print(f"\n{current}")
            print("-" * min(78, len(current) + 8))
        print(f"{info.id:3d}. {info.name:<52} [{info.status.value}]")


def print_algorithm_info(algorithm: SteganographyAlgorithm) -> None:
    i = algorithm.info
    fields = [
        ("Algorithm", f"{i.id}. {i.name}"),
        ("Slug", i.slug),
        ("Category", i.category),
        ("Status", i.status.value),
        ("Concept", i.concept),
        ("Mathematical idea", i.mathematical_idea),
        ("Encoding", i.encoding_process),
        ("Decoding", i.decoding_process),
        ("Advantages", i.advantages),
        ("Disadvantages", i.disadvantages),
        ("Recommended input formats", ", ".join(i.supported_input_formats)),
        ("Recommended output formats", ", ".join(i.supported_output_formats)),
        ("Capacity", i.approximate_capacity),
        ("Detectability", i.detectability),
        ("Robustness", i.robustness),
        ("Reversible", "YES" if i.reversible else "NO"),
        ("Implementation status", i.status.value),
        ("Notes", i.notes or "—"),
    ]
    print("\n" + "=" * 72)
    for label, value in fields:
        wrapped = textwrap.fill(str(value), width=72, subsequent_indent=" " * 22)
        print(f"{label + ':':<21} {wrapped}")


def qualitative_invisibility(info: AlgorithmInfo) -> str:
    if info.category == CATEGORY_A:
        return "Very High"
    if info.id in (22, 23, 77, 78):
        return "Medium"
    if info.category in (CATEGORY_H, CATEGORY_I, CATEGORY_J, CATEGORY_K):
        return "High"
    return "High"


def comparison_rows(ids: Sequence[int] | None = None) -> list[list[str]]:
    selected = ids if ids else list(range(1, 129))
    rows: list[list[str]] = []
    for aid in selected:
        i = ALGORITHMS[aid].info
        rows.append([
            str(i.id),
            i.name,
            i.category.split(". ", 1)[0],
            i.status.value,
            i.approximate_capacity,
            qualitative_invisibility(i),
            i.compression_resistance,
            i.resize_resistance,
            i.cropping_resistance,
            i.steganalysis_resistance,
            "Yes" if i.reversible else "No",
            i.computational_cost,
            ",".join(i.supported_output_formats),
        ])
    return rows


def print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    # Cap column width so 128-row comparison remains terminal-friendly.
    widths = []
    for col, header in enumerate(headers):
        max_cell = max([len(str(header))] + [len(str(row[col])) for row in rows]) if rows else len(header)
        widths.append(min(max_cell, 28 if col == 1 else 18))

    def render(row: Sequence[str]) -> str:
        cells = []
        for idx, value in enumerate(row):
            text = str(value)
            if len(text) > widths[idx]:
                text = text[: max(1, widths[idx] - 1)] + "…"
            cells.append(text.ljust(widths[idx]))
        return " | ".join(cells)

    print(render(headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(render(row))


def print_comparison(ids: Sequence[int] | None = None) -> None:
    headers = ["ID", "Algorithm", "Cat", "Status", "Capacity", "Invisible", "Compress", "Resize", "Crop", "Steganalysis", "Rev", "Cost", "Formats"]
    print_table(headers, comparison_rows(ids))
    print("\nRatings are qualitative engineering guidance, not scientifically precise benchmark scores.")


def recommend_output_path(algorithm: SteganographyAlgorithm, input_path: Path) -> Path:
    if algorithm.info.lossless_required:
        return output_default(input_path, algorithm.info.slug, ".png")
    return output_default(input_path, algorithm.info.slug, input_path.suffix)


def conversion_required(algorithm: SteganographyAlgorithm, input_path: Path) -> tuple[bool, str]:
    if isinstance(algorithm, (ContainerAlgorithm, ProviderRequiredAlgorithm, PaletteLSBAlgorithm)):
        return False, ""
    try:
        image = ImageHelper.open_image(input_path)
    except StegoError:
        return False, ""
    if image.mode in ("RGB", "RGBA"):
        return False, ""
    return True, f"This algorithm requires RGB/RGBA working samples; input mode is {image.mode} and will be converted."


def print_encode_report(report: EncodeReport) -> None:
    utilization = (report.payload_bytes / report.capacity_bytes * 100.0) if report.capacity_bytes else 0.0
    print("\nEncoding result")
    print("-" * 60)
    print(f"Algorithm:             {report.algorithm}")
    print(f"Input:                 {report.input_path}")
    print(f"Output:                {report.output_path}")
    if report.dimensions:
        print(f"Input dimensions:      {report.dimensions[0]} × {report.dimensions[1]}")
    print(f"Input file size:       {human_bytes(report.input_size)}")
    print(f"Output file size:      {human_bytes(report.output_size)}")
    print(f"Payload bytes:         {report.payload_bytes:,}")
    print(f"Capacity:              {report.capacity_bytes:,} bytes")
    print(f"Capacity utilization:  {utilization:.2f}%")
    print(f"Compression:           {'YES' if report.compressed else 'NO'}")
    print(f"Encryption:            {'YES' if report.encrypted else 'NO'}")
    print("Encoding completed successfully.")


def estimate_and_print(algorithm: SteganographyAlgorithm, path: Path, message: str | None, compress: bool, password: str | None, **kwargs: Any) -> None:
    capacity = algorithm.estimate_capacity(path, **kwargs)
    image = None
    try:
        image = ImageHelper.open_image(path)
    except StegoError:
        image = None
    print(f"Algorithm:              {algorithm.info.name}")
    if image is not None:
        print(f"Image dimensions:       {image.width} × {image.height}")
    print(f"Available capacity:     {capacity:,} bytes")
    if message is not None:
        framed = PayloadCodec.pack(message, algorithm.info.id, compress=compress, password=password)
        util = (len(framed) / capacity * 100.0) if capacity else math.inf
        print(f"Required capacity:      {len(framed):,} bytes")
        print(f"Utilization:            {util:.2f}%")
        if len(framed) > capacity:
            print("ERROR: Payload is too large for this image using this algorithm.")


def verify_encoded_image(
    algorithm: SteganographyAlgorithm,
    input_path: Path,
    *,
    password: str | None = None,
    expected: str | None = None,
    **kwargs: Any,
) -> bool:
    framed = algorithm.extract_payload(input_path, **kwargs)
    # Header validation happens before decryption so verify can report framing even
    # if a password is absent or wrong.
    if len(framed) < HEADER_SIZE:
        raise InvalidPayloadError("No valid embedded message found.")
    magic, version, alg_id, flags, _salt_len, _nonce_len, data_len, checksum = HEADER_STRUCT.unpack(framed[:HEADER_SIZE])
    header_valid = magic == MAGIC and version == PAYLOAD_VERSION and alg_id == algorithm.info.id
    checksum_valid = False
    try:
        total = PayloadCodec.expected_total_length(framed)
        salt_len = framed[8]  # fixed field location from HEADER_STRUCT layout
        nonce_len = framed[9]
        stored_start = HEADER_SIZE + salt_len + nonce_len
        stored = framed[stored_start:total]
        checksum_valid = (zlib.crc32(stored) & 0xFFFFFFFF) == checksum
    except Exception:
        checksum_valid = False

    decoded = PayloadCodec.unpack(framed, expected_algorithm_id=algorithm.info.id, password=password)
    matches = expected is None or decoded.message == expected
    print(f"Payload header:   {'VALID' if header_valid else 'INVALID'}")
    print(f"Payload checksum: {'VALID' if checksum_valid else 'INVALID'}")
    print(f"Algorithm:        {algorithm.info.name}")
    print(f"Compression:      {'YES' if bool(flags & FLAG_COMPRESSED) else 'NO'}")
    print(f"Encryption:       {'YES' if bool(flags & FLAG_ENCRYPTED) else 'NO'}")
    print(f"Message size:     {decoded.plaintext_bytes} bytes")
    print(f"Decode result:    {'SUCCESS' if header_valid and checksum_valid else 'FAIL'}")
    if expected is not None:
        print(f"Expected text:    {'MATCH' if matches else 'MISMATCH'}")
    return header_valid and checksum_valid and matches


# ---------------------------------------------------------------------------
# Interactive terminal application
# ---------------------------------------------------------------------------

def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def ask_algorithm() -> SteganographyAlgorithm:
    print_algorithm_menu()
    value = input("\nEnter algorithm number: ").strip()
    return resolve_algorithm(value)


def ask_path(prompt: str) -> Path:
    raw = input(prompt).strip().strip('"').strip("'")
    if not raw:
        raise StegoError("A file path is required.")
    return Path(raw).expanduser()


def ask_optional_key(algorithm: SteganographyAlgorithm) -> str | None:
    requires = algorithm.info.id in {21, 78}
    useful = algorithm.info.id in {74, 75, 76, 79, 80}
    if requires:
        key = getpass.getpass("Embedding passphrase/key: ")
        if not key:
            raise StegoError("This algorithm requires a non-empty key.")
        return key
    if useful and ask_yes_no("Use a keyed pseudorandom sequence?", default=False):
        return getpass.getpass("Embedding passphrase/key: ")
    return None


def interactive_encode() -> None:
    algorithm = ask_algorithm()
    print_algorithm_info(algorithm)
    input_path = ask_path("\nInput image path: ")
    need_conversion, warning = conversion_required(algorithm, input_path)
    if need_conversion:
        print(f"\n{warning}")
        if not ask_yes_no("Continue?", default=False):
            print("Cancelled.")
            return

    print("\nEnter message. Finish a multiline message with a line containing only .")
    lines: list[str] = []
    while True:
        line = input()
        if line == ".":
            break
        lines.append(line)
        if len(lines) == 1 and line and not sys.stdin.isatty():
            break
    message = "\n".join(lines)
    compress = ask_yes_no("Compress message before embedding?", default=True)
    password: str | None = None
    if ask_yes_no("Encrypt message before embedding?", default=False):
        if not CryptoHelper.available():
            print("Encryption requires: python -m pip install cryptography")
            if not ask_yes_no("Continue without encryption?", default=False):
                return
        else:
            p1 = getpass.getpass("Password: ")
            p2 = getpass.getpass("Confirm password: ")
            if not p1 or p1 != p2:
                raise PasswordError("Passwords are empty or do not match.")
            password = p1
    key = ask_optional_key(algorithm)

    default_out = recommend_output_path(algorithm, input_path)
    chosen = input(f"Output path [{default_out}]: ").strip()
    output_path = Path(chosen).expanduser() if chosen else default_out
    if output_path.resolve() == input_path.resolve():
        if not ask_yes_no("Output equals source and will overwrite it. Continue?", default=False):
            print("Cancelled.")
            return
    if algorithm.info.lossless_required and output_path.suffix.lower() in {".jpg", ".jpeg"}:
        print("WARNING: JPEG compression may destroy the hidden message. PNG is recommended.")
        if not ask_yes_no("Continue?", default=False):
            return
    estimate_and_print(algorithm, input_path, message, compress, password, key=key)
    report = algorithm.encode_message(input_path, output_path, message, compress=compress, password=password, key=key)
    print_encode_report(report)


def interactive_decode() -> None:
    algorithm = ask_algorithm()
    input_path = ask_path("\nEncoded image path: ")
    key = ask_optional_key(algorithm)
    password: str | None = None
    try:
        decoded = algorithm.decode_message(input_path, key=key)
    except PasswordError:
        password = getpass.getpass("Payload password: ")
        decoded = algorithm.decode_message(input_path, password=password, key=key)
    print("\nRecovered message")
    print("-" * 60)
    print(decoded.message)
    if ask_yes_no("\nSave recovered message to file?", default=False):
        output = ask_path("Text output path: ")
        output.write_text(decoded.message, encoding="utf-8")
        print(f"Saved: {output}")


def interactive_info() -> None:
    algorithm = ask_algorithm()
    print_algorithm_info(algorithm)


def interactive_compare() -> None:
    raw = input("Algorithm ids to compare (comma-separated, blank=all 128): ").strip()
    ids = None
    if raw:
        ids = [resolve_algorithm(part.strip()).info.id for part in raw.split(",") if part.strip()]
    print_comparison(ids)


def interactive_capacity() -> None:
    algorithm = ask_algorithm()
    input_path = ask_path("Input image path: ")
    key = ask_optional_key(algorithm)
    message = None
    compress = True
    password = None
    if ask_yes_no("Also estimate a specific message?", default=False):
        message = input("Message: ")
        compress = ask_yes_no("Compress message?", default=True)
    estimate_and_print(algorithm, input_path, message, compress, password, key=key)


def interactive_verify() -> None:
    algorithm = ask_algorithm()
    input_path = ask_path("Encoded image path: ")
    key = ask_optional_key(algorithm)
    expected = input("Expected text (blank to skip comparison): ")
    expected_value = expected if expected else None
    try:
        verify_encoded_image(algorithm, input_path, expected=expected_value, key=key)
    except PasswordError:
        password = getpass.getpass("Payload password: ")
        verify_encoded_image(algorithm, input_path, password=password, expected=expected_value, key=key)


def interactive_main() -> None:
    while True:
        print("\n" + "=" * 50)
        print(PROGRAM_NAME)
        print("=" * 50)
        print("1. Encode message")
        print("2. Decode message")
        print("3. Algorithm information")
        print("4. Compare algorithms")
        print("5. Estimate image capacity")
        print("6. Verify encoded image")
        print("7. Exit")
        choice = input("\nSelect: ").strip()
        try:
            if choice == "1":
                interactive_encode()
            elif choice == "2":
                interactive_decode()
            elif choice == "3":
                interactive_info()
            elif choice == "4":
                interactive_compare()
            elif choice == "5":
                interactive_capacity()
            elif choice == "6":
                interactive_verify()
            elif choice == "7":
                return
            else:
                print("Invalid selection.")
        except (StegoError, OSError, ValueError) as exc:
            LOGGER.error("%s", exc)


# ---------------------------------------------------------------------------
# Self-test suite
# ---------------------------------------------------------------------------

def run_self_tests(debug: bool = False) -> bool:
    """Run encode→save/reload→decode tests against core implemented carriers.

    Tests intentionally include multiple scripts, emoji, empty/long messages,
    capacity boundaries, wrong algorithm/password, damaged payload, RGBA,
    grayscale conversion, JPEG input, and the required core algorithm list.
    """
    require_core_dependencies()
    import tempfile

    results: list[tuple[str, bool, str]] = []

    def record(name: str, func: Any) -> None:
        try:
            func()
            results.append((name, True, ""))
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))
            if debug:
                LOGGER.exception("Self-test failed: %s", name)

    def roundtrip(alg_id: int, src: Path, message: str, *, compress: bool = True, password: str | None = None, key: str | None = None) -> None:
        alg = ALGORITHMS[alg_id]
        ext = src.suffix if isinstance(alg, ContainerAlgorithm) and not alg.info.lossless_required else ".png"
        out = src.with_name(f"rt_{alg_id}{ext}")
        alg.encode_message(src, out, message, compress=compress, password=password, key=key)
        decoded = alg.decode_message(out, password=password, key=key)
        if decoded.message != message:
            raise AssertionError(f"round-trip mismatch: {decoded.message!r} != {message!r}")

    rng = np.random.default_rng(12345)
    with tempfile.TemporaryDirectory(prefix="isl-selftest-") as temp_dir:
        td = Path(temp_dir)
        # Noise-limited to 32..223 avoids pathological clipping in adaptive/PVD tests.
        rgb_arr = rng.integers(32, 224, size=(384, 384, 3), dtype=np.uint8)
        rgb_path = td / "rgb.png"
        Image.fromarray(rgb_arr, "RGB").save(rgb_path)

        rgba_arr = np.dstack([rgb_arr, np.full((384, 384), 220, dtype=np.uint8)])
        rgba_path = td / "rgba.png"
        Image.fromarray(rgba_arr, "RGBA").save(rgba_path)

        gray_path = td / "gray.png"
        Image.fromarray(rgb_arr[:, :, 0], "L").save(gray_path)

        # A structured image with deliberately sparse histogram bins.
        hist_arr = rng.integers(80, 121, size=(512, 512, 3), dtype=np.uint8)
        hist_path = td / "hist.png"
        Image.fromarray(hist_arr, "RGB").save(hist_path)

        jpeg_path = td / "photo.jpg"
        Image.fromarray(rgb_arr, "RGB").save(jpeg_path, quality=94)

        transparent = rgba_arr.copy()
        transparent[:200, :200, 3] = 0
        transparent_path = td / "transparent.png"
        Image.fromarray(transparent, "RGBA").save(transparent_path)

        palette_img = Image.fromarray(rng.integers(0, 256, size=(128, 128), dtype=np.uint8), "P")
        palette = []
        for i in range(256):
            palette.extend([i, (i * 3) % 256, (255 - i)])
        palette_img.putpalette(palette)
        palette_path = td / "palette.png"
        palette_img.save(palette_path)

        sample = "Hello World | سلام دنیا | مرحبا بالعالم | Hello 🌍 🔐"
        required_algorithms = [
            (16, rgb_path, None),
            (17, rgb_path, None),
            (21, rgb_path, "secret-key"),
            (22, rgb_path, None),
            (25, rgb_path, None),
            (26, rgb_path, None),
            (34, rgb_path, None),
            (9, rgb_path, None),
            (11, rgb_path, None),
            (49, rgb_path, None),
            (40, hist_path, None),
            (62, rgb_path, None),
            (63, rgb_path, None),
            (64, rgb_path, None),
            (66, rgb_path, None),
            (67, rgb_path, None),
            (77, rgb_path, None),
            (93, rgb_path, None),
        ]
        for alg_id, src, key in required_algorithms:
            record(f"algorithm {alg_id}: {ALGORITHMS[alg_id].info.name}", lambda aid=alg_id, p=src, k=key: roundtrip(aid, p, sample, key=k))

        # Metadata, alpha, transparent-pixel, and palette cases use suitable files.
        record("EXIF metadata", lambda: roundtrip(1, jpeg_path, "EXIF metadata message"))
        record("alpha-channel", lambda: roundtrip(13, rgba_path, "alpha payload"))
        record("transparent-pixel", lambda: roundtrip(14, transparent_path, "transparent payload"))
        record("palette LSB", lambda: roundtrip(101, palette_path, "P"))

        payload_cases = [
            ("ASCII", "Hello World"),
            ("Persian", "سلام دنیا"),
            ("Arabic", "مرحبا بالعالم"),
            ("Emoji", "Hello 🌍 🔐"),
            ("Multiline", "line 1\nline 2\nخط سوم\n" * 20),
            ("Empty", ""),
        ]
        for name, msg in payload_cases:
            record(f"payload {name}", lambda m=msg: roundtrip(16, rgb_path, m))

        def near_capacity() -> None:
            alg = ALGORITHMS[16]
            cap = alg.estimate_capacity(rgb_path)
            # No compression makes byte count predictable.  Leave a few bytes of
            # headroom for framing; UTF-8 ASCII is exactly one byte per character.
            msg = "N" * max(0, cap - HEADER_SIZE - 8)
            out = td / "near_capacity.png"
            alg.encode_message(rgb_path, out, msg, compress=False)
            if alg.decode_message(out).message != msg:
                raise AssertionError("near-capacity message mismatch")
        record("message close to capacity", near_capacity)

        def over_capacity() -> None:
            alg = ALGORITHMS[16]
            cap = alg.estimate_capacity(rgb_path)
            msg = "X" * (cap + 100)
            try:
                alg.encode_message(rgb_path, td / "too_big.png", msg, compress=False)
            except CapacityError:
                return
            raise AssertionError("expected CapacityError")
        record("message exceeding capacity", over_capacity)

        def wrong_algorithm() -> None:
            out = td / "wrong_alg.png"
            ALGORITHMS[16].encode_message(rgb_path, out, "wrong algorithm", compress=False)
            try:
                ALGORITHMS[25].decode_message(out)
            except InvalidPayloadError:
                return
            raise AssertionError("expected algorithm-id mismatch")
        record("wrong decoding algorithm", wrong_algorithm)

        if CryptoHelper.available():
            def wrong_password() -> None:
                out = td / "encrypted.png"
                ALGORITHMS[16].encode_message(rgb_path, out, "secret", password="correct")
                try:
                    ALGORITHMS[16].decode_message(out, password="wrong")
                except PasswordError:
                    return
                raise AssertionError("expected PasswordError")
            record("wrong password", wrong_password)

        def damaged_payload() -> None:
            out = td / "damage.png"
            ALGORITHMS[16].encode_message(rgb_path, out, "damage me", compress=False)
            image = Image.open(out).convert("RGB")
            arr = np.array(image, dtype=np.uint8)
            flat = arr.reshape(-1)
            # Flip a data bit after the fixed header, preserving a syntactically
            # valid magic/header so CRC verification is specifically exercised.
            bit_pos = (HEADER_SIZE + 2) * 8
            flat[bit_pos] ^= 1
            Image.fromarray(arr.reshape(image.height, image.width, 3), "RGB").save(out)
            try:
                ALGORITHMS[16].decode_message(out)
            except InvalidPayloadError:
                return
            raise AssertionError("expected checksum/payload failure")
        record("damaged encoded image", damaged_payload)

        record("RGBA image", lambda: roundtrip(16, rgba_path, "rgba"))
        record("grayscale input conversion", lambda: roundtrip(16, gray_path, "grayscale"))

        def large_png() -> None:
            large = td / "large.png"
            arr = rng.integers(0, 256, size=(1024, 1024, 3), dtype=np.uint8)
            Image.fromarray(arr, "RGB").save(large)
            roundtrip(16, large, "large png")
        record("large PNG", large_png)

        def jpeg_input() -> None:
            out = td / "jpeg_to_png.png"
            ALGORITHMS[49].encode_message(jpeg_path, out, "jpeg source", compress=True)
            if ALGORITHMS[49].decode_message(out).message != "jpeg source":
                raise AssertionError("JPEG source DCT roundtrip mismatch")
        record("JPEG input", jpeg_input)

    passed = sum(1 for _name, ok, _detail in results if ok)
    failed = len(results) - passed
    print("\nSELF-TEST RESULTS")
    print("=" * 72)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL':4s}  {name}")
        if detail and not ok:
            print(f"      {detail}")
    print("-" * 72)
    print(f"Passed: {passed}  Failed: {failed}  Total: {len(results)}")
    return failed == 0


# ---------------------------------------------------------------------------
# argparse command-line interface
# ---------------------------------------------------------------------------

def add_common_algorithm_args(parser: argparse.ArgumentParser, *, output: bool = False) -> None:
    parser.add_argument("--algorithm", "-a", required=True, help="Algorithm id, slug, or exact name")
    parser.add_argument("--input", "-i", required=True, type=Path, help="Input image/file")
    if output:
        parser.add_argument("--output", "-o", type=Path, help="Output image/file")
    parser.add_argument("--key", help="Carrier key/passphrase for keyed algorithms")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image_steganography_lab.py",
        description="Single-file image steganography laboratory. Extracted content is treated only as data.",
    )
    parser.add_argument("--debug", action="store_true", help="Show detailed exceptions and DEBUG logging")
    parser.add_argument("--self-test", action="store_true", help="Run built-in encode/decode self-tests and exit")
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encode", help="Encode a text message")
    add_common_algorithm_args(enc, output=True)
    group = enc.add_mutually_exclusive_group(required=False)
    group.add_argument("--message", help="UTF-8 text to embed")
    group.add_argument("--message-file", type=Path, help="Read UTF-8 message from a file")
    enc.add_argument("--no-compress", action="store_true", help="Disable zlib compression")
    enc.add_argument("--encrypt", action="store_true", help="Encrypt using AES-256-GCM; prompts for password if needed")
    enc.add_argument("--password", help=argparse.SUPPRESS)
    enc.add_argument("--allow-conversion", action="store_true", help="Allow RGB/RGBA conversion when required")
    enc.add_argument("--overwrite", action="store_true", help="Permit overwriting the source/output file")

    dec = sub.add_parser("decode", help="Decode a message")
    add_common_algorithm_args(dec)
    dec.add_argument("--password", help=argparse.SUPPRESS)
    dec.add_argument("--save-message", type=Path, help="Save recovered UTF-8 text to this file")

    sub.add_parser("algorithms", help="List all 128 algorithms")
    cmp_parser = sub.add_parser("compare", help="Compare algorithm metadata")
    cmp_parser.add_argument("ids", nargs="*", help="Optional ids/slugs; defaults to all")

    info = sub.add_parser("info", help="Show detailed algorithm information")
    info.add_argument("algorithm", help="Algorithm id or slug")

    cap = sub.add_parser("capacity", help="Estimate image capacity")
    add_common_algorithm_args(cap)
    cap.add_argument("--message", help="Optionally estimate framed size/utilization for this message")
    cap.add_argument("--no-compress", action="store_true")
    cap.add_argument("--encrypt", action="store_true")
    cap.add_argument("--password", help=argparse.SUPPRESS)

    ver = sub.add_parser("verify", help="Verify framing/checksum and optionally expected text")
    add_common_algorithm_args(ver)
    ver.add_argument("--password", help=argparse.SUPPRESS)
    ver.add_argument("--expected", help="Optional expected recovered text")
    return parser


def obtain_password(provided: str | None, prompt: str) -> str:
    if provided:
        return provided
    if not sys.stdin.isatty():
        raise PasswordError("A password is required but no interactive terminal is available.")
    value = getpass.getpass(prompt)
    if not value:
        raise PasswordError("Password cannot be empty.")
    return value


def cli_encode(args: argparse.Namespace) -> None:
    alg = resolve_algorithm(args.algorithm)
    input_path = args.input.expanduser()
    need_conversion, warning = conversion_required(alg, input_path)
    if need_conversion and not args.allow_conversion:
        raise ImageCompatibilityError(warning + " Re-run with --allow-conversion if intentional.")

    if args.message_file:
        message = args.message_file.read_text(encoding="utf-8")
    elif args.message is not None:
        message = args.message
    else:
        if not sys.stdin.isatty():
            message = sys.stdin.read()
        else:
            message = input("Message: ")

    password = None
    if args.encrypt:
        if not CryptoHelper.available():
            raise DependencyError("Encryption requires: python -m pip install cryptography")
        password = obtain_password(args.password, "Password: ")

    output = args.output.expanduser() if args.output else recommend_output_path(alg, input_path)
    if output.exists() and not args.overwrite:
        raise StegoError(f"Output already exists: {output}. Use --overwrite to replace it.")
    try:
        same = output.resolve() == input_path.resolve()
    except OSError:
        same = False
    if same and not args.overwrite:
        raise StegoError("Refusing to overwrite the source image without --overwrite.")
    if alg.info.lossless_required and output.suffix.lower() in {".jpg", ".jpeg"}:
        raise ImageCompatibilityError("JPEG compression may destroy this payload. Use PNG/BMP/TIFF output.")

    estimate_and_print(alg, input_path, message, not args.no_compress, password, key=args.key)
    report = alg.encode_message(
        input_path,
        output,
        message,
        compress=not args.no_compress,
        password=password,
        key=args.key,
    )
    print_encode_report(report)


def cli_decode(args: argparse.Namespace) -> None:
    alg = resolve_algorithm(args.algorithm)
    password = args.password
    try:
        decoded = alg.decode_message(args.input.expanduser(), password=password, key=args.key)
    except PasswordError:
        if password:
            raise
        password = obtain_password(None, "Payload password: ")
        decoded = alg.decode_message(args.input.expanduser(), password=password, key=args.key)
    print(decoded.message)
    if args.save_message:
        args.save_message.write_text(decoded.message, encoding="utf-8")


def cli_capacity(args: argparse.Namespace) -> None:
    alg = resolve_algorithm(args.algorithm)
    password = None
    if args.encrypt:
        if not CryptoHelper.available():
            raise DependencyError("Encryption requires: python -m pip install cryptography")
        password = obtain_password(args.password, "Password: ")
    estimate_and_print(alg, args.input.expanduser(), args.message, not args.no_compress, password, key=args.key)


def cli_verify(args: argparse.Namespace) -> None:
    alg = resolve_algorithm(args.algorithm)
    try:
        verify_encoded_image(alg, args.input.expanduser(), password=args.password, expected=args.expected, key=args.key)
    except PasswordError:
        password = obtain_password(args.password, "Payload password: ")
        verify_encoded_image(alg, args.input.expanduser(), password=password, expected=args.expected, key=args.key)


def configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(bool(args.debug))
    try:
        require_core_dependencies()
        report_optional_dependencies()
        if args.self_test:
            ok = run_self_tests(debug=bool(args.debug))
            raise SystemExit(0 if ok else 1)
        if args.command is None:
            interactive_main()
            return
        if args.command == "encode":
            cli_encode(args)
        elif args.command == "decode":
            cli_decode(args)
        elif args.command == "algorithms":
            print_algorithm_menu()
        elif args.command == "compare":
            ids = [resolve_algorithm(v).info.id for v in args.ids] if args.ids else None
            print_comparison(ids)
        elif args.command == "info":
            print_algorithm_info(resolve_algorithm(args.algorithm))
        elif args.command == "capacity":
            cli_capacity(args)
        elif args.command == "verify":
            cli_verify(args)
        else:
            parser.error(f"Unknown command: {args.command}")
    except SystemExit:
        raise
    except Exception as exc:
        if getattr(args, "debug", False):
            LOGGER.exception("Operation failed")
        else:
            LOGGER.error("%s", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
