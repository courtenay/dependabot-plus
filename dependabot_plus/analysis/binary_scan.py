"""Scan package source for suspicious binary files that may contain
steganographic payloads or encoded executables."""
from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field

log = logging.getLogger("dependabot_plus")

# File extensions that are expected in packages by ecosystem
_EXPECTED_BINARY_EXTENSIONS = {
    # Fonts — common in UI packages
    ".woff", ".woff2", ".ttf", ".eot",
    # Docs
    ".pdf",
}

# NOTE: image files (.png, .jpg, etc.) are NOT in the expected list.
# Recent supply chain attacks (polyfill.io, others) embedded payloads
# in image files. We entropy-scan all images.

# Extensions that should almost never appear in a library package
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib",  # native executables
    ".bin", ".dat",                    # opaque binary blobs
    ".mp3", ".mp4", ".wav", ".ogg",   # media files (stego vector)
    ".bmp",                            # uncompressed images (easy stego)
    ".iso", ".img",                    # disk images
    ".pyc", ".class",                  # compiled bytecode
    ".wasm",                           # WebAssembly (can hide payloads)
}

# Entropy threshold — random/encrypted data is typically > 7.5 bits/byte
_HIGH_ENTROPY_THRESHOLD = 7.2

# Max file size to analyse (skip huge vendored assets)
_MAX_SCAN_SIZE = 10 * 1024 * 1024  # 10 MB


@dataclass
class BinaryFinding:
    path: str
    size: int
    reason: str
    entropy: float | None = None


@dataclass
class BinaryScanResult:
    findings: list[BinaryFinding] = field(default_factory=list)
    binary_count: int = 0
    suspicious_count: int = 0

    @property
    def has_suspicious_binaries(self) -> bool:
        return self.suspicious_count > 0


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0-8 bits/byte)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _is_binary(path: str) -> bool:
    """Quick check if a file is binary by reading first 8KB."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        # If there are null bytes, it's binary
        return b"\x00" in chunk
    except OSError:
        return False


def scan_directory(directory: str) -> BinaryScanResult:
    """Walk a directory and flag suspicious binary files."""
    result = BinaryScanResult()

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, directory)

            if not _is_binary(fpath):
                continue

            result.binary_count += 1
            ext = os.path.splitext(fname)[1].lower()
            size = os.path.getsize(fpath)

            # Check for suspicious extension
            if ext in _SUSPICIOUS_EXTENSIONS:
                result.findings.append(BinaryFinding(
                    path=relpath,
                    size=size,
                    reason=f"Suspicious file type: {ext}",
                ))
                result.suspicious_count += 1
                continue

            # Skip very large files and known-safe extensions
            if size > _MAX_SCAN_SIZE:
                continue
            if ext in _EXPECTED_BINARY_EXTENSIONS:
                # Still check entropy on expected binaries — a .png with
                # entropy > 7.5 might have an appended payload
                pass

            # Entropy analysis
            try:
                with open(fpath, "rb") as f:
                    data = f.read(_MAX_SCAN_SIZE)
                entropy = _shannon_entropy(data)
            except OSError:
                continue

            if entropy > _HIGH_ENTROPY_THRESHOLD:
                result.findings.append(BinaryFinding(
                    path=relpath,
                    size=size,
                    reason=f"High entropy ({entropy:.2f} bits/byte) — "
                           f"may contain encrypted/encoded payload",
                    entropy=entropy,
                ))
                result.suspicious_count += 1

    return result


def scan_diff_for_new_binaries(old_dir: str, new_dir: str) -> BinaryScanResult:
    """Compare old and new package directories, scanning only new/changed
    binary files for suspicious characteristics."""
    result = BinaryScanResult()

    old_files = set()
    if os.path.isdir(old_dir):
        for root, _dirs, files in os.walk(old_dir):
            for fname in files:
                relpath = os.path.relpath(os.path.join(root, fname), old_dir)
                old_files.add(relpath)

    if not os.path.isdir(new_dir):
        return result

    for root, _dirs, files in os.walk(new_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, new_dir)

            if not _is_binary(fpath):
                continue

            result.binary_count += 1

            # Only flag new or changed binaries
            old_path = os.path.join(old_dir, relpath)
            if relpath in old_files and os.path.exists(old_path):
                # File existed before — check if it changed
                try:
                    with open(old_path, "rb") as f:
                        old_data = f.read(32)
                    with open(fpath, "rb") as f:
                        new_data = f.read(32)
                    if old_data == new_data:
                        continue  # Unchanged, skip
                except OSError:
                    pass

            ext = os.path.splitext(fname)[1].lower()
            size = os.path.getsize(fpath)

            if ext in _SUSPICIOUS_EXTENSIONS:
                result.findings.append(BinaryFinding(
                    path=relpath,
                    size=size,
                    reason=f"New suspicious file type: {ext}",
                ))
                result.suspicious_count += 1
                continue

            if size > _MAX_SCAN_SIZE:
                continue

            try:
                with open(fpath, "rb") as f:
                    data = f.read(_MAX_SCAN_SIZE)
                entropy = _shannon_entropy(data)
            except OSError:
                continue

            if entropy > _HIGH_ENTROPY_THRESHOLD:
                is_new = relpath not in old_files
                label = "New binary" if is_new else "Changed binary"
                result.findings.append(BinaryFinding(
                    path=relpath,
                    size=size,
                    reason=f"{label} with high entropy ({entropy:.2f} bits/byte) — "
                           f"may contain steganographic or encrypted payload",
                    entropy=entropy,
                ))
                result.suspicious_count += 1

    return result
