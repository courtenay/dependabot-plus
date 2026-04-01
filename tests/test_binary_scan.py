from __future__ import annotations


from dependabot_plus.analysis.binary_scan import (
    _shannon_entropy,
    scan_diff_for_new_binaries,
    scan_directory,
)


def test_shannon_entropy_empty():
    assert _shannon_entropy(b"") == 0.0


def test_shannon_entropy_uniform():
    """All same bytes = 0 entropy."""
    assert _shannon_entropy(b"\x00" * 1000) == 0.0


def test_shannon_entropy_random_is_high():
    """Random-looking data should have high entropy."""
    import random
    random.seed(42)
    data = bytes(random.randint(0, 255) for _ in range(10000))
    entropy = _shannon_entropy(data)
    assert entropy > 7.0


def test_scan_directory_empty(tmp_path):
    result = scan_directory(str(tmp_path))
    assert result.binary_count == 0
    assert result.suspicious_count == 0
    assert result.findings == []


def test_scan_directory_flags_suspicious_extension(tmp_path):
    # Create a .exe file
    exe = tmp_path / "payload.exe"
    exe.write_bytes(b"\x00" * 100)
    result = scan_directory(str(tmp_path))
    assert result.suspicious_count == 1
    assert "Suspicious file type: .exe" in result.findings[0].reason


def test_scan_directory_flags_high_entropy_binary(tmp_path):
    # Create a .png with random (high entropy) content
    import random
    random.seed(99)
    data = bytes(random.randint(0, 255) for _ in range(5000))
    png = tmp_path / "image.png"
    png.write_bytes(b"\x00" + data)  # null byte makes it binary
    result = scan_directory(str(tmp_path))
    assert result.binary_count == 1
    # Should flag as high entropy
    assert any("entropy" in f.reason.lower() for f in result.findings)


def test_scan_directory_ignores_text_files(tmp_path):
    (tmp_path / "readme.md").write_text("hello world\n")
    (tmp_path / "index.js").write_text("module.exports = {}\n")
    result = scan_directory(str(tmp_path))
    assert result.binary_count == 0


def test_scan_diff_flags_new_binary(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    # Only in new: a suspicious .exe
    (new / "trojan.exe").write_bytes(b"\x00" * 50)
    result = scan_diff_for_new_binaries(str(old), str(new))
    assert result.suspicious_count == 1


def test_scan_diff_ignores_unchanged_binary(tmp_path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    # Same file in both
    data = b"\x00\x01\x02" * 100
    (old / "icon.bin").write_bytes(data)
    (new / "icon.bin").write_bytes(data)
    result = scan_diff_for_new_binaries(str(old), str(new))
    assert result.suspicious_count == 0
