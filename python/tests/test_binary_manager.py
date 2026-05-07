"""Targeted tests for the betterleaks BinaryManager security guards."""
from __future__ import annotations

import pytest

from rafter_cli.utils.binary_manager import (
    BETTERLEAKS_PINNED_HASHES,
    BETTERLEAKS_VERSION,
    BinaryManager,
)


class TestVersionValidation:
    """`--version` flows into a download URL — guard against injection."""

    @pytest.mark.parametrize(
        "bad_version",
        [
            "1.1.2/../evil",
            "../etc/passwd",
            "1.1.2 && rm -rf /",
            "1.1.2;curl evil.com",
            "v1.1.2/whatever",  # slashes not allowed
            "",                  # empty
        ],
    )
    def test_rejects_invalid_version(self, bad_version):
        bm = BinaryManager()
        with pytest.raises(ValueError, match="Invalid betterleaks version"):
            bm.download_betterleaks(version=bad_version)

    @pytest.mark.parametrize(
        "good_version",
        ["1.1.2", "1.0.0", "v1.1.2", "1.1.2-rc1", "2.0.0_beta"],
    )
    def test_accepts_well_formed_version(self, good_version, monkeypatch):
        """Valid shape should pass validation. Block before any network call by
        forcing platform-unsupported."""
        bm = BinaryManager()
        monkeypatch.setattr(bm, "is_platform_supported", lambda: False)
        # Should reach the platform check (then raise RuntimeError, not ValueError).
        with pytest.raises(RuntimeError, match="not available for"):
            bm.download_betterleaks(version=good_version)


class TestPinnedHashes:
    """The bundled BETTERLEAKS_VERSION must have a complete hash table —
    otherwise we silently fall back to fetching the upstream checksums.txt
    on the default install path, which the migration explicitly avoids."""

    def test_pinned_hashes_cover_all_supported_artifacts(self):
        version = BETTERLEAKS_VERSION
        expected = {
            f"betterleaks_{version}_darwin_arm64.tar.gz",
            f"betterleaks_{version}_darwin_x64.tar.gz",
            f"betterleaks_{version}_linux_arm64.tar.gz",
            f"betterleaks_{version}_linux_x64.tar.gz",
            f"betterleaks_{version}_windows_arm64.zip",
            f"betterleaks_{version}_windows_x64.zip",
        }
        missing = expected - set(BETTERLEAKS_PINNED_HASHES)
        assert not missing, (
            f"Missing pinned SHA256 for: {missing}. "
            f"After bumping BETTERLEAKS_VERSION, refresh BETTERLEAKS_PINNED_HASHES."
        )

    def test_pinned_hashes_are_64_hex_chars(self):
        for filename, hash_ in BETTERLEAKS_PINNED_HASHES.items():
            assert len(hash_) == 64, f"{filename}: hash is not 64 chars"
            int(hash_, 16)  # raises ValueError if not hex


class TestNonHttpsRefused:
    """`_download_file` is the only network entry point; refuse non-https."""

    def test_refuses_http_url(self):
        bm = BinaryManager()
        with pytest.raises(RuntimeError, match="non-https"):
            bm._download_file(
                "http://example.com/foo",  # type: ignore[arg-type]
                bm.bin_dir / "_test.bin",
                lambda _: None,
            )

    def test_refuses_file_url(self):
        bm = BinaryManager()
        with pytest.raises(RuntimeError, match="non-https"):
            bm._download_file(
                "file:///etc/passwd",  # type: ignore[arg-type]
                bm.bin_dir / "_test.bin",
                lambda _: None,
            )
