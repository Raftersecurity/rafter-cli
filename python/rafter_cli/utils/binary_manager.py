"""Binary manager: download, extract, and verify the betterleaks binary."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Optional

BETTERLEAKS_VERSION = "1.1.2"

# Pinned SHA256 hashes for the bundled BETTERLEAKS_VERSION release artifacts.
# Pulled from upstream `checksums.txt` at vendoring time. Pinning in source
# means we don't rely on the release-page `checksums.txt` to authenticate
# itself when installing the version we ship by default. Refresh whenever
# BETTERLEAKS_VERSION changes.
BETTERLEAKS_PINNED_HASHES: dict[str, str] = {
    "betterleaks_1.1.2_darwin_arm64.tar.gz": "19cc2298463d7abf0aee9a03208a49834ab2e6f8411781c4cf1360827b3ded36",
    "betterleaks_1.1.2_darwin_x64.tar.gz":   "d51904879ed77fabad157ec67cb8dd3f5548e975fc32082e6abc30a026e1bec1",
    "betterleaks_1.1.2_linux_arm64.tar.gz":  "4d73dcbfe38c38878ee69e82b5aaa539398be8331f62b5640eb214ac04d890b0",
    "betterleaks_1.1.2_linux_x64.tar.gz":    "648c20617178065072ff1791d383192a62c911d9b4427f0426a8c504a6d9ddad",
    "betterleaks_1.1.2_windows_arm64.zip":   "8cc28068e8c7846027bc9b14f1c200cce64ff4198f90be5730510631c59f23ce",
    "betterleaks_1.1.2_windows_x64.zip":     "e149c86d00fb99cce8d87def2cd1ff046c6889a0e912007d44668df5980cea3a",
}

# Allowed shape for the optional `--version` flag (prevents URL injection).
import re as _re
_VERSION_RE = _re.compile(r"^[A-Za-z0-9._-]+$")

_SUPPORTED = {
    ("darwin", "x86_64"),
    ("darwin", "arm64"),
    ("linux", "x86_64"),
    ("linux", "arm64"),
    ("linux", "aarch64"),
    ("win32", "x86_64"),
    ("win32", "arm64"),
}

_PLATFORM_MAP = {
    "darwin": "darwin",
    "linux": "linux",
    "win32": "windows",
}

_ARCH_MAP = {
    "x86_64": "x64",
    "arm64": "arm64",
    "aarch64": "arm64",
}


def _get_bin_dir() -> Path:
    return Path.home() / ".rafter" / "bin"


class BinaryManager:
    def __init__(self) -> None:
        self.bin_dir = _get_bin_dir()

    # ── platform helpers ──────────────────────────────────────────────

    def _sys_platform(self) -> str:
        return sys.platform  # darwin | linux | win32

    def _machine(self) -> str:
        return platform.machine()  # x86_64 | arm64 | aarch64

    def _platform_string(self) -> str:
        p = self._sys_platform()
        if p not in _PLATFORM_MAP:
            raise ValueError(f"Unsupported platform: {p}")
        return _PLATFORM_MAP[p]

    def _arch_string(self) -> str:
        m = self._machine()
        if m not in _ARCH_MAP:
            raise ValueError(f"Unsupported architecture: {m}")
        return _ARCH_MAP[m]

    # ── public API ────────────────────────────────────────────────────

    def is_platform_supported(self) -> bool:
        return (self._sys_platform(), self._machine()) in _SUPPORTED

    def get_betterleaks_path(self) -> Path:
        ext = ".exe" if self._sys_platform() == "win32" else ""
        return self.bin_dir / f"betterleaks{ext}"

    def is_betterleaks_installed(self) -> bool:
        return self.get_betterleaks_path().exists()

    def find_betterleaks_on_path(self) -> str | None:
        """Find betterleaks on system PATH (like Node's which/where)."""
        return shutil.which("betterleaks")

    def verify_betterleaks(self) -> bool:
        """Check if the managed betterleaks binary works (simple bool)."""
        if not self.is_betterleaks_installed():
            return False
        result = self.verify_betterleaks_verbose()
        return result["ok"]

    def get_betterleaks_version(self) -> str:
        """Return installed betterleaks version string, or 'not installed'/'unknown'."""
        if not self.is_betterleaks_installed():
            return "not installed"
        result = self.verify_betterleaks_verbose()
        if result["ok"] and result["stdout"]:
            return result["stdout"]
        return "unknown"

    def verify_betterleaks_verbose(self, binary_path: Optional[Path] = None) -> dict:
        """Run 'betterleaks version' and return {ok, stdout, stderr}.

        Accept any successful exit (code 0) rather than requiring specific
        stdout content.
        """
        path = binary_path or self.get_betterleaks_path()
        try:
            result = subprocess.run(
                [str(path), "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ok = result.returncode == 0
            return {"ok": ok, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
        except Exception as e:
            return {"ok": False, "stdout": "", "stderr": str(e)}

    def collect_binary_diagnostics(self, binary_path: Optional[Path] = None) -> str:
        """Return diagnostic string: file type, uname, libc detection."""
        path = binary_path or self.get_betterleaks_path()
        lines: list[str] = []

        # file(1) output
        if shutil.which("file"):
            try:
                r = subprocess.run(["file", str(path)], capture_output=True, text=True, timeout=5)
                lines.append(f"  file: {r.stdout.strip()}")
            except Exception:
                lines.append("  file: (unavailable)")
        else:
            lines.append("  file: (unavailable)")

        # uname
        try:
            r = subprocess.run(["uname", "-a"], capture_output=True, text=True, timeout=5)
            lines.append(f"  uname: {r.stdout.strip()}")
        except Exception:
            lines.append("  uname: (unavailable)")

        lines.append(f"  python arch: {self._machine()}, platform: {self._sys_platform()}")

        # glibc vs musl detection on Linux
        if self._sys_platform() == "linux":
            try:
                r = subprocess.run(
                    "ldd --version 2>&1 || true",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                out = r.stdout + r.stderr
                if "musl" in out:
                    lines.append(
                        "  libc: musl (betterleaks linux builds target glibc; "
                        "musl systems need a musl build or static binary)"
                    )
                elif "GLIBC" in out or "GNU" in out:
                    import re
                    m = re.search(r"(\d+\.\d+)", out)
                    lines.append(f"  libc: glibc {m.group(1) if m else '(version unknown)'}")
                else:
                    lines.append("  libc: unknown")
            except Exception:
                lines.append("  libc: (detection failed)")

        return "\n".join(lines)

    def download_betterleaks(
        self,
        on_progress: Optional[Callable[[str], None]] = None,
        version: str = BETTERLEAKS_VERSION,
    ) -> None:
        """Download, extract, chmod, and verify the betterleaks binary.

        Args:
            on_progress: Optional callback for progress messages.
            version: Betterleaks version to install (defaults to BETTERLEAKS_VERSION).
        """
        log = on_progress or (lambda _: None)

        if not _VERSION_RE.match(version):
            raise ValueError(
                f"Invalid betterleaks version: {version} (expected /^[A-Za-z0-9._-]+$/)"
            )

        if not self.is_platform_supported():
            raise RuntimeError(
                f"Betterleaks not available for {self._sys_platform()}/{self._machine()}"
            )

        self.bin_dir.mkdir(parents=True, exist_ok=True)

        plat = self._platform_string()
        arch = self._arch_string()
        url = self._build_download_url(plat, arch, version)

        log(f"Downloading Betterleaks v{version} for {plat}/{arch}...")
        log(f"  URL: {url}")

        archive_name = "betterleaks.zip" if plat == "windows" else "betterleaks.tar.gz"
        archive_path = self.bin_dir / archive_name

        try:
            self._download_file(url, archive_path, log)

            size_kb = archive_path.stat().st_size / 1024
            log(f"  Downloaded: {size_kb:.1f} KB")

            log("Verifying checksum...")
            self._verify_checksum(archive_path, plat, arch, version, log)
            log("  ✓ Checksum verified")

            log("Extracting binary...")
            if plat == "windows":
                self._extract_zip(archive_path)
            else:
                self._extract_tarball(archive_path)

            if self._sys_platform() != "win32":
                bl_path = self.get_betterleaks_path()
                bl_path.chmod(bl_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                log("  chmod +x applied")

            result = self.verify_betterleaks_verbose()
            if not result["ok"]:
                diag = self.collect_binary_diagnostics()
                raise RuntimeError(
                    f"Betterleaks binary failed to execute.\n"
                    f"  Binary: {self.get_betterleaks_path()}\n"
                    f"  URL: {url}\n"
                    + (f"  betterleaks version stdout: {result['stdout']}\n" if result["stdout"] else "")
                    + (f"  betterleaks version stderr: {result['stderr']}\n" if result["stderr"] else "")
                    + f"Diagnostics:\n{diag}\n"
                    + "Fix: ensure the binary matches your OS/arch, or install betterleaks manually and ensure it is on PATH."
                )

            log(f"  Verified: {result['stdout']}")

            if archive_path.exists():
                archive_path.unlink()

            log("Betterleaks installed successfully")

        except Exception:
            if archive_path.exists():
                archive_path.unlink()
            binary = self.get_betterleaks_path()
            if binary.exists():
                binary.unlink()
            raise

    # ── private helpers ───────────────────────────────────────────────

    def _build_download_url(self, platform_str: str, arch_str: str, version: str = BETTERLEAKS_VERSION) -> str:
        base = f"https://github.com/betterleaks/betterleaks/releases/download/v{version}"
        if platform_str == "windows":
            return f"{base}/betterleaks_{version}_windows_{arch_str}.zip"
        return f"{base}/betterleaks_{version}_{platform_str}_{arch_str}.tar.gz"

    def _verify_checksum(
        self,
        archive_path: Path,
        platform_str: str,
        arch_str: str,
        version: str,
        on_progress: Callable[[str], None],
    ) -> None:
        """Verify downloaded archive checksum.

        For BETTERLEAKS_VERSION (the version we vendor), use the SHA256 pinned
        in source — this prevents a release-page compromise from re-signing both
        the tarball and `checksums.txt`. For an explicit `--version <other>`,
        fall back to the upstream `checksums.txt` (TOFU at that moment).
        """
        if platform_str == "windows":
            archive_filename = f"betterleaks_{version}_windows_{arch_str}.zip"
        else:
            archive_filename = f"betterleaks_{version}_{platform_str}_{arch_str}.tar.gz"

        expected_hash: str | None = None
        source = ""

        if version == BETTERLEAKS_VERSION and archive_filename in BETTERLEAKS_PINNED_HASHES:
            expected_hash = BETTERLEAKS_PINNED_HASHES[archive_filename]
            source = "pinned in source"
        else:
            checksums_url = (
                f"https://github.com/betterleaks/betterleaks/releases/download/v{version}"
                f"/checksums.txt"
            )
            checksums_path = self.bin_dir / "checksums.txt"
            try:
                self._download_file(checksums_url, checksums_path, lambda _: None)
                checksums_content = checksums_path.read_text()
                expected_hash = self._parse_checksum_file(checksums_content, archive_filename)
            finally:
                if checksums_path.exists():
                    checksums_path.unlink()
            source = "release checksums.txt"

        if not expected_hash:
            raise RuntimeError(f"Checksum not found for {archive_filename} ({source})")

        actual_hash = self._compute_sha256(archive_path)
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Checksum mismatch for {archive_filename} ({source}):\n"
                f"  Expected: {expected_hash}\n"
                f"  Actual:   {actual_hash}\n"
                f"The downloaded file may be corrupted or tampered with."
            )

    @staticmethod
    def _parse_checksum_file(content: str, filename: str) -> str | None:
        """Parse a checksums.txt file and return the SHA256 hash for the given filename."""
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == filename:
                return parts[0].lower()
        return None

    @staticmethod
    def _compute_sha256(file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def _download_file(
        self,
        url: str,
        dest: Path,
        on_progress: Callable[[str], None],
    ) -> None:
        # Refuse to download non-https URLs (defends against an http:// initial
        # URL or against `urlopen` quietly accepting a downgrade in some configs).
        # `urlopen` already restricts redirects to http(s) and will raise on
        # http→https mixes, but we want a hard floor before the request goes out.
        if not url.lower().startswith("https://"):
            raise RuntimeError(f"Refusing non-https download URL: {url}")

        request = urllib.request.Request(
            url,
            headers={"User-Agent": f"rafter-cli/{BETTERLEAKS_VERSION}"},
        )

        with urllib.request.urlopen(request, timeout=60) as response:
            # urllib resolves redirects internally; verify the final URL is
            # still https (defense in depth — strips any pathological mixed
            # http/https redirect chain).
            final_url = response.geturl()
            if not final_url.lower().startswith("https://"):
                raise RuntimeError(f"Refusing non-https final URL after redirects: {final_url}")
            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            last_pct = 0

            with dest.open("wb") as f:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = int(downloaded / total * 100)
                        if pct >= last_pct + 10:
                            on_progress(f"  Downloading... {pct}%")
                            last_pct = pct

    def _extract_zip(self, archive_path: Path) -> None:
        """Extract only the betterleaks binary from a Windows zip archive.

        Defensively rejects symlink/hardlink-style entries — zip can encode
        these via Unix-mode external attrs, and we don't want a malicious
        release pointing the binary at e.g. `~/.ssh/authorized_keys`.
        """
        allowed = {"betterleaks", "betterleaks.exe"}
        with tempfile.TemporaryDirectory(prefix="rafter-betterleaks-") as tmp:
            tmp_path = Path(tmp)
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    # Reject path-traversal entries (zip-slip)
                    if info.filename.startswith("/") or ".." in info.filename:
                        continue
                    # Reject symlinks/hardlinks (Unix mode bits in external_attr)
                    if (info.external_attr >> 16) & 0o170000 in (0o120000, 0o140000):
                        continue
                    basename = os.path.basename(info.filename)
                    if basename not in allowed:
                        continue
                    info.filename = basename
                    zf.extract(info, tmp_path)

            found: Path | None = None
            for name in allowed:
                candidate = tmp_path / name
                if candidate.exists() and not candidate.is_symlink() and candidate.is_file():
                    found = candidate
                    break

            if found is None:
                raise RuntimeError("betterleaks binary not found in archive (or is symlink/special)")

            target = self.bin_dir / found.name
            shutil.copy2(str(found), str(target))

    def _extract_tarball(self, archive_path: Path) -> None:
        """Extract only the betterleaks binary from the tarball.

        Defensively rejects symlinks/hardlinks/devices and absolute / `..` paths.
        Without the symlink reject a malicious release could ship a `betterleaks`
        entry that's a symlink to e.g. `~/.ssh/authorized_keys`; the subsequent
        `chmod +x` (which follows symlinks) would then mode-flip the target.

        Uses `filter="data"` on Python 3.12+ which adds a second layer of
        defense (rejects unsafe member kinds at the stdlib level).
        """
        _extract_kwargs: dict = {}
        if sys.version_info >= (3, 12):
            _extract_kwargs["filter"] = "data"

        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                base = os.path.basename(member.name)
                if base not in ("betterleaks", "betterleaks.exe"):
                    continue
                if member.issym() or member.islnk() or member.isdev():
                    raise RuntimeError(
                        f"Refusing to extract non-regular tar entry: {member.name} "
                        f"(type={member.type!r})"
                    )
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    raise RuntimeError(f"Refusing path-traversal tar entry: {member.name}")
                member.name = base
                tf.extract(member, path=self.bin_dir, **_extract_kwargs)

        # Belt-and-suspenders: confirm what landed is a regular file.
        installed = self.get_betterleaks_path()
        if installed.exists():
            if installed.is_symlink() or not installed.is_file():
                installed.unlink()
                raise RuntimeError(
                    "Extracted betterleaks is not a regular file (symlink/special); aborting."
                )
