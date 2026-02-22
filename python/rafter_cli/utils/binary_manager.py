"""Binary manager: download, extract, and verify the gitleaks binary."""
from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable, Optional

GITLEAKS_VERSION = "8.18.2"

_SUPPORTED = {
    ("darwin", "x86_64"),
    ("darwin", "arm64"),
    ("linux", "x86_64"),
    ("linux", "arm64"),
    ("linux", "aarch64"),
    ("win32", "x86_64"),
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

    def get_gitleaks_path(self) -> Path:
        ext = ".exe" if self._sys_platform() == "win32" else ""
        return self.bin_dir / f"gitleaks{ext}"

    def is_gitleaks_installed(self) -> bool:
        return self.get_gitleaks_path().exists()

    def verify_gitleaks_verbose(self, binary_path: Optional[Path] = None) -> dict:
        """Run 'gitleaks version' and return {ok, stdout, stderr}."""
        path = binary_path or self.get_gitleaks_path()
        try:
            result = subprocess.run(
                [str(path), "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ok = "gitleaks version" in result.stdout
            return {"ok": ok, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
        except Exception as e:
            return {"ok": False, "stdout": "", "stderr": str(e)}

    def collect_binary_diagnostics(self, binary_path: Optional[Path] = None) -> str:
        """Return diagnostic string: file type, uname, libc detection."""
        path = binary_path or self.get_gitleaks_path()
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
                        "  libc: musl (gitleaks linux builds target glibc; "
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

    def download_gitleaks(self, on_progress: Optional[Callable[[str], None]] = None) -> None:
        """Download, extract, chmod, and verify the gitleaks binary."""
        log = on_progress or (lambda _: None)

        if not self.is_platform_supported():
            raise RuntimeError(
                f"Gitleaks not available for {self._sys_platform()}/{self._machine()}"
            )

        self.bin_dir.mkdir(parents=True, exist_ok=True)

        plat = self._platform_string()
        arch = self._arch_string()
        url = self._build_download_url(plat, arch)

        log(f"Downloading Gitleaks v{GITLEAKS_VERSION} for {plat}/{arch}...")
        log(f"  URL: {url}")

        archive_name = "gitleaks.zip" if plat == "windows" else "gitleaks.tar.gz"
        archive_path = self.bin_dir / archive_name

        try:
            self._download_file(url, archive_path, log)

            size_kb = archive_path.stat().st_size / 1024
            log(f"  Downloaded: {size_kb:.1f} KB")

            log("Extracting binary...")
            if plat == "windows":
                raise NotImplementedError("Windows zip extraction not yet implemented")
            else:
                self._extract_tarball(archive_path)

            if self._sys_platform() != "win32":
                gitleaks_path = self.get_gitleaks_path()
                gitleaks_path.chmod(gitleaks_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                log("  chmod +x applied")

            result = self.verify_gitleaks_verbose()
            if not result["ok"]:
                diag = self.collect_binary_diagnostics()
                raise RuntimeError(
                    f"Gitleaks binary failed to execute.\n"
                    f"  Binary: {self.get_gitleaks_path()}\n"
                    f"  URL: {url}\n"
                    + (f"  gitleaks version stdout: {result['stdout']}\n" if result["stdout"] else "")
                    + (f"  gitleaks version stderr: {result['stderr']}\n" if result["stderr"] else "")
                    + f"Diagnostics:\n{diag}\n"
                    + "Fix: ensure the binary matches your OS/arch, or install gitleaks manually and ensure it is on PATH."
                )

            log(f"  Verified: {result['stdout']}")

            if archive_path.exists():
                archive_path.unlink()

            log("Gitleaks installed successfully")

        except Exception:
            if archive_path.exists():
                archive_path.unlink()
            binary = self.get_gitleaks_path()
            if binary.exists():
                binary.unlink()
            raise

    # ── private helpers ───────────────────────────────────────────────

    def _build_download_url(self, platform_str: str, arch_str: str) -> str:
        base = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
        if platform_str == "windows":
            return f"{base}/gitleaks_{GITLEAKS_VERSION}_windows_{arch_str}.zip"
        return f"{base}/gitleaks_{GITLEAKS_VERSION}_{platform_str}_{arch_str}.tar.gz"

    def _download_file(
        self,
        url: str,
        dest: Path,
        on_progress: Callable[[str], None],
        *,
        _redirects: int = 0,
    ) -> None:
        if _redirects > 10:
            raise RuntimeError("Too many redirects")

        request = urllib.request.Request(
            url,
            headers={"User-Agent": f"rafter-cli/{GITLEAKS_VERSION}"},
        )

        with urllib.request.urlopen(request, timeout=60) as response:
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

    def _extract_tarball(self, archive_path: Path) -> None:
        """Extract only the gitleaks binary from the tarball."""
        # filter="data" was added in Python 3.12; fall back gracefully on older runtimes.
        _extract_kwargs: dict = {}
        if sys.version_info >= (3, 12):
            _extract_kwargs["filter"] = "data"

        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                base = os.path.basename(member.name)
                if base in ("gitleaks", "gitleaks.exe"):
                    # Flatten: extract directly to bin_dir with just the binary name
                    member.name = base
                    tf.extract(member, path=self.bin_dir, **_extract_kwargs)
