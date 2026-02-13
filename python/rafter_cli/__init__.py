"""Rafter CLI — security for AI builders."""
try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("rafter-cli")
except Exception:
    __version__ = "0.5.0"
