# MIT License © 2025 Motohiro Suzuki
"""
keysources/qkd_factory.py

Stage167-B compatibility:
- Accept both config styles:
    (A) cfg.enable_qkd / cfg.qkd_seed / (optional) cfg.qkd_source
    (B) cfg.qkd.enabled / cfg.qkd.seed / cfg.qkd.source
- If QKD is enabled but source is None/empty, default to "e91".
- Never raise "Unknown qkd_source: None" (that breaks failover intent).
"""

from __future__ import annotations

from typing import Any


def _enabled(cfg: Any) -> bool:
    if hasattr(cfg, "qkd"):
        return bool(getattr(cfg.qkd, "enabled", False))
    return bool(getattr(cfg, "enable_qkd", False))


def _source(cfg: Any) -> str | None:
    # Prefer cfg.qkd.source if available
    if hasattr(cfg, "qkd"):
        v = getattr(cfg.qkd, "source", None)
        if isinstance(v, str) and v.strip():
            return v.strip()

    v2 = getattr(cfg, "qkd_source", None)
    if isinstance(v2, str) and v2.strip():
        return v2.strip()

    return None


def _seed(cfg: Any) -> int | None:
    if hasattr(cfg, "qkd"):
        s = getattr(cfg.qkd, "seed", None)
        return None if s is None else int(s)
    s2 = getattr(cfg, "qkd_seed", None)
    return None if s2 is None else int(s2)


def make_qkd_source(cfg: Any):
    """
    Factory for QKD KeySource.

    Supported sources (case-insensitive):
      - None / ""  -> defaults to "e91"
      - "e91"
      - "qkd_e91_dev"
      - "dev"
    """
    if not _enabled(cfg):
        raise RuntimeError("QKD disabled (enable_qkd=False)")

    src = (_source(cfg) or "e91").lower()  # ★ここが今回の修正の核心
    seed = _seed(cfg)

    # --- E91 dev key source (Stage161/162 style) ---
    # We try multiple module names to match your project evolution.
    if src in ("e91", "qkd_e91_dev", "dev"):
        # Try keysources/qkd_e91.py
        try:
            from keysources.qkd_e91 import E91KeySource  # type: ignore
            ks = E91KeySource()
            if seed is not None and hasattr(ks, "seed"):
                try:
                    ks.seed = seed
                except Exception:
                    pass
            return ks
        except Exception:
            pass

        # Try keysources/e91.py
        try:
            from keysources.e91 import E91KeySource  # type: ignore
            ks = E91KeySource()
            if seed is not None and hasattr(ks, "seed"):
                try:
                    ks.seed = seed
                except Exception:
                    pass
            return ks
        except Exception:
            pass

        # Try keysources/qkd_e91_dev.py (older naming)
        try:
            from keysources.qkd_e91_dev import E91KeySource  # type: ignore
            ks = E91KeySource()
            if seed is not None and hasattr(ks, "seed"):
                try:
                    ks.seed = seed
                except Exception:
                    pass
            return ks
        except Exception:
            pass

        # Last resort: direct class name used in earlier snippets
        try:
            from keysources.qkd_e91_dev import QKDE91KeySource  # type: ignore
            ks = QKDE91KeySource()
            return ks
        except Exception:
            pass

        raise RuntimeError(
            "QKD source 'e91' selected but E91KeySource implementation not found. "
            "Expected one of: keysources/qkd_e91.py, keysources/e91.py, keysources/qkd_e91_dev.py"
        )

    raise RuntimeError(f"Unknown qkd_source: {src}")
