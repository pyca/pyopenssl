"""
PRNG management routines, thin wrappers.
"""

from __future__ import annotations

import warnings

from OpenSSL._rust import _rand as _mod

warnings.warn(
    "OpenSSL.rand is deprecated - you should use os.urandom instead",
    DeprecationWarning,
    stacklevel=3,
)

add = _mod.add
status = _mod.status

__all__ = ["add", "status"]
