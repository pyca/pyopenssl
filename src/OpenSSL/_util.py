"""
Backwards-compatibility helpers for code (and tests) which used the cffi
based ``OpenSSL._util`` module. The OpenSSL binding now lives in Rust (see
the ``pyopenssl`` crate in this repository), so only a minimal shim is
provided here.
"""

from __future__ import annotations

import os
import sys
from typing import Union

from OpenSSL._rust import _util as _mod

if sys.version_info >= (3, 9):
    StrOrBytesPath = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]
else:
    StrOrBytesPath = Union[str, bytes, os.PathLike]


class _Lib:
    """
    A tiny stand-in for the old cffi ``lib`` object, providing only what is
    needed to interact with the OpenSSL error queue.
    """

    ERR_LIB_EVP = _mod.ERR_LIB_EVP

    @staticmethod
    def ERR_put_error(
        lib: int, func: int, reason: int, file: bytes, line: int
    ) -> None:
        _mod.ERR_put_error(lib, func, reason, file, line)


lib = _Lib()


def exception_from_error_queue(exception_type: type[Exception]) -> None:
    """
    Convert an OpenSSL library failure into a Python exception.
    """
    _mod.exception_from_error_queue(exception_type)


def path_bytes(s: StrOrBytesPath) -> bytes:
    b = os.fspath(s)
    if isinstance(b, str):
        return b.encode(sys.getfilesystemencoding())
    return b


def byte_string(s: str) -> bytes:
    return s.encode("charmap")
