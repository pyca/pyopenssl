"""
Locate the Rust implementation of pyOpenSSL.

In released packages, pyOpenSSL's implementation is provided by
pyca/cryptography's ``_rust`` extension module (which builds the
``pyopenssl`` Rust crate from this repository into itself, so that a single
copy of OpenSSL is shared between cryptography and pyOpenSSL).

When working in the pyOpenSSL repository itself (where the installed
cryptography may not carry the pyopenssl submodule yet), we fall back to the
locally built ``_pyopenssl_shim`` extension module, which contains the same
Rust code built against its own copy of OpenSSL.
"""

from __future__ import annotations

try:
    from cryptography.hazmat.bindings._rust import (  # type: ignore[attr-defined]
        pyopenssl as _rust,
    )
except ImportError:
    try:
        import _pyopenssl_shim as _rust  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "pyOpenSSL's compiled implementation is not available. Either "
            "install a version of cryptography that provides "
            "cryptography.hazmat.bindings._rust.pyopenssl, or build the "
            "local test shim (see rust/shim/README)."
        )

_SSL = _rust._SSL
_crypto = _rust._crypto
_rand = _rust._rand
_util = _rust._util

__all__ = ["_SSL", "_crypto", "_rand", "_util"]
