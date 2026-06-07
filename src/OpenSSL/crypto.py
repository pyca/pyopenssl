"""
``OpenSSL.crypto`` - re-exported from the Rust implementation.

The implementation of this module lives in the ``pyopenssl`` Rust crate
(in the ``rust/`` directory of this repository), which is built into
pyca/cryptography's ``_rust`` extension module in released packages.
"""
# ruff: noqa: F822

from __future__ import annotations

from typing import Callable, Union

from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

from OpenSSL._rust import _crypto as _mod

_PrivateKey = Union[
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
]
_PublicKey = Union[
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    rsa.RSAPublicKey,
]
_Key = Union[_PrivateKey, _PublicKey]
PassphraseCallableT = Union[bytes, Callable[..., bytes]]

__all__ = [
    "FILETYPE_ASN1",
    "FILETYPE_PEM",
    "FILETYPE_TEXT",
    "TYPE_DSA",
    "TYPE_RSA",
    "X509",
    "Error",
    "PKey",
    "X509Name",
    "X509Req",
    "X509Store",
    "X509StoreContext",
    "X509StoreContextError",
    "X509StoreFlags",
    "dump_certificate",
    "dump_certificate_request",
    "dump_privatekey",
    "dump_publickey",
    "get_elliptic_curve",
    "get_elliptic_curves",
    "load_certificate",
    "load_certificate_request",
    "load_privatekey",
    "load_publickey",
]

for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
del _name
