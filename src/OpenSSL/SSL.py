"""
``OpenSSL.SSL`` - re-exported from the Rust implementation.

The implementation of this module lives in the ``pyopenssl`` Rust crate
(in the ``rust/`` directory of this repository), which is built into
pyca/cryptography's ``_rust`` extension module in released packages.
"""
# ruff: noqa: F822, RUF022

from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

from OpenSSL._rust import _SSL as _mod

_T = TypeVar("_T")


def _make_requires(flag: int, error: str) -> Callable[[_T], _T]:
    """
    Builds a decorator that ensures that functions that rely on OpenSSL
    functions that are not present in this build raise NotImplementedError,
    rather than AttributeError.
    """

    def _requires_decorator(func):  # type: ignore[no-untyped-def]
        if not flag:

            @wraps(func)
            def explode(*args, **kwargs):  # type: ignore[no-untyped-def]
                raise NotImplementedError(error)

            return explode
        else:
            return func

    return _requires_decorator


__all__ = [
    "DTLS_CLIENT_METHOD",
    "DTLS_METHOD",
    "DTLS_SERVER_METHOD",
    "MODE_RELEASE_BUFFERS",
    "NO_OVERLAPPING_PROTOCOLS",
    "OPENSSL_BUILT_ON",
    "OPENSSL_CFLAGS",
    "OPENSSL_DIR",
    "OPENSSL_PLATFORM",
    "OPENSSL_VERSION",
    "OPENSSL_VERSION_NUMBER",
    "OP_ALL",
    "OP_CIPHER_SERVER_PREFERENCE",
    "OP_DONT_INSERT_EMPTY_FRAGMENTS",
    "OP_EPHEMERAL_RSA",
    "OP_MICROSOFT_BIG_SSLV3_BUFFER",
    "OP_MICROSOFT_SESS_ID_BUG",
    "OP_MSIE_SSLV2_RSA_PADDING",
    "OP_NETSCAPE_CA_DN_BUG",
    "OP_NETSCAPE_CHALLENGE_BUG",
    "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG",
    "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
    "OP_NO_COMPRESSION",
    "OP_NO_QUERY_MTU",
    "OP_NO_TICKET",
    "OP_PKCS1_CHECK_1",
    "OP_PKCS1_CHECK_2",
    "OP_SINGLE_DH_USE",
    "OP_SINGLE_ECDH_USE",
    "OP_SSLEAY_080_CLIENT_DH_BUG",
    "OP_SSLREF2_REUSE_CERT_TYPE_BUG",
    "OP_TLS_BLOCK_PADDING_BUG",
    "OP_TLS_D5_BUG",
    "OP_TLS_ROLLBACK_BUG",
    "RECEIVED_SHUTDOWN",
    "SENT_SHUTDOWN",
    "SESS_CACHE_BOTH",
    "SESS_CACHE_CLIENT",
    "SESS_CACHE_NO_AUTO_CLEAR",
    "SESS_CACHE_NO_INTERNAL",
    "SESS_CACHE_NO_INTERNAL_LOOKUP",
    "SESS_CACHE_NO_INTERNAL_STORE",
    "SESS_CACHE_OFF",
    "SESS_CACHE_SERVER",
    "SSL3_VERSION",
    "SSLEAY_BUILT_ON",
    "SSLEAY_CFLAGS",
    "SSLEAY_DIR",
    "SSLEAY_PLATFORM",
    "SSLEAY_VERSION",
    "SSL_CB_ACCEPT_EXIT",
    "SSL_CB_ACCEPT_LOOP",
    "SSL_CB_ALERT",
    "SSL_CB_CONNECT_EXIT",
    "SSL_CB_CONNECT_LOOP",
    "SSL_CB_EXIT",
    "SSL_CB_HANDSHAKE_DONE",
    "SSL_CB_HANDSHAKE_START",
    "SSL_CB_LOOP",
    "SSL_CB_READ",
    "SSL_CB_READ_ALERT",
    "SSL_CB_WRITE",
    "SSL_CB_WRITE_ALERT",
    "SSL_ST_ACCEPT",
    "SSL_ST_CONNECT",
    "SSL_ST_MASK",
    "TLS1_1_VERSION",
    "TLS1_2_VERSION",
    "TLS1_3_VERSION",
    "TLS1_VERSION",
    "TLS_CLIENT_METHOD",
    "TLS_METHOD",
    "TLS_SERVER_METHOD",
    "VERIFY_CLIENT_ONCE",
    "VERIFY_FAIL_IF_NO_PEER_CERT",
    "VERIFY_NONE",
    "VERIFY_PEER",
    "Connection",
    "Context",
    "Error",
    "OP_NO_SSLv2",
    "OP_NO_SSLv3",
    "OP_NO_TLSv1",
    "OP_NO_TLSv1_1",
    "OP_NO_TLSv1_2",
    "OP_NO_TLSv1_3",
    "SSLeay_version",
    "SSLv23_METHOD",
    "Session",
    "SysCallError",
    "TLSv1_1_METHOD",
    "TLSv1_2_METHOD",
    "TLSv1_METHOD",
    "WantReadError",
    "WantWriteError",
    "WantX509LookupError",
    "X509VerificationCodes",
    "ZeroReturnError",
    "OP_COOKIE_EXCHANGE",
    "OP_NO_RENEGOTIATION",
    "OP_IGNORE_UNEXPECTED_EOF",
    "OP_LEGACY_SERVER_CONNECT",
]

for _name in dir(_mod):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_mod, _name)
del _name
