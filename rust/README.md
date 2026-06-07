# pyOpenSSL's Rust implementation

The implementation of the `OpenSSL.SSL`, `OpenSSL.crypto`, and
`OpenSSL.rand` Python modules lives here, written in Rust against
[rust-openssl] (the `openssl` and `openssl-sys` crates) and [PyO3].

## Layout

* `pyopenssl/` — the `pyopenssl` crate. This is a *library* crate exposing
  `pyopenssl::populate_module`, which fills a Python module with the
  pyOpenSSL submodules (`_SSL`, `_crypto`, `_rand`, `_util`). It is designed
  to be embedded into another PyO3 extension module:

  * In **released packages**, pyca/cryptography's `_rust` extension depends
    on this crate and exposes the result as
    `cryptography.hazmat.bindings._rust.pyopenssl`. The pure-Python
    `OpenSSL` package published to PyPI just re-exports from there. This
    arrangement means a single copy of OpenSSL is linked and shared between
    cryptography and pyOpenSSL.

  * For **in-repo testing**, the `shim/` crate (below) builds the same code
    as a standalone extension module, so the test suite can run against an
    unmodified cryptography release.

* `shim/` — the `pyopenssl-shim` crate, a thin `cdylib` wrapper producing
  the `_pyopenssl_shim` extension module. `OpenSSL._rust` falls back to
  importing this when cryptography does not provide the `pyopenssl`
  submodule. Build it with [maturin]:

  ```console
  $ pip install ./rust/shim
  ```

  or, for development:

  ```console
  $ maturin develop -m rust/shim/Cargo.toml
  ```

## Relationship to safe rust-openssl

The implementation uses rust-openssl's safe API wherever its model fits:
`SslContextBuilder` (kept un-`build()`-en, since pyOpenSSL contexts stay
configurable until first use) with closure-based verify/servername/keylog/
cookie callbacks, `SslStream<PyBio>` for connection I/O (where `PyBio`
proxies either the Python socket's fd or a pair of in-memory buffers),
and the safe `X509`/`PKey`/`X509Store`/`X509StoreContext` types for the
crypto module.

openssl-sys is used directly only where safe rust-openssl cannot express
pyOpenSSL's semantics. The main categories (each call site carries a
comment):

* **In-place mutation of `X509`/`X509Req`/`X509_NAME`** — the safe API is
  strictly builder-based (`X509Builder` cannot wrap an existing
  certificate) and `X509Name` objects returned by `get_subject()` *alias*
  the name inside the certificate.
* **ASN.1 TIME string access** — pyOpenSSL exposes `notBefore`/`notAfter`
  as raw `YYYYMMDDhhmmssZ` strings; `Asn1TimeRef` only supports Display
  formatting.
* **Callback shapes** — the info callback and the context-wide passphrase
  callback (`SSL_CTX_set_default_passwd_cb`) have no safe wrappers; the
  safe ALPN-select callback cannot return bytes outside the client's
  offer; the safe OCSP status callback cannot express the OK/NOACK/fatal
  result space.
* **Renegotiation/DTLS surface** — `SSL_renegotiate(_pending)`,
  `SSL_total_renegotiations`, `SSL_want`, `DTLSv1_listen`,
  `DTLSv1_{get,handle}_timeout`, `DTLS_get_data_mtu`.
* **Small missing functions/getters** — see `pyopenssl/src/ffi_ext.rs`
  for the exact inventory (e.g. `X509_STORE_load_locations`,
  `X509_STORE_add_crl`, `X509_STORE_up_ref`, `SSL_get_client_CA_list`,
  `SSL_get_cipher_list`, `X509_NAME_oneline/_hash/_delete_entry`,
  `EC_get_builtin_curves`, the `FILETYPE_TEXT` printers, session-cache /
  timeout / verify-depth getters, and — surprisingly — `BIO_free` and
  `OBJ_txt2nid`, which openssl-sys does not bind). Additionally,
  `SslVerifyMode` cannot represent `SSL_VERIFY_CLIENT_ONCE` (and
  `verify_mode()` panics on unknown bits), `SslVersion` is not
  constructible from a raw protocol number, and `Asn1StringRef::as_utf8`
  truncates at NUL bytes.

[rust-openssl]: https://github.com/sfackler/rust-openssl
[PyO3]: https://pyo3.rs
[maturin]: https://maturin.rs
