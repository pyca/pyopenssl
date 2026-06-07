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

## Missing rust-openssl functionality

pyOpenSSL needs a number of OpenSSL functions, macros, and constants that
rust-openssl does not currently expose, and pyOpenSSL's object model
(in-place mutation of `X509`, `X509_NAME` aliasing into certificates,
memory-BIO driven `SSL` objects, C callbacks that re-enter Python, etc.)
does not map onto rust-openssl's safe, builder-oriented API. Those gaps are
worked around in `pyopenssl/src/ffi_ext.rs` (extra `extern "C"`
declarations and macro re-implementations on top of `openssl-sys`) and by
using raw `openssl-sys` calls instead of the safe `openssl` crate where
required. See `ffi_ext.rs` for the full inventory.

[rust-openssl]: https://github.com/sfackler/rust-openssl
[PyO3]: https://pyo3.rs
[maturin]: https://maturin.rs
