//! Rust implementation of pyOpenSSL, built on rust-openssl.
//!
//! This crate implements the `OpenSSL.SSL`, `OpenSSL.crypto`, and
//! `OpenSSL.rand` Python modules. It is structured as a library so that it
//! can be linked into another PyO3 extension module:
//!
//! * In this repository, the `pyopenssl-shim` crate builds it as the
//!   standalone `_pyopenssl_shim` extension module for testing.
//! * In released packages, pyca/cryptography's `_rust` extension depends on
//!   this crate and exposes [`populate_module`]'s output as
//!   `cryptography.hazmat.bindings._rust.pyopenssl`, sharing a single copy
//!   of OpenSSL between cryptography and pyOpenSSL.

use pyo3::prelude::*;

pub mod crypto;
mod ffi_ext;
pub mod rand;
pub mod ssl;
pub mod util;

/// Populate `m` with the pyOpenSSL submodules (`_SSL`, `_crypto`, `_rand`,
/// `_util`).
pub fn populate_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_submodule(&crypto::create_module(py)?)?;
    m.add_submodule(&ssl::create_module(py)?)?;
    m.add_submodule(&rand::create_module(py)?)?;
    m.add_submodule(&util::create_module(py)?)?;
    Ok(())
}
