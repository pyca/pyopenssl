//! Implementation of the `OpenSSL.rand` module.

use openssl_sys as ffi;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Mix bytes from *string* into the PRNG state.
#[pyfunction]
fn add(buffer: &Bound<'_, PyAny>, entropy: &Bound<'_, PyAny>) -> PyResult<()> {
    let buffer = buffer
        .cast::<PyBytes>()
        .map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err("buffer must be a byte string")
        })?
        .as_bytes();
    let entropy: f64 = if entropy.is_instance_of::<pyo3::types::PyInt>() {
        entropy.extract::<i64>()? as f64
    } else {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "entropy must be an integer",
        ));
    };
    unsafe {
        ffi::RAND_add(
            buffer.as_ptr() as *const libc::c_void,
            buffer.len() as libc::c_int,
            entropy,
        );
    }
    Ok(())
}

/// Check whether the PRNG has been seeded with enough data.
#[pyfunction]
fn status() -> i32 {
    unsafe { ffi::RAND_status() }
}

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "_rand")?;
    m.add_function(pyo3::wrap_pyfunction!(add, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(status, &m)?)?;
    Ok(m)
}
