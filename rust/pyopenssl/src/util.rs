//! Shared helpers: OpenSSL error queue handling, warnings, and
//! miscellaneous conversions.

use openssl_sys as ffi;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

use crate::ffi_ext;

/// Convert a C string pointer (possibly NULL) into a String ("" for NULL).
pub unsafe fn text(ptr: *const libc::c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Convert an `ErrorStack` into a Python list of (lib, func, reason)
/// string 3-tuples, matching the format the cffi implementation produced.
pub fn error_stack_to_list<'py>(
    py: Python<'py>,
    stack: &openssl::error::ErrorStack,
) -> PyResult<Bound<'py, PyList>> {
    let errors = PyList::empty(py);
    for error in stack.errors() {
        errors.append(PyTuple::new(
            py,
            [
                error.library().unwrap_or(""),
                error.function().unwrap_or(""),
                error.reason().unwrap_or(""),
            ],
        )?)?;
    }
    Ok(errors)
}

/// Build (but do not raise) an exception of the given Python type from an
/// `ErrorStack`.
pub fn error_stack_to_exception(
    py: Python<'_>,
    exception_type: &Bound<'_, pyo3::types::PyType>,
    stack: &openssl::error::ErrorStack,
) -> PyErr {
    match error_stack_to_list(py, stack) {
        Ok(errors) => match exception_type.call1((errors,)) {
            Ok(exc) => PyErr::from_value(exc),
            Err(e) => e,
        },
        Err(e) => e,
    }
}

/// Drain the OpenSSL error queue into a list of 3-tuples of strings.
pub fn error_queue<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
    error_stack_to_list(py, &openssl::error::ErrorStack::get())
}

/// Build (but do not raise) an exception of the given Python type from the
/// contents of the OpenSSL error queue.
pub fn exception_from_error_queue(
    py: Python<'_>,
    exception_type: &Bound<'_, pyo3::types::PyType>,
) -> PyErr {
    error_stack_to_exception(py, exception_type, &openssl::error::ErrorStack::get())
}

#[macro_export]
macro_rules! openssl_error {
    ($py:expr, $exc:ty) => {
        $crate::util::exception_from_error_queue(
            $py,
            &<$exc as ::pyo3::PyTypeInfo>::type_object($py),
        )
    };
}

/// `openssl_assert`-alike: clears the error queue into an exception.
#[macro_export]
macro_rules! openssl_assert {
    ($py:expr, $exc:ty, $cond:expr) => {
        if !($cond) {
            return Err($crate::openssl_error!($py, $exc));
        }
    };
}

pub fn warn(py: Python<'_>, message: &str, category: &str, stacklevel: i32) -> PyResult<()> {
    let warnings = py.import("warnings")?;
    let builtins = py.import("builtins")?;
    let category = builtins.getattr(category)?;
    let kwargs = pyo3::types::PyDict::new(py);
    kwargs.set_item("stacklevel", stacklevel)?;
    warnings.call_method(
        "warn",
        (message, category),
        Some(&kwargs),
    )?;
    Ok(())
}

pub fn warn_text_deprecated(py: Python<'_>, label: &str) -> PyResult<()> {
    warn(
        py,
        &format!("str for {} is no longer accepted, use bytes", label),
        "DeprecationWarning",
        4,
    )
}

/// Port of `_text_to_bytes_and_warn`: accept bytes-like objects unchanged,
/// converting str (with a deprecation warning) to UTF-8 bytes.
pub fn text_to_bytes_and_warn(
    py: Python<'_>,
    label: &str,
    obj: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    if let Ok(s) = obj.cast::<pyo3::types::PyString>() {
        warn_text_deprecated(py, label)?;
        return Ok(PyBytes::new(py, s.to_cow()?.as_bytes()).into_any().unbind());
    }
    Ok(obj.clone().unbind())
}

/// Extract a contiguous buffer (bytes, bytearray, memoryview) as a Vec.
pub fn buffer_to_vec(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    let buf = pyo3::buffer::PyBuffer::<u8>::get(obj)?;
    buf.to_vec(obj.py())
}

/// Port of `_path_bytes`: os.fspath() then fsencode if str.
pub fn path_bytes(py: Python<'_>, s: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let os = py.import("os")?;
    let b = os.call_method1("fspath", (s,))?;
    if b.cast::<pyo3::types::PyString>().is_ok() {
        let encoded = os.call_method1("fsencode", (&b,))?;
        Ok(encoded.extract::<Vec<u8>>()?)
    } else {
        Ok(b.extract::<Vec<u8>>()?)
    }
}

/// NUL-terminate a byte path for C consumption.
pub fn cstring(py: Python<'_>, bytes: &[u8]) -> PyResult<std::ffi::CString> {
    std::ffi::CString::new(bytes).map_err(|_| {
        let _ = py;
        pyo3::exceptions::PyValueError::new_err("embedded null byte")
    })
}

/// Allocate a new memory BIO, optionally populated with data. The returned
/// guard frees the BIO (and keeps the backing data alive) on drop.
pub struct MemBio {
    bio: *mut ffi::BIO,
    _data: Option<Vec<u8>>,
}

unsafe impl Send for MemBio {}

impl MemBio {
    pub fn new(py: Python<'_>) -> PyResult<MemBio> {
        unsafe {
            let bio = ffi::BIO_new(ffi::BIO_s_mem());
            if bio.is_null() {
                return Err(pyo3::exceptions::PyMemoryError::new_err(
                    "BIO_new failed",
                ));
            }
            let _ = py;
            Ok(MemBio { bio, _data: None })
        }
    }

    pub fn from_data(py: Python<'_>, data: &[u8]) -> PyResult<MemBio> {
        let owned = data.to_vec();
        unsafe {
            let bio = ffi::BIO_new_mem_buf(
                owned.as_ptr() as *const libc::c_void,
                owned.len() as libc::c_int,
            );
            if bio.is_null() {
                return Err(pyo3::exceptions::PyMemoryError::new_err(
                    "BIO_new_mem_buf failed",
                ));
            }
            let _ = py;
            Ok(MemBio {
                bio,
                _data: Some(owned),
            })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.bio
    }

    /// Copy the current contents of the BIO out into a Vec.
    pub fn contents(&self) -> Vec<u8> {
        unsafe {
            let mut ptr: *mut libc::c_char = std::ptr::null_mut();
            let len = ffi::BIO_get_mem_data(self.bio, &mut ptr);
            if ptr.is_null() || len <= 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(ptr as *const u8, len as usize).to_vec()
            }
        }
    }
}

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe {
            crate::ffi_ext::BIO_free(self.bio);
        }
    }
}

/// Port of `_get_asn1_time`.
pub unsafe fn get_asn1_time(
    py: Python<'_>,
    timestamp: *const ffi::ASN1_TIME,
) -> PyResult<Option<Py<PyBytes>>> {
    let string_timestamp = timestamp as *const ffi::ASN1_STRING;
    if ffi::ASN1_STRING_length(string_timestamp) == 0 {
        return Ok(None);
    }
    const V_ASN1_GENERALIZEDTIME: libc::c_int = 24;
    if ffi::ASN1_STRING_type(string_timestamp) == V_ASN1_GENERALIZEDTIME {
        let data = ffi::ASN1_STRING_get0_data(string_timestamp);
        let s = std::ffi::CStr::from_ptr(data as *const libc::c_char);
        Ok(Some(PyBytes::new(py, s.to_bytes()).unbind()))
    } else {
        let mut generalized: *mut ffi::ASN1_GENERALIZEDTIME = std::ptr::null_mut();
        crate::ffi_ext::ASN1_TIME_to_generalizedtime(timestamp, &mut generalized);
        if generalized.is_null() {
            return Err(openssl_error!(py, crate::crypto::Error));
        }
        let data = ffi::ASN1_STRING_get0_data(generalized as *const ffi::ASN1_STRING);
        let s = std::ffi::CStr::from_ptr(data as *const libc::c_char);
        let result = PyBytes::new(py, s.to_bytes()).unbind();
        ffi::ASN1_STRING_free(generalized as *mut ffi::ASN1_STRING);
        Ok(Some(result))
    }
}

/// Port of `_set_asn1_time`.
pub unsafe fn set_asn1_time(
    py: Python<'_>,
    boundary: *mut ffi::ASN1_TIME,
    when: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let when = when
        .cast::<PyBytes>()
        .map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err("when must be a byte string")
        })?
        .as_bytes();
    openssl_assert!(py, crate::crypto::Error, !boundary.is_null());
    let when_c = cstring(py, when)?;
    let result = ffi_ext::ASN1_TIME_set_string(boundary, when_c.as_ptr());
    if result == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Invalid string"));
    }
    Ok(())
}

/// errno of the most recent C call.
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Python-visible: raise an exception of *exception_type* from the OpenSSL
/// error queue (port of `OpenSSL._util.exception_from_error_queue`).
#[pyfunction(name = "exception_from_error_queue")]
fn py_exception_from_error_queue(
    py: Python<'_>,
    exception_type: &Bound<'_, pyo3::types::PyType>,
) -> PyResult<()> {
    Err(exception_from_error_queue(py, exception_type))
}

/// Python-visible ERR_put_error, for tests which need to inject errors into
/// the OpenSSL error queue.
#[pyfunction(name = "ERR_put_error")]
fn py_err_put_error(
    py: Python<'_>,
    lib: i32,
    func: i32,
    reason: i32,
    file: &[u8],
    line: i32,
) -> PyResult<()> {
    let file = crate::util::cstring(py, file)?;
    unsafe {
        crate::ffi_ext::ERR_put_error(lib, func, reason, file.as_ptr(), line);
    }
    Ok(())
}

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "_util")?;
    m.add_function(pyo3::wrap_pyfunction!(py_exception_from_error_queue, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(py_err_put_error, &m)?)?;
    m.add("ERR_LIB_EVP", 6)?;
    Ok(m)
}
