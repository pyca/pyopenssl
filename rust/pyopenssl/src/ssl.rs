//! Implementation of the `OpenSSL.SSL` module.

use std::sync::{Arc, Mutex, OnceLock};

use libc::{c_char, c_int, c_long, c_uchar, c_void};
use openssl_sys as ffi;
use pyo3::exceptions::{PyNotImplementedError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple};

use crate::crypto::{self, PassphraseHelper, PKey, X509, X509Name, X509Store};
use crate::ffi_ext::{self, CPtr};
use crate::util::{self, cstring};
use crate::{openssl_assert, openssl_error};

pyo3::create_exception!(
    OpenSSL.SSL,
    Error,
    pyo3::exceptions::PyException,
    "An error occurred in an `OpenSSL.SSL` API."
);
pyo3::create_exception!(OpenSSL.SSL, WantReadError, Error);
pyo3::create_exception!(OpenSSL.SSL, WantWriteError, Error);
pyo3::create_exception!(OpenSSL.SSL, WantX509LookupError, Error);
pyo3::create_exception!(OpenSSL.SSL, ZeroReturnError, Error);
pyo3::create_exception!(OpenSSL.SSL, SysCallError, Error);

// Method constants
pub const SSLV23_METHOD: c_int = 3;
pub const TLSV1_METHOD: c_int = 4;
pub const TLSV1_1_METHOD: c_int = 5;
pub const TLSV1_2_METHOD: c_int = 6;
pub const TLS_METHOD: c_int = 7;
pub const TLS_SERVER_METHOD: c_int = 8;
pub const TLS_CLIENT_METHOD: c_int = 9;
pub const DTLS_METHOD: c_int = 10;
pub const DTLS_SERVER_METHOD: c_int = 11;
pub const DTLS_CLIENT_METHOD: c_int = 12;

// ---------------------------------------------------------------------------
// ex_data indices
// ---------------------------------------------------------------------------

fn ctx_state_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_CTX_get_ex_new_index(
            0,
            std::ptr::null_mut(),
            None,
            None,
            None,
        )
    })
}

fn conn_obj_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), None, None, None)
    })
}

fn conn_state_idx() -> c_int {
    static IDX: OnceLock<c_int> = OnceLock::new();
    *IDX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), None, None, None)
    })
}

// ---------------------------------------------------------------------------
// Callback state shared with the C trampolines
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CtxState {
    verify_cb: Option<Py<PyAny>>,
    info_cb: Option<Py<PyAny>>,
    keylog_cb: Option<Py<PyAny>>,
    servername_cb: Option<Py<PyAny>>,
    alpn_select_cb: Option<Py<PyAny>>,
    ocsp_cb: Option<Py<PyAny>>,
    ocsp_data: Option<Py<PyAny>>,
    ocsp_is_server: bool,
    cookie_generate_cb: Option<Py<PyAny>>,
    cookie_verify_cb: Option<Py<PyAny>>,
    problems: Vec<PyErr>,
}

#[derive(Default)]
pub struct ConnState {
    verify_cb: Option<Py<PyAny>>,
    info_cb: Option<Py<PyAny>>,
    alpn_buf: Option<Vec<u8>>,
    problems: Vec<PyErr>,
}

unsafe fn get_ctx_state<'a>(ssl: *const ffi::SSL) -> Option<&'a Mutex<CtxState>> {
    let ctx = ffi::SSL_get_SSL_CTX(ssl);
    if ctx.is_null() {
        return None;
    }
    let ptr = ffi::SSL_CTX_get_ex_data(ctx, ctx_state_idx()) as *const Mutex<CtxState>;
    ptr.as_ref()
}

unsafe fn get_conn_state<'a>(ssl: *const ffi::SSL) -> Option<&'a Mutex<ConnState>> {
    let ptr = ffi::SSL_get_ex_data(ssl, conn_state_idx()) as *const Mutex<ConnState>;
    ptr.as_ref()
}

unsafe fn get_conn_obj<'py>(
    py: Python<'py>,
    ssl: *const ffi::SSL,
) -> Option<Bound<'py, PyAny>> {
    let ptr = ffi::SSL_get_ex_data(ssl, conn_obj_idx()) as *mut pyo3::ffi::PyObject;
    if ptr.is_null() {
        None
    } else {
        Some(Bound::from_borrowed_ptr(py, ptr))
    }
}

// ---------------------------------------------------------------------------
// C trampolines
// ---------------------------------------------------------------------------

unsafe fn run_verify_callback(
    ok: c_int,
    store_ctx: *mut ffi::X509_STORE_CTX,
    from_conn: bool,
) -> c_int {
    Python::attach(|py| {
        let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(store_ctx, idx) as *mut ffi::SSL;
        if ssl.is_null() {
            return 0;
        }
        let cb = if from_conn {
            match get_conn_state(ssl) {
                Some(s) => s.lock().unwrap().verify_cb.as_ref().map(|c| c.clone_ref(py)),
                None => None,
            }
        } else {
            match get_ctx_state(ssl) {
                Some(s) => s.lock().unwrap().verify_cb.as_ref().map(|c| c.clone_ref(py)),
                None => None,
            }
        };
        let cb = match cb {
            Some(cb) => cb,
            None => return ok,
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return 0,
        };

        let result: PyResult<bool> = (|| {
            let x509 = ffi::X509_STORE_CTX_get_current_cert(store_ctx);
            ffi::X509_up_ref(x509);
            let cert = Py::new(py, X509::from_raw(x509))?;
            let error_number = ffi::X509_STORE_CTX_get_error(store_ctx);
            let error_depth = ffi::X509_STORE_CTX_get_error_depth(store_ctx);
            let r = cb.bind(py).call1((
                conn,
                cert,
                error_number,
                error_depth,
                ok,
            ))?;
            r.is_truthy()
        })();

        match result {
            Ok(true) => {
                ffi::X509_STORE_CTX_set_error(store_ctx, ffi::X509_V_OK);
                1
            }
            Ok(false) => 0,
            Err(e) => {
                let state_problems = if from_conn {
                    get_conn_state(ssl).map(|s| {
                        s.lock().unwrap().problems.push(e);
                    })
                } else {
                    get_ctx_state(ssl).map(|s| {
                        s.lock().unwrap().problems.push(e);
                    })
                };
                let _ = state_problems;
                0
            }
        }
    })
}

extern "C" fn verify_cb_ctx(ok: c_int, store_ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    unsafe { run_verify_callback(ok, store_ctx, false) }
}

extern "C" fn verify_cb_conn(ok: c_int, store_ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    unsafe { run_verify_callback(ok, store_ctx, true) }
}

unsafe fn run_info_callback(ssl: *const ffi::SSL, where_: c_int, ret: c_int, from_conn: bool) {
    Python::attach(|py| {
        let cb = if from_conn {
            get_conn_state(ssl)
                .and_then(|s| s.lock().unwrap().info_cb.as_ref().map(|c| c.clone_ref(py)))
        } else {
            get_ctx_state(ssl)
                .and_then(|s| s.lock().unwrap().info_cb.as_ref().map(|c| c.clone_ref(py)))
        };
        let (cb, conn) = match (cb, get_conn_obj(py, ssl)) {
            (Some(cb), Some(conn)) => (cb, conn),
            _ => return,
        };
        if let Err(e) = cb.bind(py).call1((conn, where_, ret)) {
            e.write_unraisable(py, None);
        }
    })
}

unsafe extern "C" fn info_cb_ctx(ssl: *const ffi::SSL, where_: c_int, ret: c_int) {
    run_info_callback(ssl, where_, ret, false)
}

unsafe extern "C" fn info_cb_conn(ssl: *const ffi::SSL, where_: c_int, ret: c_int) {
    run_info_callback(ssl, where_, ret, true)
}

unsafe extern "C" fn keylog_cb(ssl: *const ffi::SSL, line: *const c_char) {
    Python::attach(|py| {
        let cb = match get_ctx_state(ssl)
            .and_then(|s| s.lock().unwrap().keylog_cb.as_ref().map(|c| c.clone_ref(py)))
        {
            Some(cb) => cb,
            None => return,
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return,
        };
        let line = std::ffi::CStr::from_ptr(line).to_bytes();
        if let Err(e) = cb.bind(py).call1((conn, PyBytes::new(py, line))) {
            e.write_unraisable(py, None);
        }
    })
}

unsafe extern "C" fn servername_cb(
    ssl: *mut ffi::SSL,
    _alert: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    Python::attach(|py| {
        let cb = match get_ctx_state(ssl)
            .and_then(|s| s.lock().unwrap().servername_cb.as_ref().map(|c| c.clone_ref(py)))
        {
            Some(cb) => cb,
            None => return 0,
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return 0,
        };
        match cb.bind(py).call1((conn,)) {
            Ok(_) => 0,
            Err(e) => {
                // The Python implementation routes this through
                // sys.excepthook.
                let hook_result = py.import("sys").and_then(|sys| {
                    let hook = sys.getattr("excepthook")?;
                    let tb = e
                        .traceback(py)
                        .map(|t| t.into_any().unbind())
                        .unwrap_or_else(|| py.None());
                    hook.call1((e.get_type(py), e.value(py), tb))?;
                    Ok(())
                });
                if let Err(hook_err) = hook_result {
                    hook_err.write_unraisable(py, None);
                }
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    })
}

unsafe extern "C" fn alpn_select_cb(
    ssl: *mut ffi::SSL,
    out: *mut *const c_uchar,
    outlen: *mut c_uchar,
    in_: *const c_uchar,
    inlen: libc::c_uint,
    _arg: *mut c_void,
) -> c_int {
    Python::attach(|py| {
        let result: PyResult<c_int> = (|| {
            let cb = match get_ctx_state(ssl).and_then(|s| {
                s.lock().unwrap().alpn_select_cb.as_ref().map(|c| c.clone_ref(py))
            }) {
                Some(cb) => cb,
                None => return Ok(ffi::SSL_TLSEXT_ERR_NOACK),
            };
            let conn = match get_conn_obj(py, ssl) {
                Some(c) => c,
                None => return Ok(ffi::SSL_TLSEXT_ERR_ALERT_FATAL),
            };
            // The string passed to us is made up of multiple
            // length-prefixed bytestrings. We need to split that into a
            // list.
            let instr = std::slice::from_raw_parts(in_, inlen as usize);
            let protolist = PyList::empty(py);
            let mut i = 0usize;
            while i < instr.len() {
                let encoded_len = instr[i] as usize;
                let end = std::cmp::min(i + 1 + encoded_len, instr.len());
                protolist.append(PyBytes::new(py, &instr[i + 1..end]))?;
                i = end;
            }

            let outbytes = cb.bind(py).call1((conn, protolist))?;
            let no_overlap = no_overlapping_protocols(py)?;
            let mut any_accepted = true;
            let outvec: Vec<u8> = if outbytes.is(&no_overlap) {
                any_accepted = false;
                Vec::new()
            } else if let Ok(b) = outbytes.downcast::<PyBytes>() {
                b.as_bytes().to_vec()
            } else {
                return Err(PyTypeError::new_err(
                    "ALPN callback must return a bytestring or the \
                     special NO_OVERLAPPING_PROTOCOLS sentinel value.",
                ));
            };

            // Save the callback result on the connection object to make
            // sure that it doesn't get freed before OpenSSL uses it. Then,
            // return it in the appropriate output parameters.
            let state = match get_conn_state(ssl) {
                Some(s) => s,
                None => return Ok(ffi::SSL_TLSEXT_ERR_ALERT_FATAL),
            };
            let mut state = state.lock().unwrap();
            state.alpn_buf = Some(outvec);
            let buf = state.alpn_buf.as_ref().unwrap();
            *outlen = buf.len() as c_uchar;
            *out = buf.as_ptr();
            if !any_accepted {
                return Ok(ffi::SSL_TLSEXT_ERR_NOACK);
            }
            Ok(ffi::SSL_TLSEXT_ERR_OK)
        })();
        match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(s) = get_ctx_state(ssl) {
                    s.lock().unwrap().problems.push(e);
                }
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    })
}

unsafe extern "C" fn ocsp_cb(ssl: *mut ffi::SSL, _arg: *mut c_void) -> c_int {
    Python::attach(|py| {
        let (cb, data, is_server) = match get_ctx_state(ssl).map(|s| {
            let s = s.lock().unwrap();
            (
                s.ocsp_cb.as_ref().map(|c| c.clone_ref(py)),
                s.ocsp_data.as_ref().map(|c| c.clone_ref(py)),
                s.ocsp_is_server,
            )
        }) {
            Some((Some(cb), data, is_server)) => (cb, data, is_server),
            _ => return if is_server_guess(ssl) { 3 } else { -1 },
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return if is_server { 2 } else { -1 },
        };
        let data = match data {
            Some(d) => d.into_bound(py),
            None => py.None().into_bound(py),
        };

        if is_server {
            let result: PyResult<c_int> = (|| {
                let ocsp_data = cb.bind(py).call1((conn, data))?;
                let ocsp_data = ocsp_data.downcast::<PyBytes>().map_err(|_| {
                    PyTypeError::new_err("OCSP callback must return a bytestring.")
                })?;
                let bytes = ocsp_data.as_bytes();
                if bytes.is_empty() {
                    return Ok(3); // SSL_TLSEXT_ERR_NOACK
                }
                // OpenSSL takes ownership of this data and expects it to
                // have been allocated by OPENSSL_malloc.
                let data_ptr = ffi::CRYPTO_malloc(
                    bytes.len(),
                    b"pyopenssl\0".as_ptr() as *const c_char,
                    0,
                ) as *mut u8;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, bytes.len());
                ffi::SSL_set_tlsext_status_ocsp_resp(
                    ssl,
                    data_ptr as *mut c_uchar,
                    bytes.len() as c_long,
                );
                Ok(0)
            })();
            match result {
                Ok(r) => r,
                Err(e) => {
                    if let Some(s) = get_ctx_state(ssl) {
                        s.lock().unwrap().problems.push(e);
                    }
                    2 // SSL_TLSEXT_ERR_ALERT_FATAL
                }
            }
        } else {
            let result: PyResult<c_int> = (|| {
                let mut ocsp_ptr: *mut c_uchar = std::ptr::null_mut();
                let ocsp_len = ffi::SSL_get_tlsext_status_ocsp_resp(ssl, &mut ocsp_ptr);
                let ocsp_data = if ocsp_len < 0 {
                    PyBytes::new(py, b"")
                } else {
                    PyBytes::new(
                        py,
                        std::slice::from_raw_parts(ocsp_ptr, ocsp_len as usize),
                    )
                };
                let valid = cb.bind(py).call1((conn, ocsp_data, data))?;
                Ok(valid.is_truthy()? as c_int)
            })();
            match result {
                Ok(r) => r,
                Err(e) => {
                    if let Some(s) = get_ctx_state(ssl) {
                        s.lock().unwrap().problems.push(e);
                    }
                    -1
                }
            }
        }
    })
}

unsafe fn is_server_guess(ssl: *mut ffi::SSL) -> bool {
    ffi::SSL_is_server(ssl) == 1
}

unsafe extern "C" fn cookie_generate_cb(
    ssl: *mut ffi::SSL,
    out: *mut c_uchar,
    outlen: *mut libc::c_uint,
) -> c_int {
    Python::attach(|py| {
        let cb = match get_ctx_state(ssl).and_then(|s| {
            s.lock().unwrap().cookie_generate_cb.as_ref().map(|c| c.clone_ref(py))
        }) {
            Some(cb) => cb,
            None => return 0,
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return 0,
        };
        let result: PyResult<c_int> = (|| {
            let cookie = cb.bind(py).call1((conn,))?;
            let cookie = cookie.extract::<Vec<u8>>()?;
            if cookie.len() > ffi_ext::DTLS1_COOKIE_LENGTH {
                return Err(PyValueError::new_err(format!(
                    "Cookie too long (got {} bytes, max {})",
                    cookie.len(),
                    ffi_ext::DTLS1_COOKIE_LENGTH
                )));
            }
            std::ptr::copy_nonoverlapping(cookie.as_ptr(), out, cookie.len());
            *outlen = cookie.len() as libc::c_uint;
            Ok(1)
        })();
        match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(s) = get_ctx_state(ssl) {
                    s.lock().unwrap().problems.push(e);
                }
                // "a zero return value can be used to abort the handshake"
                0
            }
        }
    })
}

unsafe extern "C" fn cookie_verify_cb(
    ssl: *mut ffi::SSL,
    cookie: *const c_uchar,
    cookie_len: libc::c_uint,
) -> c_int {
    Python::attach(|py| {
        let cb = match get_ctx_state(ssl).and_then(|s| {
            s.lock().unwrap().cookie_verify_cb.as_ref().map(|c| c.clone_ref(py))
        }) {
            Some(cb) => cb,
            None => return 0,
        };
        let conn = match get_conn_obj(py, ssl) {
            Some(c) => c,
            None => return 0,
        };
        let cookie = std::slice::from_raw_parts(cookie, cookie_len as usize);
        let result: PyResult<c_int> = (|| {
            let r = cb.bind(py).call1((conn, PyBytes::new(py, cookie)))?;
            Ok(r.is_truthy()? as c_int)
        })();
        match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(s) = get_ctx_state(ssl) {
                    s.lock().unwrap().problems.push(e);
                }
                0
            }
        }
    })
}

// ---------------------------------------------------------------------------
// NO_OVERLAPPING_PROTOCOLS sentinel
// ---------------------------------------------------------------------------

#[pyclass(module = "OpenSSL.SSL", name = "_NoOverlappingProtocols")]
pub struct NoOverlappingProtocols;

#[pymethods]
impl NoOverlappingProtocols {
    #[new]
    fn new() -> NoOverlappingProtocols {
        NoOverlappingProtocols
    }
}

fn no_overlapping_protocols(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    static SENTINEL: pyo3::sync::PyOnceLock<Py<PyAny>> = pyo3::sync::PyOnceLock::new();
    Ok(SENTINEL
        .get_or_try_init(py, || -> PyResult<Py<PyAny>> {
            Ok(Py::new(py, NoOverlappingProtocols)?.into_any())
        })?
        .bind(py)
        .clone())
}

// ---------------------------------------------------------------------------
// X509VerificationCodes
// ---------------------------------------------------------------------------

/// Success and error codes for X509 verification, as returned by the
/// underlying ``X509_STORE_CTX_get_error()`` function and passed by
/// pyOpenSSL to verification callback functions.
#[pyclass(module = "OpenSSL.SSL")]
pub struct X509VerificationCodes;

#[pymethods]
impl X509VerificationCodes {
    #[classattr]
    const OK: c_int = 0;
    #[classattr]
    const ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
    #[classattr]
    const ERR_UNABLE_TO_GET_CRL: c_int = 3;
    #[classattr]
    const ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
    #[classattr]
    const ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
    #[classattr]
    const ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
    #[classattr]
    const ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
    #[classattr]
    const ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
    #[classattr]
    const ERR_CERT_NOT_YET_VALID: c_int = 9;
    #[classattr]
    const ERR_CERT_HAS_EXPIRED: c_int = 10;
    #[classattr]
    const ERR_CRL_NOT_YET_VALID: c_int = 11;
    #[classattr]
    const ERR_CRL_HAS_EXPIRED: c_int = 12;
    #[classattr]
    const ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
    #[classattr]
    const ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
    #[classattr]
    const ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
    #[classattr]
    const ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
    #[classattr]
    const ERR_OUT_OF_MEM: c_int = 17;
    #[classattr]
    const ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
    #[classattr]
    const ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
    #[classattr]
    const ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
    #[classattr]
    const ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
    #[classattr]
    const ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
    #[classattr]
    const ERR_CERT_REVOKED: c_int = 23;
    #[classattr]
    const ERR_INVALID_CA: c_int = 24;
    #[classattr]
    const ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
    #[classattr]
    const ERR_INVALID_PURPOSE: c_int = 26;
    #[classattr]
    const ERR_CERT_UNTRUSTED: c_int = 27;
    #[classattr]
    const ERR_CERT_REJECTED: c_int = 28;
    #[classattr]
    const ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
    #[classattr]
    const ERR_AKID_SKID_MISMATCH: c_int = 30;
    #[classattr]
    const ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
    #[classattr]
    const ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
    #[classattr]
    const ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
    #[classattr]
    const ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
    #[classattr]
    const ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
    #[classattr]
    const ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
    #[classattr]
    const ERR_INVALID_NON_CA: c_int = 37;
    #[classattr]
    const ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
    #[classattr]
    const ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
    #[classattr]
    const ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
    #[classattr]
    const ERR_INVALID_EXTENSION: c_int = 41;
    #[classattr]
    const ERR_INVALID_POLICY_EXTENSION: c_int = 42;
    #[classattr]
    const ERR_NO_EXPLICIT_POLICY: c_int = 43;
    #[classattr]
    const ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
    #[classattr]
    const ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
    #[classattr]
    const ERR_UNNESTED_RESOURCE: c_int = 46;
    #[classattr]
    const ERR_PERMITTED_VIOLATION: c_int = 47;
    #[classattr]
    const ERR_EXCLUDED_VIOLATION: c_int = 48;
    #[classattr]
    const ERR_SUBTREE_MINMAX: c_int = 49;
    #[classattr]
    const ERR_APPLICATION_VERIFICATION: c_int = 50;
    #[classattr]
    const ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
    #[classattr]
    const ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
    #[classattr]
    const ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
    #[classattr]
    const ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
    #[classattr]
    const ERR_HOSTNAME_MISMATCH: c_int = 62;
    #[classattr]
    const ERR_EMAIL_MISMATCH: c_int = 63;
    #[classattr]
    const ERR_IP_ADDRESS_MISMATCH: c_int = 64;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A class representing an SSL session. A session defines certain
/// connection parameters which may be re-used to speed up the setup of
/// subsequent connections.
#[pyclass(module = "OpenSSL.SSL", subclass)]
pub struct Session {
    session: CPtr<ffi::SSL_SESSION>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.session.is_null() {
            unsafe { ffi::SSL_SESSION_free(self.session.get()) }
        }
    }
}

#[pymethods]
impl Session {
    #[new]
    fn new() -> Session {
        Session {
            session: CPtr(std::ptr::null_mut()),
        }
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

// Taken from https://golang.org/src/crypto/x509/root_linux.go
const CERTIFICATE_FILE_LOCATIONS: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",             // OpenSUSE
    "/etc/pki/tls/cacert.pem",            // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
];

const CERTIFICATE_PATH_LOCATIONS: [&str; 1] = [
    "/etc/ssl/certs", // SLES10/SLES11
];

const CRYPTOGRAPHY_MANYLINUX_CA_DIR: &[u8] = b"/opt/pyca/cryptography/openssl/certs";
const CRYPTOGRAPHY_MANYLINUX_CA_FILE: &[u8] =
    b"/opt/pyca/cryptography/openssl/cert.pem";

/// `OpenSSL.SSL.Context` instances define the parameters for setting up
/// new SSL connections.
#[pyclass(module = "OpenSSL.SSL", subclass, dict)]
pub struct Context {
    ctx: CPtr<ffi::SSL_CTX>,
    pub used: bool,
    state: Arc<Mutex<CtxState>>,
    passphrase_helper: Option<Box<PassphraseHelper>>,
    app_data: Py<PyAny>,
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { ffi::SSL_CTX_free(self.ctx.get()) }
        }
    }
}

impl Context {
    fn require_not_used(&self) -> PyResult<()> {
        if self.used {
            return Err(PyValueError::new_err(
                "Context has already been used to create a Connection, it \
                 cannot be mutated again",
            ));
        }
        Ok(())
    }

    pub fn ctx_ptr(&self) -> *mut ffi::SSL_CTX {
        self.ctx.get()
    }

    fn raise_passphrase_exception(&mut self, py: Python<'_>) -> PyErr {
        if let Some(helper) = self.passphrase_helper.as_mut() {
            if let Err(e) = helper.raise_if_problem(py) {
                return e;
            }
        }
        openssl_error!(py, Error)
    }

    fn load_verify_locations_impl(
        &self,
        py: Python<'_>,
        cafile: Option<&Bound<'_, PyAny>>,
        capath: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let cafile = match cafile {
            Some(f) if !f.is_none() => Some(cstring(py, &util::path_bytes(py, f)?)?),
            _ => None,
        };
        let capath = match capath {
            Some(p) if !p.is_none() => Some(cstring(py, &util::path_bytes(py, p)?)?),
            _ => None,
        };
        let result = unsafe {
            ffi::SSL_CTX_load_verify_locations(
                self.ctx.get(),
                cafile.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                capath.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            )
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }
}

/// Convert an X509-or-cryptography-Certificate argument into a Py<X509>,
/// warning if a pyOpenSSL X509 was passed.
fn as_x509(py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<Py<X509>> {
    if let Ok(c) = cert.downcast::<X509>() {
        util::warn(
            py,
            "Passing pyOpenSSL X509 objects is deprecated. You should use a \
             cryptography.x509.Certificate instead.",
            "DeprecationWarning",
            3,
        )?;
        Ok(c.clone().unbind())
    } else {
        let x509_type = py.get_type::<X509>();
        let converted = x509_type.call_method1("from_cryptography", (cert,))?;
        Ok(converted.downcast_into::<X509>()?.unbind())
    }
}

/// Convert a PKey-or-cryptography-key argument into a Py<PKey>, warning if
/// a pyOpenSSL PKey was passed.
fn as_pkey(py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<Py<PKey>> {
    if let Ok(k) = pkey.downcast::<PKey>() {
        util::warn(
            py,
            "Passing pyOpenSSL PKey objects is deprecated. You should use a \
             cryptography private key instead.",
            "DeprecationWarning",
            3,
        )?;
        Ok(k.clone().unbind())
    } else {
        let pkey_type = py.get_type::<PKey>();
        let converted = pkey_type.call_method1("from_cryptography_key", (pkey,))?;
        Ok(converted.downcast_into::<PKey>()?.unbind())
    }
}

#[pymethods]
impl Context {
    #[new]
    fn new(py: Python<'_>, method: &Bound<'_, PyAny>) -> PyResult<Context> {
        if !method.is_instance_of::<pyo3::types::PyInt>() {
            return Err(PyTypeError::new_err("method must be an integer"));
        }
        let method: c_int = method.extract()?;
        let (method_obj, version): (*const ffi::SSL_METHOD, Option<c_int>) = unsafe {
            match method {
                SSLV23_METHOD => (ffi::TLS_method(), None),
                TLSV1_METHOD => (ffi::TLS_method(), Some(ffi::TLS1_VERSION)),
                TLSV1_1_METHOD => (ffi::TLS_method(), Some(ffi::TLS1_1_VERSION)),
                TLSV1_2_METHOD => (ffi::TLS_method(), Some(ffi::TLS1_2_VERSION)),
                TLS_METHOD => (ffi::TLS_method(), None),
                TLS_SERVER_METHOD => (ffi::TLS_server_method(), None),
                TLS_CLIENT_METHOD => (ffi::TLS_client_method(), None),
                DTLS_METHOD => (ffi::DTLS_method(), None),
                DTLS_SERVER_METHOD => (ffi::DTLS_server_method(), None),
                DTLS_CLIENT_METHOD => (ffi::DTLS_client_method(), None),
                _ => return Err(PyValueError::new_err("No such protocol")),
            }
        };
        openssl_assert!(py, Error, !method_obj.is_null());
        let ctx = unsafe { ffi::SSL_CTX_new(method_obj) };
        openssl_assert!(py, Error, !ctx.is_null());

        let state = Arc::new(Mutex::new(CtxState::default()));
        unsafe {
            ffi::SSL_CTX_set_ex_data(
                ctx,
                ctx_state_idx(),
                Arc::as_ptr(&state) as *mut c_void,
            );
            ffi_ext::SSL_CTX_set_mode_long(
                ctx,
                (ffi_ext::SSL_MODE_ENABLE_PARTIAL_WRITE
                    | ffi_ext::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)
                    as c_long,
            );
            if let Some(version) = version {
                openssl_assert!(
                    py,
                    Error,
                    ffi::SSL_CTX_set_min_proto_version(ctx, version) == 1
                );
                openssl_assert!(
                    py,
                    Error,
                    ffi::SSL_CTX_set_max_proto_version(ctx, version) == 1
                );
            }
        }
        Ok(Context {
            ctx: CPtr(ctx),
            used: false,
            state,
            passphrase_helper: None,
            app_data: py.None(),
        })
    }

    /// Set the minimum supported protocol version.
    fn set_min_proto_version(&self, py: Python<'_>, version: c_int) -> PyResult<()> {
        self.require_not_used()?;
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_min_proto_version(self.ctx.get(), version) } == 1
        );
        Ok(())
    }

    /// Set the maximum supported protocol version.
    fn set_max_proto_version(&self, py: Python<'_>, version: c_int) -> PyResult<()> {
        self.require_not_used()?;
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_max_proto_version(self.ctx.get(), version) } == 1
        );
        Ok(())
    }

    /// Let SSL know where we can find trusted certificates for the
    /// certificate chain. Note that the certificates have to be in PEM
    /// format.
    #[pyo3(signature = (cafile, capath=None))]
    fn load_verify_locations(
        &self,
        py: Python<'_>,
        cafile: Option<&Bound<'_, PyAny>>,
        capath: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        self.load_verify_locations_impl(py, cafile, capath)
    }

    /// Set the passphrase callback. This function will be called when a
    /// private key with a passphrase is loaded.
    #[pyo3(signature = (callback, userdata=None))]
    fn set_passwd_cb(
        &mut self,
        py: Python<'_>,
        callback: &Bound<'_, PyAny>,
        userdata: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        if !callback.is_callable() {
            return Err(PyTypeError::new_err("callback must be callable"));
        }
        let helper = PassphraseHelper::new(
            py,
            crypto::FILETYPE_PEM,
            Some(callback),
            true,
            true,
            userdata.map(|u| u.clone().unbind()),
        )?;
        let mut helper = Box::new(helper);
        unsafe {
            ffi_ext::SSL_CTX_set_default_passwd_cb(
                self.ctx.get(),
                Some(crypto::raw_pem_password_cb),
            );
            ffi_ext::SSL_CTX_set_default_passwd_cb_userdata(
                self.ctx.get(),
                helper.as_mut() as *mut PassphraseHelper as *mut c_void,
            );
        }
        self.passphrase_helper = Some(helper);
        Ok(())
    }

    /// Specify that the platform provided CA certificates are to be used
    /// for verification purposes.
    fn set_default_verify_paths(slf: &Bound<'_, Self>, py: Python<'_>) -> PyResult<()> {
        slf.borrow().require_not_used()?;
        // SSL_CTX_set_default_verify_paths will attempt to load certs
        // from both a cafile and capath that are set at compile time.
        // However, it will first check environment variables and, if
        // present, load those paths instead. (Dispatched through Python
        // attribute lookup so that tests can substitute it.)
        slf.call_method0("_set_default_verify_paths_openssl")?;
        // After attempting to set default_verify_paths we need to know
        // whether to go down the fallback path.
        let env_vars_set = slf
            .call_method1("_check_env_vars_set", ("SSL_CERT_DIR", "SSL_CERT_FILE"))?
            .is_truthy()?;
        if !env_vars_set {
            let (default_dir, default_file) = unsafe {
                (
                    std::ffi::CStr::from_ptr(ffi_ext::X509_get_default_cert_dir())
                        .to_bytes()
                        .to_vec(),
                    std::ffi::CStr::from_ptr(ffi_ext::X509_get_default_cert_file())
                        .to_bytes()
                        .to_vec(),
                )
            };
            // Read the manylinux constants and fallback locations from the
            // OpenSSL.SSL module if it is importable (so that they can be
            // patched in tests), falling back to the compiled-in values.
            let (manylinux_dir, manylinux_file, files, dirs) =
                match py.import("OpenSSL.SSL") {
                    Ok(m) => (
                        m.getattr("_CRYPTOGRAPHY_MANYLINUX_CA_DIR")?
                            .extract::<Vec<u8>>()?,
                        m.getattr("_CRYPTOGRAPHY_MANYLINUX_CA_FILE")?
                            .extract::<Vec<u8>>()?,
                        m.getattr("_CERTIFICATE_FILE_LOCATIONS")?.unbind(),
                        m.getattr("_CERTIFICATE_PATH_LOCATIONS")?.unbind(),
                    ),
                    Err(_) => (
                        CRYPTOGRAPHY_MANYLINUX_CA_DIR.to_vec(),
                        CRYPTOGRAPHY_MANYLINUX_CA_FILE.to_vec(),
                        PyList::new(py, CERTIFICATE_FILE_LOCATIONS)?
                            .into_any()
                            .unbind(),
                        PyList::new(py, CERTIFICATE_PATH_LOCATIONS)?
                            .into_any()
                            .unbind(),
                    ),
                };
            if default_dir == manylinux_dir && default_file == manylinux_file {
                // This is manylinux, let's load our fallback paths
                slf.call_method1(
                    "_fallback_default_verify_paths",
                    (files, dirs),
                )?;
            }
        }
        Ok(())
    }

    /// Call ``SSL_CTX_set_default_verify_paths``; the testable C-call part
    /// of `set_default_verify_paths`.
    fn _set_default_verify_paths_openssl(&self, py: Python<'_>) -> PyResult<()> {
        let set_result =
            unsafe { ffi::SSL_CTX_set_default_verify_paths(self.ctx.get()) };
        openssl_assert!(py, Error, set_result == 1);
        Ok(())
    }

    /// Check to see if the default cert dir/file environment vars are
    /// present.
    fn _check_env_vars_set(
        &self,
        py: Python<'_>,
        dir_env_var: &str,
        file_env_var: &str,
    ) -> PyResult<bool> {
        let environ = py.import("os")?.getattr("environ")?;
        Ok(!environ.call_method1("get", (file_env_var,))?.is_none()
            || !environ.call_method1("get", (dir_env_var,))?.is_none())
    }

    /// Default verify paths are based on the compiled version of OpenSSL.
    /// However, when pyca/cryptography is compiled as a manylinux wheel
    /// that compiled location can potentially be wrong. So, like Go, we
    /// will try a predefined set of paths and attempt to load roots from
    /// there.
    fn _fallback_default_verify_paths(
        slf: &Bound<'_, Self>,
        py: Python<'_>,
        file_path: &Bound<'_, PyAny>,
        dir_path: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let os_path = py.import("os.path")?;
        for cafile in file_path.try_iter()? {
            let cafile = cafile?;
            if os_path.call_method1("isfile", (&cafile,))?.is_truthy()? {
                slf.borrow().load_verify_locations_impl(py, Some(&cafile), None)?;
                break;
            }
        }
        for capath in dir_path.try_iter()? {
            let capath = capath?;
            if os_path.call_method1("isdir", (&capath,))?.is_truthy()? {
                slf.borrow().load_verify_locations_impl(py, None, Some(&capath))?;
                break;
            }
        }
        Ok(())
    }

    /// Load a certificate chain from a file.
    fn use_certificate_chain_file(
        &self,
        py: Python<'_>,
        certfile: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certfile = cstring(py, &util::path_bytes(py, certfile)?)?;
        let result = unsafe {
            ffi::SSL_CTX_use_certificate_chain_file(self.ctx.get(), certfile.as_ptr())
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// Load a certificate from a file
    #[pyo3(signature = (certfile, filetype=crypto::FILETYPE_PEM))]
    fn use_certificate_file(
        &self,
        py: Python<'_>,
        certfile: &Bound<'_, PyAny>,
        filetype: c_int,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certfile = cstring(py, &util::path_bytes(py, certfile)?)?;
        let result = unsafe {
            ffi::SSL_CTX_use_certificate_file(
                self.ctx.get(),
                certfile.as_ptr(),
                filetype,
            )
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// Load a certificate from a X509 object
    fn use_certificate(&self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cert = as_x509(py, cert)?;
        let result = unsafe {
            ffi::SSL_CTX_use_certificate(self.ctx.get(), cert.borrow(py).x509_ptr())
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// Add certificate to chain
    fn add_extra_chain_cert(
        &self,
        py: Python<'_>,
        certobj: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certobj = as_x509(py, certobj)?;
        unsafe {
            let copy = ffi::X509_dup(certobj.borrow(py).x509_ptr());
            let result = ffi::SSL_CTX_add_extra_chain_cert(self.ctx.get(), copy);
            if result == 0 {
                ffi::X509_free(copy);
                return Err(openssl_error!(py, Error));
            }
        }
        Ok(())
    }

    /// Load a private key from a file
    #[pyo3(signature = (keyfile, filetype=crypto::FILETYPE_PEM))]
    fn use_privatekey_file(
        &mut self,
        py: Python<'_>,
        keyfile: &Bound<'_, PyAny>,
        filetype: c_int,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let keyfile = cstring(py, &util::path_bytes(py, keyfile)?)?;
        let result = unsafe {
            ffi::SSL_CTX_use_PrivateKey_file(self.ctx.get(), keyfile.as_ptr(), filetype)
        };
        if result == 0 {
            return Err(self.raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// Load a private key from a PKey object
    fn use_privatekey(&mut self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let pkey = as_pkey(py, pkey)?;
        let result = unsafe {
            ffi::SSL_CTX_use_PrivateKey(self.ctx.get(), pkey.borrow(py).pkey_ptr())
        };
        if result == 0 {
            return Err(self.raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// Check if the private key (loaded with `use_privatekey`) matches the
    /// certificate (loaded with `use_certificate`)
    fn check_privatekey(&self, py: Python<'_>) -> PyResult<()> {
        if unsafe { ffi::SSL_CTX_check_private_key(self.ctx.get()) } == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// Load the trusted certificates that will be sent to the client.
    fn load_client_ca(&self, py: Python<'_>, cafile: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cafile = util::text_to_bytes_and_warn(py, "cafile", cafile)?;
        let cafile = cafile.bind(py).extract::<Vec<u8>>()?;
        let cafile = cstring(py, &cafile)?;
        unsafe {
            let ca_list = ffi::SSL_load_client_CA_file(cafile.as_ptr());
            openssl_assert!(py, Error, !ca_list.is_null());
            ffi::SSL_CTX_set_client_CA_list(self.ctx.get(), ca_list);
        }
        Ok(())
    }

    /// Set the session id to *buf* within which a session can be reused
    /// for this Context object.
    fn set_session_id(&self, py: Python<'_>, buf: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        let buf = buf.bind(py).extract::<Vec<u8>>()?;
        openssl_assert!(
            py,
            Error,
            unsafe {
                ffi::SSL_CTX_set_session_id_context(
                    self.ctx.get(),
                    buf.as_ptr(),
                    buf.len() as libc::c_uint,
                )
            } == 1
        );
        Ok(())
    }

    /// Set the behavior of the session cache used by all connections using
    /// this Context. The previously set mode is returned.
    fn set_session_cache_mode(&self, mode: &Bound<'_, PyAny>) -> PyResult<c_long> {
        self.require_not_used()?;
        let mode: c_long = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        Ok(unsafe { ffi::SSL_CTX_set_session_cache_mode(self.ctx.get(), mode) })
    }

    /// Get the current session cache mode.
    fn get_session_cache_mode(&self) -> c_long {
        unsafe { ffi_ext::SSL_CTX_get_session_cache_mode(self.ctx.get()) }
    }

    /// Set the verification flags for this Context object to *mode* and
    /// specify that *callback* should be used for verification callbacks.
    #[pyo3(signature = (mode, callback=None))]
    fn set_verify(
        &mut self,
        py: Python<'_>,
        mode: &Bound<'_, PyAny>,
        callback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let mode: c_int = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        let _ = py;
        match callback {
            None => {
                self.state.lock().unwrap().verify_cb = None;
                unsafe { ffi::SSL_CTX_set_verify(self.ctx.get(), mode, None) };
            }
            Some(callback) => {
                if !callback.is_callable() {
                    return Err(PyTypeError::new_err("callback must be callable"));
                }
                self.state.lock().unwrap().verify_cb = Some(callback.clone().unbind());
                unsafe {
                    ffi::SSL_CTX_set_verify(self.ctx.get(), mode, Some(verify_cb_ctx))
                };
            }
        }
        Ok(())
    }

    /// Set the maximum depth for the certificate chain verification that
    /// shall be allowed for this Context object.
    fn set_verify_depth(&self, depth: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let depth: c_int = depth
            .extract()
            .map_err(|_| PyTypeError::new_err("depth must be an integer"))?;
        unsafe { ffi::SSL_CTX_set_verify_depth(self.ctx.get(), depth) };
        Ok(())
    }

    /// Retrieve the Context object's verify mode, as set by `set_verify`.
    fn get_verify_mode(&self) -> c_int {
        unsafe { ffi::SSL_CTX_get_verify_mode(self.ctx.get()) }
    }

    /// Retrieve the Context object's verify depth, as set by
    /// `set_verify_depth`.
    fn get_verify_depth(&self) -> c_int {
        unsafe { ffi_ext::SSL_CTX_get_verify_depth(self.ctx.get()) }
    }

    /// Load parameters for Ephemeral Diffie-Hellman
    fn load_tmp_dh(&self, py: Python<'_>, dhfile: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let dhfile = cstring(py, &util::path_bytes(py, dhfile)?)?;
        unsafe {
            let bio = ffi_ext::BIO_new_file(dhfile.as_ptr(), b"r\0".as_ptr() as *const c_char);
            if bio.is_null() {
                return Err(openssl_error!(py, Error));
            }
            let dh = ffi::PEM_read_bio_DHparams(
                bio,
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            );
            crate::ffi_ext::BIO_free(bio);
            openssl_assert!(py, Error, !dh.is_null());
            let res = ffi::SSL_CTX_set_tmp_dh(self.ctx.get(), dh);
            ffi::DH_free(dh);
            openssl_assert!(py, Error, res == 1);
        }
        Ok(())
    }

    /// Select a curve to use for ECDHE key exchange.
    fn set_tmp_ecdh(&self, py: Python<'_>, curve: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let nid = if let Ok(c) = curve.downcast::<crypto::EllipticCurve>() {
            util::warn(
                py,
                "Passing pyOpenSSL elliptic curves to set_tmp_ecdh is \
                 deprecated. You should use cryptography's elliptic curve \
                 types instead.",
                "DeprecationWarning",
                3,
            )?;
            c.borrow().nid
        } else {
            let mut name = curve.getattr("name")?.extract::<String>()?;
            if name == "secp192r1" {
                name = "prime192v1".to_string();
            } else if name == "secp256r1" {
                name = "prime256v1".to_string();
            }
            let name_c = cstring(py, name.as_bytes())?;
            let nid = unsafe { ffi_ext::OBJ_txt2nid(name_c.as_ptr()) };
            if nid == 0 {
                return Err(openssl_error!(py, Error));
            }
            nid
        };
        unsafe {
            let ec = ffi::EC_KEY_new_by_curve_name(nid);
            openssl_assert!(py, Error, !ec.is_null());
            ffi::SSL_CTX_set_tmp_ecdh(self.ctx.get(), ec);
            ffi::EC_KEY_free(ec);
        }
        Ok(())
    }

    /// Set the list of ciphers to be used in this context.
    fn set_cipher_list(&self, py: Python<'_>, cipher_list: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cipher_list = util::text_to_bytes_and_warn(py, "cipher_list", cipher_list)?;
        let cipher_list = cipher_list
            .bind(py)
            .downcast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("cipher_list must be a byte string."))?;
        let cipher_c = cstring(py, cipher_list.as_bytes())?;
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_cipher_list(self.ctx.get(), cipher_c.as_ptr()) }
                == 1
        );
        Ok(())
    }

    /// Set the list of TLS 1.3 ciphers to be used in this context.
    fn set_tls13_ciphersuites(
        &self,
        py: Python<'_>,
        ciphersuites: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let ciphersuites = ciphersuites
            .downcast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("ciphersuites must be a byte string."))?;
        let cipher_c = cstring(py, ciphersuites.as_bytes())?;
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_ciphersuites(self.ctx.get(), cipher_c.as_ptr()) }
                == 1
        );
        Ok(())
    }

    /// Set the list of preferred client certificate signers for this
    /// server context.
    fn set_client_ca_list(
        &self,
        py: Python<'_>,
        certificate_authorities: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        unsafe {
            let name_stack = ffi::OPENSSL_sk_new_null() as *mut ffi::stack_st_X509_NAME;
            openssl_assert!(py, Error, !name_stack.is_null());
            let cleanup = |stack: *mut ffi::stack_st_X509_NAME| {
                let sk = stack as *mut ffi::OPENSSL_STACK;
                for i in 0..ffi::OPENSSL_sk_num(sk) {
                    ffi::X509_NAME_free(ffi::OPENSSL_sk_value(sk, i) as *mut ffi::X509_NAME);
                }
                ffi::OPENSSL_sk_free(sk);
            };
            let iter = match certificate_authorities.try_iter() {
                Ok(i) => i,
                Err(e) => {
                    cleanup(name_stack);
                    return Err(e);
                }
            };
            for ca_name in iter {
                let result: PyResult<()> = (|| {
                    let ca_name = ca_name?;
                    let ca_name = ca_name.downcast::<X509Name>().map_err(|_| {
                        PyTypeError::new_err(format!(
                            "client CAs must be X509Name objects, not {} objects",
                            ca_name.get_type().name().map(|n| n.to_string()).unwrap_or_default()
                        ))
                    })?;
                    let name_ptr = ca_name.borrow().name.get();
                    let copy = ffi::X509_NAME_dup(name_ptr);
                    openssl_assert!(py, Error, !copy.is_null());
                    if ffi::OPENSSL_sk_push(
                        name_stack as *mut ffi::OPENSSL_STACK,
                        copy as *const c_void,
                    ) == 0
                    {
                        ffi::X509_NAME_free(copy);
                        return Err(openssl_error!(py, Error));
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    cleanup(name_stack);
                    return Err(e);
                }
            }
            ffi::SSL_CTX_set_client_CA_list(self.ctx.get(), name_stack);
        }
        Ok(())
    }

    /// Add the CA certificate to the list of preferred signers for this
    /// context.
    fn add_client_ca(
        &self,
        py: Python<'_>,
        certificate_authority: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let cert = as_x509(py, certificate_authority)?;
        openssl_assert!(
            py,
            Error,
            unsafe {
                ffi::SSL_CTX_add_client_CA(self.ctx.get(), cert.borrow(py).x509_ptr())
            } == 1
        );
        Ok(())
    }

    /// Set the timeout for newly created sessions for this Context object
    /// to *timeout*.
    fn set_timeout(&self, timeout: &Bound<'_, PyAny>) -> PyResult<c_long> {
        self.require_not_used()?;
        let timeout: c_long = timeout
            .extract()
            .map_err(|_| PyTypeError::new_err("timeout must be an integer"))?;
        Ok(unsafe { ffi_ext::SSL_CTX_set_timeout(self.ctx.get(), timeout) })
    }

    /// Retrieve session timeout, as set by `set_timeout`. The default is
    /// 300 seconds.
    fn get_timeout(&self) -> c_long {
        unsafe { ffi_ext::SSL_CTX_get_timeout(self.ctx.get()) }
    }

    /// Set the information callback to *callback*. This function will be
    /// called from time to time during SSL handshakes.
    fn set_info_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().info_cb = Some(callback.clone().unbind());
        unsafe {
            ffi_ext::SSL_CTX_set_info_callback(self.ctx.get(), Some(info_cb_ctx));
        }
        Ok(())
    }

    /// Set the TLS key logging callback to *callback*. This function will
    /// be called whenever TLS key material is generated or received.
    fn set_keylog_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().keylog_cb = Some(callback.clone().unbind());
        unsafe {
            ffi_ext::SSL_CTX_set_keylog_callback(self.ctx.get(), Some(keylog_cb));
        }
        Ok(())
    }

    /// Get the application data (supplied via `set_app_data()`)
    fn get_app_data(&self, py: Python<'_>) -> Py<PyAny> {
        self.app_data.clone_ref(py)
    }

    /// Set the application data (will be returned from get_app_data())
    fn set_app_data(&mut self, data: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.app_data = data.clone().unbind();
        Ok(())
    }

    /// Get the certificate store for the context. This can be used to add
    /// "trusted" certificates without using the `load_verify_locations`
    /// method.
    fn get_cert_store(&self) -> Option<X509Store> {
        unsafe {
            let store = ffi::SSL_CTX_get_cert_store(self.ctx.get());
            if store.is_null() {
                return None;
            }
            ffi_ext::X509_STORE_up_ref(store);
            Some(X509Store::from_raw(store))
        }
    }

    /// Add options. Options set before are not cleared! This method should
    /// be used with the `OP_*` constants.
    fn set_options(&self, options: &Bound<'_, PyAny>) -> PyResult<u64> {
        self.require_not_used()?;
        let options: u64 = options
            .extract()
            .map_err(|_| PyTypeError::new_err("options must be an integer"))?;
        Ok(unsafe { ffi::SSL_CTX_set_options(self.ctx.get(), options) })
    }

    /// Add modes via bitmask. Modes set before are not cleared! This
    /// method should be used with the `MODE_*` constants.
    fn set_mode(&self, mode: &Bound<'_, PyAny>) -> PyResult<c_long> {
        self.require_not_used()?;
        let mode: c_long = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        Ok(unsafe { ffi::SSL_CTX_set_mode(self.ctx.get(), mode) })
    }

    /// Modes previously set cannot be overwritten without being cleared
    /// first. This method should be used to clear existing modes.
    fn clear_mode(&self, mode_to_clear: c_long) -> PyResult<c_long> {
        self.require_not_used()?;
        Ok(unsafe { ffi_ext::SSL_CTX_clear_mode(self.ctx.get(), mode_to_clear) })
    }

    /// Specify a callback function to be called when clients specify a
    /// server name.
    fn set_tlsext_servername_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().servername_cb = Some(callback.clone().unbind());
        unsafe {
            ffi::SSL_CTX_set_tlsext_servername_callback__fixed_rust(
                self.ctx.get(),
                Some(servername_cb),
            );
        }
        Ok(())
    }

    /// Enable support for negotiating SRTP keying material.
    fn set_tlsext_use_srtp(&self, py: Python<'_>, profiles: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let profiles = profiles
            .downcast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("profiles must be a byte string."))?;
        let profiles_c = cstring(py, profiles.as_bytes())?;
        openssl_assert!(
            py,
            Error,
            unsafe {
                ffi::SSL_CTX_set_tlsext_use_srtp(self.ctx.get(), profiles_c.as_ptr())
            } == 0
        );
        Ok(())
    }

    /// Specify the protocols that the client is prepared to speak after
    /// the TLS connection has been negotiated using Application Layer
    /// Protocol Negotiation.
    fn set_alpn_protos(&self, py: Python<'_>, protos: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let protostr = build_alpn_wire_format(py, protos)?;
        // https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_alpn_protos.html:
        // SSL_CTX_set_alpn_protos() and SSL_set_alpn_protos()
        // return 0 on success, and non-0 on failure.
        // WARNING: these functions reverse the return value convention.
        openssl_assert!(
            py,
            Error,
            unsafe {
                ffi::SSL_CTX_set_alpn_protos(
                    self.ctx.get(),
                    protostr.as_ptr(),
                    protostr.len() as libc::c_uint,
                )
            } == 0
        );
        Ok(())
    }

    /// Specify a callback function that will be called on the server when
    /// a client offers protocols using ALPN.
    fn set_alpn_select_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().alpn_select_cb = Some(callback.clone().unbind());
        unsafe {
            ffi::SSL_CTX_set_alpn_select_cb__fixed_rust(
                self.ctx.get(),
                Some(alpn_select_cb),
                std::ptr::null_mut(),
            );
        }
        Ok(())
    }

    /// Set a callback to provide OCSP data to be stapled to the TLS
    /// handshake on the server side.
    #[pyo3(signature = (callback, data=None))]
    fn set_ocsp_server_callback(
        &mut self,
        py: Python<'_>,
        callback: &Bound<'_, PyAny>,
        data: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        self.set_ocsp_callback(py, callback, data, true)
    }

    /// Set a callback to validate OCSP data stapled to the TLS handshake
    /// on the client side.
    #[pyo3(signature = (callback, data=None))]
    fn set_ocsp_client_callback(
        &mut self,
        py: Python<'_>,
        callback: &Bound<'_, PyAny>,
        data: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        self.set_ocsp_callback(py, callback, data, false)
    }

    fn set_cookie_generate_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().cookie_generate_cb = Some(callback.clone().unbind());
        unsafe {
            ffi_ext::SSL_CTX_set_cookie_generate_cb(
                self.ctx.get(),
                Some(cookie_generate_cb),
            );
        }
        Ok(())
    }

    fn set_cookie_verify_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        self.state.lock().unwrap().cookie_verify_cb = Some(callback.clone().unbind());
        unsafe {
            ffi_ext::SSL_CTX_set_cookie_verify_cb(self.ctx.get(), Some(cookie_verify_cb));
        }
        Ok(())
    }
}

impl Context {
    fn set_ocsp_callback(
        &mut self,
        py: Python<'_>,
        callback: &Bound<'_, PyAny>,
        data: Option<&Bound<'_, PyAny>>,
        is_server: bool,
    ) -> PyResult<()> {
        {
            let mut state = self.state.lock().unwrap();
            state.ocsp_cb = Some(callback.clone().unbind());
            state.ocsp_data = data.map(|d| d.clone().unbind());
            state.ocsp_is_server = is_server;
        }
        unsafe {
            let rc = ffi::SSL_CTX_set_tlsext_status_cb(self.ctx.get(), Some(ocsp_cb));
            openssl_assert!(py, Error, rc == 1);
            let rc = ffi::SSL_CTX_set_tlsext_status_arg(
                self.ctx.get(),
                std::ptr::null_mut(),
            );
            openssl_assert!(py, Error, rc == 1);
        }
        Ok(())
    }
}

fn build_alpn_wire_format(py: Python<'_>, protos: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let mut result = Vec::new();
    let mut count = 0;
    for proto in protos.try_iter()? {
        let proto = proto?;
        let bytes = proto.extract::<Vec<u8>>()?;
        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        count += 1;
    }
    // Different versions of OpenSSL are inconsistent about how they handle
    // empty proto lists (see #1043), so we avoid the problem entirely by
    // rejecting them ourselves.
    if count == 0 {
        return Err(PyValueError::new_err(
            "at least one protocol must be specified",
        ));
    }
    let _ = py;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

#[pyclass(module = "OpenSSL.SSL", subclass, weakref, dict)]
pub struct Connection {
    ssl: CPtr<ffi::SSL>,
    context: Py<Context>,
    socket: Option<Py<PyAny>>,
    app_data: Py<PyAny>,
    into_ssl: CPtr<ffi::BIO>,
    from_ssl: CPtr<ffi::BIO>,
    state: Arc<Mutex<ConnState>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            unsafe { ffi::SSL_free(self.ssl.get()) }
        }
    }
}

/// Port of `_asFileDescriptor`.
fn as_file_descriptor(obj: &Bound<'_, PyAny>) -> PyResult<c_int> {
    let mut candidate = obj.clone();
    if !candidate.is_instance_of::<pyo3::types::PyInt>() {
        if let Ok(meth) = candidate.getattr("fileno") {
            candidate = meth.call0()?;
        }
    }
    let fd: c_int = candidate.extract().map_err(|_| {
        PyTypeError::new_err("argument must be an int, or have a fileno() method.")
    })?;
    if fd < 0 {
        return Err(PyValueError::new_err(format!(
            "file descriptor cannot be a negative integer ({})",
            fd
        )));
    }
    Ok(fd)
}

impl Connection {
    fn ssl_ptr(&self) -> *mut ffi::SSL {
        self.ssl.get()
    }

    /// Store a borrowed pointer to the Python Connection object in the
    /// SSL's ex_data so that callbacks can find it. The pointer is only
    /// dereferenced while a method of this Connection is executing, so the
    /// object is guaranteed to be alive.
    fn register(slf: &Bound<'_, Self>) {
        let this = slf.borrow();
        unsafe {
            ffi::SSL_set_ex_data(
                this.ssl.get(),
                conn_obj_idx(),
                slf.as_ptr() as *mut c_void,
            );
        }
    }

    fn raise_ssl_error(&self, py: Python<'_>, result: c_int, errno: i32) -> PyErr {
        // Check for exceptions raised in Python callbacks first.
        {
            let ctx_state_arc = self.context.borrow(py).state.clone();
            let mut ctx_state = ctx_state_arc.lock().unwrap();
            if !ctx_state.problems.is_empty() {
                let problem = ctx_state.problems.remove(0);
                drop(ctx_state);
                let _ = util::error_queue(py);
                return problem;
            }
        }
        {
            let mut conn_state = self.state.lock().unwrap();
            if !conn_state.problems.is_empty() {
                let problem = conn_state.problems.remove(0);
                drop(conn_state);
                let _ = util::error_queue(py);
                return problem;
            }
        }

        let error = unsafe { ffi::SSL_get_error(self.ssl.get(), result) };
        match error {
            ffi::SSL_ERROR_WANT_READ => WantReadError::new_err(()),
            ffi::SSL_ERROR_WANT_WRITE => WantWriteError::new_err(()),
            ffi::SSL_ERROR_ZERO_RETURN => ZeroReturnError::new_err(()),
            ffi::SSL_ERROR_WANT_X509_LOOKUP => WantX509LookupError::new_err(()),
            ffi::SSL_ERROR_SYSCALL => {
                if unsafe { ffi_ext::ERR_peek_error() } == 0 || errno != 0 {
                    if result < 0 && errno != 0 {
                        let errorcode = py
                            .import("errno")
                            .and_then(|m| m.getattr("errorcode"))
                            .and_then(|d| d.call_method1("get", (errno,)))
                            .map(|v| v.unbind())
                            .unwrap_or_else(|_| py.None());
                        SysCallError::new_err((errno, errorcode))
                    } else {
                        SysCallError::new_err((-1, "Unexpected EOF"))
                    }
                } else {
                    openssl_error!(py, Error)
                }
            }
            ffi::SSL_ERROR_SSL if unsafe { ffi_ext::ERR_peek_error() } != 0 => {
                // In 3.0.x an unexpected EOF no longer triggers syscall
                // error but we want to maintain compatibility so we check
                // here and raise SysCallError if it is an EOF.
                let peeked_error = unsafe { ffi_ext::ERR_peek_error() };
                let reason = ffi::ERR_GET_REASON(peeked_error);
                if reason == ffi_ext::SSL_R_UNEXPECTED_EOF_WHILE_READING {
                    unsafe { ffi::ERR_clear_error() };
                    SysCallError::new_err((-1, "Unexpected EOF"))
                } else {
                    openssl_error!(py, Error)
                }
            }
            ffi::SSL_ERROR_NONE => {
                // No error; this should not be reached when raising.
                Error::new_err(())
            }
            _ => openssl_error!(py, Error),
        }
    }

    fn handle_bio_errors(&self, py: Python<'_>, bio: *mut ffi::BIO, _result: c_int) -> PyErr {
        unsafe {
            if ffi_ext::BIO_should_retry(bio) {
                if ffi_ext::BIO_should_read(bio) {
                    WantReadError::new_err(())
                } else if ffi_ext::BIO_should_write(bio) {
                    WantWriteError::new_err(())
                } else if ffi_ext::BIO_should_io_special(bio) {
                    PyValueError::new_err("BIO_should_io_special")
                } else {
                    PyValueError::new_err("unknown bio failure")
                }
            } else {
                openssl_error!(py, Error)
            }
        }
    }

    fn socket_or_typeerror<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.socket {
            Some(s) => Ok(s.bind(py).clone()),
            None => Err(PyTypeError::new_err("Connection sock was not None")),
        }
    }

    fn cert_stack_to_list(
        py: Python<'_>,
        cert_stack: *mut ffi::stack_st_X509,
        as_cryptography: bool,
    ) -> PyResult<Py<PyList>> {
        let result = PyList::empty(py);
        unsafe {
            let sk = cert_stack as *mut ffi::OPENSSL_STACK;
            for i in 0..ffi::OPENSSL_sk_num(sk) {
                let cert = ffi::OPENSSL_sk_value(sk, i) as *mut ffi::X509;
                openssl_assert!(py, Error, !cert.is_null());
                let res = ffi::X509_up_ref(cert);
                openssl_assert!(py, Error, res >= 1);
                let pycert = Py::new(py, X509::from_raw(cert))?;
                if as_cryptography {
                    result.append(pycert.bind(py).call_method0("to_cryptography")?)?;
                } else {
                    result.append(pycert)?;
                }
            }
        }
        Ok(result.unbind())
    }

    fn get_finished_message(
        &self,
        py: Python<'_>,
        function: unsafe extern "C" fn(*const ffi::SSL, *mut c_void, libc::size_t) -> libc::size_t,
    ) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            let mut empty = [0u8; 1];
            let size = function(self.ssl.get(), empty.as_mut_ptr() as *mut c_void, 0);
            if size == 0 {
                return Ok(None);
            }
            let mut buf = vec![0u8; size];
            function(self.ssl.get(), buf.as_mut_ptr() as *mut c_void, size);
            Ok(Some(PyBytes::new(py, &buf).unbind()))
        }
    }
}

#[pymethods]
impl Connection {
    #[new]
    #[pyo3(signature = (context, socket=None))]
    fn new(
        py: Python<'_>,
        context: &Bound<'_, PyAny>,
        socket: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Connection> {
        let context = context
            .downcast::<Context>()
            .map_err(|_| PyTypeError::new_err("context must be a Context instance"))?;
        context.borrow_mut().used = true;

        let ssl = unsafe { ffi::SSL_new(context.borrow().ctx_ptr()) };
        openssl_assert!(py, Error, !ssl.is_null());

        // We set SSL_MODE_AUTO_RETRY to handle situations where OpenSSL
        // returns an SSL_ERROR_WANT_READ when processing a
        // non-application data packet even though there is still data on
        // the underlying transport.
        // See https://github.com/openssl/openssl/issues/6234.
        unsafe {
            ffi_ext::SSL_set_mode(ssl, ffi_ext::SSL_MODE_AUTO_RETRY);
        }

        let state = Arc::new(Mutex::new(ConnState::default()));
        unsafe {
            ffi::SSL_set_ex_data(
                ssl,
                conn_state_idx(),
                Arc::as_ptr(&state) as *mut c_void,
            );
        }

        let mut conn = Connection {
            ssl: CPtr(ssl),
            context: context.clone().unbind(),
            socket: None,
            app_data: py.None(),
            into_ssl: CPtr(std::ptr::null_mut()),
            from_ssl: CPtr(std::ptr::null_mut()),
            state,
        };

        let socket = socket.filter(|s| !s.is_none());
        match socket {
            None => unsafe {
                // Don't set up any gc for these, SSL_free will take care
                // of them.
                let into_ssl = ffi::BIO_new(ffi::BIO_s_mem());
                openssl_assert!(py, Error, !into_ssl.is_null());
                let from_ssl = ffi::BIO_new(ffi::BIO_s_mem());
                openssl_assert!(py, Error, !from_ssl.is_null());
                ffi::SSL_set_bio(ssl, into_ssl, from_ssl);
                conn.into_ssl = CPtr(into_ssl);
                conn.from_ssl = CPtr(from_ssl);
            },
            Some(socket) => unsafe {
                conn.socket = Some(socket.clone().unbind());
                let fd = as_file_descriptor(socket)?;
                let set_result = ffi_ext::SSL_set_fd(ssl, fd);
                openssl_assert!(py, Error, set_result == 1);
            },
        }
        Ok(conn)
    }

    /// Look up attributes on the wrapped socket object if they are not
    /// found on the Connection object.
    fn __getattr__(slf: &Bound<'_, Self>, name: &str) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let this = slf.borrow();
        match &this.socket {
            None => Err(pyo3::exceptions::PyAttributeError::new_err(format!(
                "'{}' object has no attribute '{}'",
                slf.get_type().name()?,
                name
            ))),
            Some(socket) => Ok(socket.bind(py).getattr(name)?.unbind()),
        }
    }

    /// Retrieve the `Context` object associated with this `Connection`.
    fn get_context(&self, py: Python<'_>) -> Py<Context> {
        self.context.clone_ref(py)
    }

    /// Switch this connection to a new session context.
    fn set_context(&mut self, py: Python<'_>, context: &Bound<'_, PyAny>) -> PyResult<()> {
        let context = context
            .downcast::<Context>()
            .map_err(|_| PyTypeError::new_err("context must be a Context instance"))?;
        unsafe {
            ffi::SSL_set_SSL_CTX(self.ssl.get(), context.borrow().ctx_ptr());
        }
        self.context = context.clone().unbind();
        context.borrow_mut().used = true;
        let _ = py;
        Ok(())
    }

    /// Add options. Options set before are not cleared!
    fn set_options(&self, options: &Bound<'_, PyAny>) -> PyResult<u64> {
        let options: u64 = options
            .extract()
            .map_err(|_| PyTypeError::new_err("options must be an integer"))?;
        Ok(unsafe { ffi_ext::SSL_set_options(self.ssl.get(), options) })
    }

    /// Retrieve the servername extension value if provided in the client
    /// hello message, or None if there wasn't one.
    fn get_servername(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        unsafe {
            let name = ffi::SSL_get_servername(
                self.ssl.get(),
                ffi::TLSEXT_NAMETYPE_host_name,
            );
            if name.is_null() {
                None
            } else {
                Some(
                    PyBytes::new(py, std::ffi::CStr::from_ptr(name).to_bytes())
                        .unbind(),
                )
            }
        }
    }

    /// Override the Context object's verification flags for this specific
    /// connection. See `Context.set_verify` for details.
    #[pyo3(signature = (mode, callback=None))]
    fn set_verify(
        slf: &Bound<'_, Self>,
        mode: &Bound<'_, PyAny>,
        callback: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let mode: c_int = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        Connection::register(slf);
        let this = slf.borrow();
        match callback {
            None => {
                this.state.lock().unwrap().verify_cb = None;
                unsafe { ffi::SSL_set_verify(this.ssl.get(), mode, None) };
            }
            Some(callback) => {
                if !callback.is_callable() {
                    return Err(PyTypeError::new_err("callback must be callable"));
                }
                this.state.lock().unwrap().verify_cb = Some(callback.clone().unbind());
                unsafe {
                    ffi::SSL_set_verify(this.ssl.get(), mode, Some(verify_cb_conn))
                };
            }
        }
        Ok(())
    }

    /// Retrieve the Connection object's verify mode, as set by
    /// `set_verify`.
    fn get_verify_mode(&self) -> c_int {
        unsafe { ffi::SSL_get_verify_mode(self.ssl.get()) }
    }

    /// Load a certificate from a X509 object
    fn use_certificate(&self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        let cert = as_x509(py, cert)?;
        let result = unsafe {
            ffi::SSL_use_certificate(self.ssl.get(), cert.borrow(py).x509_ptr())
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// Load a private key from a PKey object
    fn use_privatekey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = as_pkey(py, pkey)?;
        let result = unsafe {
            ffi::SSL_use_PrivateKey(self.ssl.get(), pkey.borrow(py).pkey_ptr())
        };
        if result == 0 {
            return Err(self.context.borrow_mut(py).raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// For DTLS, set the maximum UDP payload size (*not* including IP/UDP
    /// overhead).
    fn set_ciphertext_mtu(&self, mtu: c_long) {
        unsafe {
            ffi::SSL_set_mtu(self.ssl.get(), mtu);
        }
    }

    /// For DTLS, get the maximum size of unencrypted data you can pass to
    /// `write` without exceeding the MTU (as passed to
    /// `set_ciphertext_mtu`).
    fn get_cleartext_mtu(&self) -> usize {
        unsafe { ffi_ext::DTLS_get_data_mtu(self.ssl.get()) }
    }

    /// Set the value of the servername extension to send in the client
    /// hello.
    fn set_tlsext_host_name(&self, py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<()> {
        let name = name
            .downcast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("name must be a byte string"))?
            .as_bytes();
        if name.contains(&0) {
            return Err(PyTypeError::new_err("name must not contain NUL byte"));
        }
        let name_c = cstring(py, name)?;
        unsafe {
            ffi::SSL_set_tlsext_host_name(self.ssl.get(), name_c.as_ptr() as *mut c_char);
        }
        Ok(())
    }

    /// Get the number of bytes that can be safely read from the SSL
    /// buffer (**not** the underlying transport buffer).
    fn pending(&self) -> c_int {
        unsafe { ffi::SSL_pending(self.ssl.get()) }
    }

    /// Send data on the connection. NOTE: If you get one of the WantRead,
    /// WantWrite or WantX509Lookup exceptions on this, you have to call
    /// the method again with the SAME buffer.
    #[pyo3(signature = (buf, flags=0))]
    fn send(slf: &Bound<'_, Self>, buf: &Bound<'_, PyAny>, flags: c_int) -> PyResult<c_int> {
        let py = slf.py();
        let _ = flags;
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        // check len(buf) instead of the buffer length for testability
        if buf.bind(py).len()? > 2147483647 {
            return Err(PyValueError::new_err(
                "Cannot send more than 2**31-1 bytes at once.",
            ));
        }
        let data = util::buffer_to_vec(buf.bind(py))?;
        Connection::register(slf);
        let this = slf.borrow();
        let ssl = CPtr(this.ssl.get());
        let (result, errno) = py.detach(move || {
            let r = unsafe {
                ffi::SSL_write(ssl.get(), data.as_ptr() as *const c_void, data.len() as c_int)
            };
            (r, util::last_errno())
        });
        if result <= 0 {
            return Err(this.raise_ssl_error(py, result, errno));
        }
        Ok(result)
    }

    /// Alias for send().
    #[pyo3(signature = (buf, flags=0))]
    fn write(slf: &Bound<'_, Self>, buf: &Bound<'_, PyAny>, flags: c_int) -> PyResult<c_int> {
        Connection::send(slf, buf, flags)
    }

    /// Send "all" data on the connection. This calls send() repeatedly
    /// until all data is sent. If an error occurs, it's impossible to
    /// tell how much data has been sent.
    #[pyo3(signature = (buf, flags=0))]
    fn sendall(slf: &Bound<'_, Self>, buf: &Bound<'_, PyAny>, flags: c_int) -> PyResult<usize> {
        let py = slf.py();
        let _ = flags;
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        let data = util::buffer_to_vec(buf.bind(py))?;
        Connection::register(slf);
        let this = slf.borrow();

        let mut total_sent: usize = 0;
        let mut left_to_send = data.len();
        while left_to_send > 0 {
            // SSL_write's num arg is an int, so we cannot send more than
            // 2**31-1 bytes at once.
            let chunk = std::cmp::min(left_to_send, 2147483647);
            let ssl = CPtr(this.ssl.get());
            let ptr = CPtr(data[total_sent..].as_ptr() as *mut u8);
            let (result, errno) = py.detach(move || {
                let r = unsafe {
                    ffi::SSL_write(ssl.get(), ptr.get() as *const c_void, chunk as c_int)
                };
                (r, util::last_errno())
            });
            if result <= 0 {
                return Err(this.raise_ssl_error(py, result, errno));
            }
            total_sent += result as usize;
            left_to_send -= result as usize;
        }
        Ok(total_sent)
    }

    /// Receive data on the connection.
    #[pyo3(signature = (bufsiz, flags=None))]
    fn recv(
        slf: &Bound<'_, Self>,
        bufsiz: usize,
        flags: Option<c_int>,
    ) -> PyResult<Py<PyBytes>> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        let mut buf = vec![0u8; bufsiz];
        let peek = flags.map_or(false, |f| f & libc::MSG_PEEK != 0);
        let ssl = CPtr(this.ssl.get());
        let ptr = CPtr(buf.as_mut_ptr());
        let (result, errno) = py.detach(move || {
            let r = unsafe {
                if peek {
                    ffi::SSL_peek(ssl.get(), ptr.get() as *mut c_void, bufsiz as c_int)
                } else {
                    ffi::SSL_read(ssl.get(), ptr.get() as *mut c_void, bufsiz as c_int)
                }
            };
            (r, util::last_errno())
        });
        if result <= 0 {
            return Err(this.raise_ssl_error(py, result, errno));
        }
        Ok(PyBytes::new(py, &buf[..result as usize]).unbind())
    }

    /// Alias for recv().
    #[pyo3(signature = (bufsiz, flags=None))]
    fn read(
        slf: &Bound<'_, Self>,
        bufsiz: usize,
        flags: Option<c_int>,
    ) -> PyResult<Py<PyBytes>> {
        Connection::recv(slf, bufsiz, flags)
    }

    /// Receive data on the connection and copy it directly into the
    /// provided buffer, rather than creating a new string.
    #[pyo3(signature = (buffer, nbytes=None, flags=None))]
    fn recv_into(
        slf: &Bound<'_, Self>,
        buffer: &Bound<'_, PyAny>,
        nbytes: Option<usize>,
        flags: Option<c_int>,
    ) -> PyResult<c_int> {
        let py = slf.py();
        let pybuf = pyo3::buffer::PyBuffer::<u8>::get(buffer)?;
        if pybuf.readonly() {
            return Err(PyTypeError::new_err("buffer must be writable"));
        }
        let buflen = pybuf.len_bytes();
        let nbytes = match nbytes {
            Some(n) => std::cmp::min(n, buflen),
            None => buflen,
        };
        Connection::register(slf);
        let this = slf.borrow();
        let peek = flags.map_or(false, |f| f & libc::MSG_PEEK != 0);
        let ssl = CPtr(this.ssl.get());
        let ptr = CPtr(pybuf.buf_ptr() as *mut u8);
        let (result, errno) = py.detach(move || {
            let r = unsafe {
                if peek {
                    ffi::SSL_peek(ssl.get(), ptr.get() as *mut c_void, nbytes as c_int)
                } else {
                    ffi::SSL_read(ssl.get(), ptr.get() as *mut c_void, nbytes as c_int)
                }
            };
            (r, util::last_errno())
        });
        if result <= 0 {
            return Err(this.raise_ssl_error(py, result, errno));
        }
        Ok(result)
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to read bytes from the write end of that memory BIO.
    fn bio_read(&self, py: Python<'_>, bufsiz: &Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
        if self.from_ssl.is_null() {
            return Err(PyTypeError::new_err("Connection sock was not None"));
        }
        let bufsiz: c_int = bufsiz
            .extract()
            .map_err(|_| PyTypeError::new_err("bufsiz must be an integer"))?;
        let mut buf = vec![0u8; bufsiz.max(0) as usize];
        let result = unsafe {
            ffi::BIO_read(
                self.from_ssl.get(),
                buf.as_mut_ptr() as *mut c_void,
                bufsiz,
            )
        };
        if result <= 0 {
            return Err(self.handle_bio_errors(py, self.from_ssl.get(), result));
        }
        Ok(PyBytes::new(py, &buf[..result as usize]).unbind())
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to add bytes to the read end of that memory BIO. The
    /// Connection can then read the bytes (for example, in response to a
    /// call to `recv`).
    fn bio_write(&self, py: Python<'_>, buf: &Bound<'_, PyAny>) -> PyResult<c_int> {
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        if self.into_ssl.is_null() {
            return Err(PyTypeError::new_err("Connection sock was not None"));
        }
        let data = util::buffer_to_vec(buf.bind(py))?;
        let result = unsafe {
            ffi::BIO_write(
                self.into_ssl.get(),
                data.as_ptr() as *const c_void,
                data.len() as c_int,
            )
        };
        if result <= 0 {
            return Err(self.handle_bio_errors(py, self.into_ssl.get(), result));
        }
        Ok(result)
    }

    /// Renegotiate the session.
    fn renegotiate(&self, py: Python<'_>) -> PyResult<bool> {
        if !self.renegotiate_pending() {
            openssl_assert!(
                py,
                Error,
                unsafe { ffi_ext::SSL_renegotiate(self.ssl.get()) } == 1
            );
            return Ok(true);
        }
        Ok(false)
    }

    /// Perform an SSL handshake (usually called after `renegotiate` or
    /// one of `set_accept_state` or `set_connect_state`). This can raise
    /// the same exceptions as `send` and `recv`.
    fn do_handshake(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        let ssl = CPtr(this.ssl.get());
        let (result, errno) = py.detach(move || {
            let r = unsafe { ffi::SSL_do_handshake(ssl.get()) };
            (r, util::last_errno())
        });
        if result <= 0 {
            return Err(this.raise_ssl_error(py, result, errno));
        }
        Ok(())
    }

    /// Check if there's a renegotiation in progress, it will return False
    /// once a renegotiation is finished.
    fn renegotiate_pending(&self) -> bool {
        unsafe { ffi_ext::SSL_renegotiate_pending(self.ssl.get()) == 1 }
    }

    /// Find out the total number of renegotiations.
    fn total_renegotiations(&self) -> c_long {
        unsafe { ffi_ext::SSL_total_renegotiations(self.ssl.get()) }
    }

    /// Call the `connect` method of the underlying socket and set up SSL
    /// on the socket, using the `Context` object supplied to this
    /// `Connection` object at creation.
    fn connect(slf: &Bound<'_, Self>, addr: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        unsafe { ffi::SSL_set_connect_state(this.ssl.get()) };
        let socket = this.socket_or_typeerror(py)?;
        Ok(socket.call_method1("connect", (addr,))?.unbind())
    }

    /// Call the `connect_ex` method of the underlying socket and set up
    /// SSL on the socket, using the Context object supplied to this
    /// Connection object at creation.
    fn connect_ex(slf: &Bound<'_, Self>, addr: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        let socket = this.socket_or_typeerror(py)?;
        let connect_ex = socket.getattr("connect_ex")?;
        unsafe { ffi::SSL_set_connect_state(this.ssl.get()) };
        Ok(connect_ex.call1((addr,))?.unbind())
    }

    /// Call the `accept` method of the underlying socket and set up SSL
    /// on the returned socket, using the Context object supplied to this
    /// `Connection` object at creation.
    fn accept(slf: &Bound<'_, Self>) -> PyResult<Py<PyTuple>> {
        let py = slf.py();
        let this = slf.borrow();
        let socket = this.socket_or_typeerror(py)?;
        let result = socket.call_method0("accept")?;
        let (client, addr): (Bound<'_, PyAny>, Bound<'_, PyAny>) = result.extract()?;
        let conn = Py::new(
            py,
            Connection::new(py, this.context.bind(py).as_any(), Some(&client))?,
        )?;
        unsafe { ffi::SSL_set_accept_state(conn.borrow(py).ssl.get()) };
        Ok(PyTuple::new(py, [conn.into_any(), addr.unbind()])?.unbind())
    }

    /// Call the OpenSSL function DTLSv1_listen on this connection. See
    /// the OpenSSL manual for more details.
    #[allow(non_snake_case)]
    fn DTLSv1_listen(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        let result = unsafe {
            let bio_addr = ffi_ext::BIO_ADDR_new();
            let result = ffi_ext::DTLSv1_listen(this.ssl.get(), bio_addr);
            ffi_ext::BIO_ADDR_free(bio_addr);
            result
        };
        // DTLSv1_listen is weird. A zero return value means 'didn't find a
        // ClientHello with valid cookie, but keep trying'. So basically
        // WantReadError. But it doesn't work correctly with
        // raise_ssl_error. So we raise it manually instead.
        {
            let ctx_state_arc = this.context.borrow(py).state.clone();
            let mut ctx_state = ctx_state_arc.lock().unwrap();
            if !ctx_state.problems.is_empty() {
                let problem = ctx_state.problems.remove(0);
                drop(ctx_state);
                let _ = util::error_queue(py);
                return Err(problem);
            }
        }
        if result == 0 {
            return Err(WantReadError::new_err(()));
        }
        if result < 0 {
            return Err(this.raise_ssl_error(py, result, util::last_errno()));
        }
        Ok(())
    }

    /// Determine when the DTLS SSL object next needs to perform internal
    /// processing due to the passage of time.
    #[allow(non_snake_case)]
    fn DTLSv1_get_timeout(&self) -> Option<f64> {
        let mut tv = ffi_ext::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = unsafe { ffi_ext::DTLSv1_get_timeout(self.ssl.get(), &mut tv) };
        if result == 1 {
            Some(tv.tv_sec as f64 + (tv.tv_usec as f64 / 1_000_000.0))
        } else {
            None
        }
    }

    /// Handles any timeout events which have become pending on a DTLS SSL
    /// object.
    #[allow(non_snake_case)]
    fn DTLSv1_handle_timeout(&self, py: Python<'_>) -> PyResult<bool> {
        let result = unsafe { ffi_ext::DTLSv1_handle_timeout(self.ssl.get()) };
        if result < 0 {
            return Err(self.raise_ssl_error(py, result as c_int, util::last_errno()));
        }
        Ok(result > 0)
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to indicate that *end of file* has been reached on the
    /// read end of that memory BIO.
    fn bio_shutdown(&self) -> PyResult<()> {
        if self.from_ssl.is_null() {
            return Err(PyTypeError::new_err("Connection sock was not None"));
        }
        unsafe {
            ffi_ext::BIO_set_mem_eof_return(self.into_ssl.get(), 0);
        }
        Ok(())
    }

    /// Send the shutdown message to the Connection.
    fn shutdown(slf: &Bound<'_, Self>) -> PyResult<bool> {
        let py = slf.py();
        Connection::register(slf);
        let this = slf.borrow();
        let ssl = CPtr(this.ssl.get());
        let (result, errno) = py.detach(move || {
            let r = unsafe { ffi::SSL_shutdown(ssl.get()) };
            (r, util::last_errno())
        });
        if result < 0 {
            return Err(this.raise_ssl_error(py, result, errno));
        }
        Ok(result > 0)
    }

    /// Retrieve the list of ciphers used by the Connection object.
    fn get_cipher_list(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        let mut ciphers = Vec::new();
        let mut i = 0;
        loop {
            let result = unsafe { ffi_ext::SSL_get_cipher_list(self.ssl.get(), i) };
            if result.is_null() {
                break;
            }
            ciphers.push(unsafe { util::text(result) });
            i += 1;
        }
        let _ = py;
        Ok(ciphers)
    }

    /// Get CAs whose certificates are suggested for client
    /// authentication.
    fn get_client_ca_list(&self, py: Python<'_>) -> PyResult<Vec<Py<X509Name>>> {
        unsafe {
            let ca_names = ffi_ext::SSL_get_client_CA_list(self.ssl.get());
            if ca_names.is_null() {
                return Ok(Vec::new());
            }
            let sk = ca_names as *mut ffi::OPENSSL_STACK;
            let mut result = Vec::new();
            for i in 0..ffi::OPENSSL_sk_num(sk) {
                let name = ffi::OPENSSL_sk_value(sk, i) as *mut ffi::X509_NAME;
                let copy = ffi::X509_NAME_dup(name);
                openssl_assert!(py, Error, !copy.is_null());
                result.push(Py::new(py, X509Name::from_owned_ptr(copy))?);
            }
            Ok(result)
        }
    }

    /// The makefile() method is not implemented, since there is no dup
    /// semantics for SSL connections
    #[pyo3(signature = (*args, **kwargs))]
    fn makefile(
        &self,
        args: &Bound<'_, PyTuple>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<()> {
        let _ = (args, kwargs);
        Err(PyNotImplementedError::new_err(
            "Cannot make file object of OpenSSL.SSL.Connection",
        ))
    }

    /// Retrieve application data as set by `set_app_data`.
    fn get_app_data(&self, py: Python<'_>) -> Py<PyAny> {
        self.app_data.clone_ref(py)
    }

    /// Set application data
    fn set_app_data(&mut self, data: &Bound<'_, PyAny>) {
        self.app_data = data.clone().unbind();
    }

    /// Get the shutdown state of the Connection.
    fn get_shutdown(&self) -> c_int {
        unsafe { ffi::SSL_get_shutdown(self.ssl.get()) }
    }

    /// Set the shutdown state of the Connection.
    fn set_shutdown(&self, state: &Bound<'_, PyAny>) -> PyResult<()> {
        let state: c_int = state
            .extract()
            .map_err(|_| PyTypeError::new_err("state must be an integer"))?;
        unsafe { ffi::SSL_set_shutdown(self.ssl.get(), state) };
        Ok(())
    }

    /// Retrieve a verbose string detailing the state of the Connection.
    fn get_state_string(&self, py: Python<'_>) -> Py<PyBytes> {
        unsafe {
            let state = ffi::SSL_state_string_long(self.ssl.get());
            PyBytes::new(py, std::ffi::CStr::from_ptr(state).to_bytes()).unbind()
        }
    }

    /// Retrieve the random value used with the server hello message.
    fn server_random(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            let session = ffi::SSL_get_session(self.ssl.get());
            if session.is_null() {
                return Ok(None);
            }
            let length = ffi::SSL_get_server_random(self.ssl.get(), std::ptr::null_mut(), 0);
            openssl_assert!(py, Error, length > 0);
            let mut buf = vec![0u8; length];
            ffi::SSL_get_server_random(self.ssl.get(), buf.as_mut_ptr(), length);
            Ok(Some(PyBytes::new(py, &buf).unbind()))
        }
    }

    /// Retrieve the random value used with the client hello message.
    fn client_random(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            let session = ffi::SSL_get_session(self.ssl.get());
            if session.is_null() {
                return Ok(None);
            }
            let length = ffi::SSL_get_client_random(self.ssl.get(), std::ptr::null_mut(), 0);
            openssl_assert!(py, Error, length > 0);
            let mut buf = vec![0u8; length];
            ffi::SSL_get_client_random(self.ssl.get(), buf.as_mut_ptr(), length);
            Ok(Some(PyBytes::new(py, &buf).unbind()))
        }
    }

    /// Retrieve the value of the master key for this session.
    fn master_key(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            let session = ffi::SSL_get_session(self.ssl.get());
            if session.is_null() {
                return Ok(None);
            }
            let length = ffi::SSL_SESSION_get_master_key(session, std::ptr::null_mut(), 0);
            openssl_assert!(py, Error, length > 0);
            let mut buf = vec![0u8; length];
            ffi::SSL_SESSION_get_master_key(session, buf.as_mut_ptr(), length);
            Ok(Some(PyBytes::new(py, &buf).unbind()))
        }
    }

    /// Obtain keying material for application use.
    #[pyo3(signature = (label, olen, context=None))]
    fn export_keying_material(
        &self,
        py: Python<'_>,
        label: &[u8],
        olen: usize,
        context: Option<&[u8]>,
    ) -> PyResult<Py<PyBytes>> {
        let mut outp = vec![0u8; olen];
        let (context_buf, context_len, use_context) = match context {
            Some(c) => (c.as_ptr(), c.len(), 1),
            None => (std::ptr::null(), 0, 0),
        };
        let success = unsafe {
            ffi::SSL_export_keying_material(
                self.ssl.get(),
                outp.as_mut_ptr(),
                olen,
                label.as_ptr() as *const c_char,
                label.len(),
                context_buf,
                context_len,
                use_context,
            )
        };
        openssl_assert!(py, Error, success == 1);
        Ok(PyBytes::new(py, &outp).unbind())
    }

    /// Call the `shutdown` method of the underlying socket.
    #[pyo3(signature = (*args, **kwargs))]
    fn sock_shutdown(
        &self,
        py: Python<'_>,
        args: &Bound<'_, PyTuple>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        let socket = self.socket_or_typeerror(py)?;
        Ok(socket.call_method("shutdown", args, kwargs)?.unbind())
    }

    /// Retrieve the local certificate (if any)
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_certificate(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyAny>>> {
        unsafe {
            let cert = ffi::SSL_get_certificate(self.ssl.get());
            if cert.is_null() {
                return Ok(None);
            }
            ffi::X509_up_ref(cert);
            let pycert = Py::new(py, X509::from_raw(cert))?;
            if as_cryptography {
                return Ok(Some(
                    pycert.bind(py).call_method0("to_cryptography")?.unbind(),
                ));
            }
            Ok(Some(pycert.into_any()))
        }
    }

    /// Retrieve the other side's certificate (if any)
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_peer_certificate(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyAny>>> {
        unsafe {
            let cert = ffi::SSL_get1_peer_certificate(self.ssl.get());
            if cert.is_null() {
                return Ok(None);
            }
            let pycert = Py::new(py, X509::from_raw(cert))?;
            if as_cryptography {
                return Ok(Some(
                    pycert.bind(py).call_method0("to_cryptography")?.unbind(),
                ));
            }
            Ok(Some(pycert.into_any()))
        }
    }

    /// Retrieve the other side's certificate chain (if any)
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_peer_cert_chain(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyList>>> {
        unsafe {
            let cert_stack = ffi::SSL_get_peer_cert_chain(self.ssl.get());
            if cert_stack.is_null() {
                return Ok(None);
            }
            Ok(Some(Connection::cert_stack_to_list(
                py,
                cert_stack,
                as_cryptography,
            )?))
        }
    }

    /// Retrieve the verified certificate chain of the peer including the
    /// peer's end entity certificate.
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_verified_chain(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyList>>> {
        unsafe {
            let cert_stack = ffi::SSL_get0_verified_chain(self.ssl.get());
            if cert_stack.is_null() {
                return Ok(None);
            }
            Ok(Some(Connection::cert_stack_to_list(
                py,
                cert_stack,
                as_cryptography,
            )?))
        }
    }

    /// Checks if more data has to be read from the transport layer to
    /// complete an operation.
    fn want_read(&self) -> bool {
        const SSL_READING: c_int = 3;
        unsafe { ffi_ext::SSL_want(self.ssl.get()) == SSL_READING }
    }

    /// Checks if there is data to write to the transport layer to
    /// complete an operation.
    fn want_write(&self) -> bool {
        const SSL_WRITING: c_int = 2;
        unsafe { ffi_ext::SSL_want(self.ssl.get()) == SSL_WRITING }
    }

    /// Set the connection to work in server mode. The handshake will be
    /// handled automatically by read/write.
    fn set_accept_state(&self) {
        unsafe { ffi::SSL_set_accept_state(self.ssl.get()) }
    }

    /// Set the connection to work in client mode. The handshake will be
    /// handled automatically by read/write.
    fn set_connect_state(&self) {
        unsafe { ffi::SSL_set_connect_state(self.ssl.get()) }
    }

    /// Returns the Session currently used.
    fn get_session(&self) -> Option<Session> {
        unsafe {
            let session = ffi_ext::SSL_get1_session(self.ssl.get());
            if session.is_null() {
                return None;
            }
            Some(Session {
                session: CPtr(session),
            })
        }
    }

    /// Set the session to be used when the TLS/SSL connection is
    /// established.
    fn set_session(&self, py: Python<'_>, session: &Bound<'_, PyAny>) -> PyResult<()> {
        let session = session
            .downcast::<Session>()
            .map_err(|_| PyTypeError::new_err("session must be a Session instance"))?;
        let result = unsafe {
            ffi::SSL_set_session(self.ssl.get(), session.borrow().session.get())
        };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Obtain the latest TLS Finished message that we sent.
    fn get_finished(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        self.get_finished_message(py, ffi::SSL_get_finished)
    }

    /// Obtain the latest TLS Finished message that we received from the
    /// peer.
    fn get_peer_finished(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        self.get_finished_message(py, ffi::SSL_get_peer_finished)
    }

    /// Obtain the name of the currently used cipher.
    fn get_cipher_name(&self, py: Python<'_>) -> Option<String> {
        unsafe {
            let cipher = ffi::SSL_get_current_cipher(self.ssl.get());
            if cipher.is_null() {
                None
            } else {
                let _ = py;
                Some(util::text(ffi::SSL_CIPHER_get_name(cipher)))
            }
        }
    }

    /// Obtain the number of secret bits of the currently used cipher.
    fn get_cipher_bits(&self) -> Option<c_int> {
        unsafe {
            let cipher = ffi::SSL_get_current_cipher(self.ssl.get());
            if cipher.is_null() {
                None
            } else {
                Some(ffi::SSL_CIPHER_get_bits(cipher, std::ptr::null_mut()))
            }
        }
    }

    /// Obtain the protocol version of the currently used cipher.
    fn get_cipher_version(&self) -> Option<String> {
        unsafe {
            let cipher = ffi::SSL_get_current_cipher(self.ssl.get());
            if cipher.is_null() {
                None
            } else {
                Some(util::text(ffi::SSL_CIPHER_get_version(cipher)))
            }
        }
    }

    /// Retrieve the protocol version of the current connection.
    fn get_protocol_version_name(&self) -> String {
        unsafe { util::text(ffi::SSL_get_version(self.ssl.get())) }
    }

    /// Retrieve the SSL or TLS protocol version of the current
    /// connection.
    fn get_protocol_version(&self) -> c_int {
        unsafe { ffi::SSL_version(self.ssl.get()) }
    }

    /// Specify the client's ALPN protocol list.
    fn set_alpn_protos(&self, py: Python<'_>, protos: &Bound<'_, PyAny>) -> PyResult<()> {
        let protostr = build_alpn_wire_format(py, protos)?;
        openssl_assert!(
            py,
            Error,
            unsafe {
                ffi::SSL_set_alpn_protos(
                    self.ssl.get(),
                    protostr.as_ptr(),
                    protostr.len() as libc::c_uint,
                )
            } == 0
        );
        Ok(())
    }

    /// Get the protocol that was negotiated by ALPN.
    fn get_alpn_proto_negotiated(&self, py: Python<'_>) -> Py<PyBytes> {
        unsafe {
            let mut data: *const c_uchar = std::ptr::null();
            let mut data_len: libc::c_uint = 0;
            ffi::SSL_get0_alpn_selected(self.ssl.get(), &mut data, &mut data_len);
            if data_len == 0 || data.is_null() {
                return PyBytes::new(py, b"").unbind();
            }
            PyBytes::new(py, std::slice::from_raw_parts(data, data_len as usize))
                .unbind()
        }
    }

    /// Get the SRTP protocol which was negotiated.
    fn get_selected_srtp_profile(&self, py: Python<'_>) -> Py<PyBytes> {
        unsafe {
            let profile = ffi::SSL_get_selected_srtp_profile(self.ssl.get());
            if profile.is_null() {
                return PyBytes::new(py, b"").unbind();
            }
            PyBytes::new(
                py,
                std::ffi::CStr::from_ptr((*profile).name).to_bytes(),
            )
            .unbind()
        }
    }

    /// Get the name of the negotiated group for the key exchange.
    fn get_group_name(&self, py: Python<'_>) -> PyResult<Option<String>> {
        #[cfg(ossl320)]
        {
            // Do not remove this guard.
            // SSL_get0_group_name crashes with a segfault if called
            // without an established connection (should return NULL but
            // doesn't).
            unsafe {
                let session = ffi::SSL_get_session(self.ssl.get());
                if session.is_null() {
                    return Ok(None);
                }
                let group_name = ffi_ext::SSL_get0_group_name(self.ssl.get());
                if group_name.is_null() {
                    return Ok(None);
                }
                let _ = py;
                Ok(Some(util::text(group_name)))
            }
        }
        #[cfg(not(ossl320))]
        {
            let _ = py;
            Err(PyNotImplementedError::new_err(
                "Getting group name is not supported by the linked OpenSSL version",
            ))
        }
    }

    /// Called to request that the server sends stapled OCSP data, if
    /// available. If this is not called on the client side then the
    /// server will not send OCSP data.
    fn request_ocsp(&self, py: Python<'_>) -> PyResult<()> {
        let rc = unsafe {
            ffi::SSL_set_tlsext_status_type(
                self.ssl.get(),
                ffi::TLSEXT_STATUSTYPE_ocsp,
            )
        };
        openssl_assert!(py, Error, rc == 1);
        Ok(())
    }

    /// Set the information callback to *callback*. This function will be
    /// called from time to time during SSL handshakes.
    fn set_info_callback(slf: &Bound<'_, Self>, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        Connection::register(slf);
        let this = slf.borrow();
        this.state.lock().unwrap().info_cb = Some(callback.clone().unbind());
        unsafe {
            ffi_ext::SSL_set_info_callback(this.ssl.get(), Some(info_cb_conn));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

#[pyfunction]
fn _x509_get_default_cert_file(py: Python<'_>) -> Py<PyBytes> {
    unsafe {
        PyBytes::new(
            py,
            std::ffi::CStr::from_ptr(ffi_ext::X509_get_default_cert_file()).to_bytes(),
        )
        .unbind()
    }
}

#[pyfunction]
fn _x509_get_default_cert_dir(py: Python<'_>) -> Py<PyBytes> {
    unsafe {
        PyBytes::new(
            py,
            std::ffi::CStr::from_ptr(ffi_ext::X509_get_default_cert_dir()).to_bytes(),
        )
        .unbind()
    }
}

/// Return a string describing the version of OpenSSL in use.
#[pyfunction(name = "OpenSSL_version")]
fn openssl_version(py: Python<'_>, r#type: c_int) -> Py<PyBytes> {
    unsafe {
        let s = ffi::OpenSSL_version(r#type);
        PyBytes::new(py, std::ffi::CStr::from_ptr(s).to_bytes()).unbind()
    }
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "_SSL")?;

    m.add("Error", py.get_type::<Error>())?;
    m.add("WantReadError", py.get_type::<WantReadError>())?;
    m.add("WantWriteError", py.get_type::<WantWriteError>())?;
    m.add("WantX509LookupError", py.get_type::<WantX509LookupError>())?;
    m.add("ZeroReturnError", py.get_type::<ZeroReturnError>())?;
    m.add("SysCallError", py.get_type::<SysCallError>())?;

    m.add_class::<Context>()?;
    m.add_class::<Connection>()?;
    m.add_class::<Session>()?;
    m.add_class::<X509VerificationCodes>()?;
    m.add_class::<NoOverlappingProtocols>()?;
    m.add("NO_OVERLAPPING_PROTOCOLS", no_overlapping_protocols(py)?)?;

    m.add_function(pyo3::wrap_pyfunction!(openssl_version, &m)?)?;
    m.add("SSLeay_version", m.getattr("OpenSSL_version")?)?;

    unsafe {
        m.add("OPENSSL_VERSION_NUMBER", ffi::OpenSSL_version_num())?;
    }
    m.add("OPENSSL_VERSION", ffi_ext::OPENSSL_VERSION_T)?;
    m.add("OPENSSL_CFLAGS", ffi_ext::OPENSSL_CFLAGS_T)?;
    m.add("OPENSSL_BUILT_ON", ffi_ext::OPENSSL_BUILT_ON_T)?;
    m.add("OPENSSL_PLATFORM", ffi_ext::OPENSSL_PLATFORM_T)?;
    m.add("OPENSSL_DIR", ffi_ext::OPENSSL_DIR_T)?;
    m.add("SSLEAY_VERSION", ffi_ext::OPENSSL_VERSION_T)?;
    m.add("SSLEAY_CFLAGS", ffi_ext::OPENSSL_CFLAGS_T)?;
    m.add("SSLEAY_BUILT_ON", ffi_ext::OPENSSL_BUILT_ON_T)?;
    m.add("SSLEAY_PLATFORM", ffi_ext::OPENSSL_PLATFORM_T)?;
    m.add("SSLEAY_DIR", ffi_ext::OPENSSL_DIR_T)?;

    m.add("SENT_SHUTDOWN", ffi_ext::SSL_SENT_SHUTDOWN)?;
    m.add("RECEIVED_SHUTDOWN", ffi_ext::SSL_RECEIVED_SHUTDOWN)?;

    m.add("SSLv23_METHOD", SSLV23_METHOD)?;
    m.add("TLSv1_METHOD", TLSV1_METHOD)?;
    m.add("TLSv1_1_METHOD", TLSV1_1_METHOD)?;
    m.add("TLSv1_2_METHOD", TLSV1_2_METHOD)?;
    m.add("TLS_METHOD", TLS_METHOD)?;
    m.add("TLS_SERVER_METHOD", TLS_SERVER_METHOD)?;
    m.add("TLS_CLIENT_METHOD", TLS_CLIENT_METHOD)?;
    m.add("DTLS_METHOD", DTLS_METHOD)?;
    m.add("DTLS_SERVER_METHOD", DTLS_SERVER_METHOD)?;
    m.add("DTLS_CLIENT_METHOD", DTLS_CLIENT_METHOD)?;

    m.add("SSL3_VERSION", ffi::SSL3_VERSION)?;
    m.add("TLS1_VERSION", ffi::TLS1_VERSION)?;
    m.add("TLS1_1_VERSION", ffi::TLS1_1_VERSION)?;
    m.add("TLS1_2_VERSION", ffi::TLS1_2_VERSION)?;
    m.add("TLS1_3_VERSION", ffi::TLS1_3_VERSION)?;

    m.add("OP_NO_SSLv2", 0u64)?;
    m.add("OP_NO_SSLv3", ffi::SSL_OP_NO_SSLv3)?;
    m.add("OP_NO_TLSv1", ffi::SSL_OP_NO_TLSv1)?;
    m.add("OP_NO_TLSv1_1", ffi::SSL_OP_NO_TLSv1_1)?;
    m.add("OP_NO_TLSv1_2", ffi::SSL_OP_NO_TLSv1_2)?;
    m.add("OP_NO_TLSv1_3", ffi::SSL_OP_NO_TLSv1_3)?;

    m.add("MODE_RELEASE_BUFFERS", ffi_ext::SSL_MODE_RELEASE_BUFFERS)?;

    m.add("OP_SINGLE_DH_USE", ffi::SSL_OP_SINGLE_DH_USE)?;
    m.add("OP_SINGLE_ECDH_USE", ffi::SSL_OP_SINGLE_ECDH_USE)?;
    m.add("OP_EPHEMERAL_RSA", 0u64)?;
    m.add("OP_MICROSOFT_SESS_ID_BUG", ffi::SSL_OP_MICROSOFT_SESS_ID_BUG)?;
    m.add("OP_NETSCAPE_CHALLENGE_BUG", ffi::SSL_OP_NETSCAPE_CHALLENGE_BUG)?;
    m.add(
        "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
        ffi::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG,
    )?;
    m.add("OP_SSLREF2_REUSE_CERT_TYPE_BUG", 0u64)?;
    m.add(
        "OP_MICROSOFT_BIG_SSLV3_BUFFER",
        ffi::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER,
    )?;
    m.add("OP_MSIE_SSLV2_RSA_PADDING", 0u64)?;
    m.add(
        "OP_SSLEAY_080_CLIENT_DH_BUG",
        ffi::SSL_OP_SSLEAY_080_CLIENT_DH_BUG,
    )?;
    m.add("OP_TLS_D5_BUG", ffi::SSL_OP_TLS_D5_BUG)?;
    m.add("OP_TLS_BLOCK_PADDING_BUG", ffi::SSL_OP_TLS_BLOCK_PADDING_BUG)?;
    m.add(
        "OP_DONT_INSERT_EMPTY_FRAGMENTS",
        ffi::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS,
    )?;
    m.add(
        "OP_CIPHER_SERVER_PREFERENCE",
        ffi::SSL_OP_CIPHER_SERVER_PREFERENCE,
    )?;
    m.add("OP_TLS_ROLLBACK_BUG", ffi::SSL_OP_TLS_ROLLBACK_BUG)?;
    m.add("OP_PKCS1_CHECK_1", 0u64)?;
    m.add("OP_PKCS1_CHECK_2", 0u64)?;
    m.add("OP_NETSCAPE_CA_DN_BUG", 0u64)?;
    m.add("OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", 0u64)?;
    m.add("OP_NO_COMPRESSION", ffi::SSL_OP_NO_COMPRESSION)?;
    m.add("OP_NO_QUERY_MTU", ffi::SSL_OP_NO_QUERY_MTU)?;
    m.add("OP_COOKIE_EXCHANGE", ffi::SSL_OP_COOKIE_EXCHANGE)?;
    m.add("OP_NO_TICKET", ffi::SSL_OP_NO_TICKET)?;
    m.add("OP_NO_RENEGOTIATION", ffi::SSL_OP_NO_RENEGOTIATION)?;
    m.add("OP_IGNORE_UNEXPECTED_EOF", ffi::SSL_OP_IGNORE_UNEXPECTED_EOF)?;
    m.add("OP_LEGACY_SERVER_CONNECT", ffi::SSL_OP_LEGACY_SERVER_CONNECT)?;
    m.add("OP_ALL", ffi::SSL_OP_ALL)?;

    m.add("VERIFY_PEER", ffi::SSL_VERIFY_PEER)?;
    m.add(
        "VERIFY_FAIL_IF_NO_PEER_CERT",
        ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    )?;
    m.add("VERIFY_CLIENT_ONCE", 0x4)?;
    m.add("VERIFY_NONE", ffi::SSL_VERIFY_NONE)?;

    m.add("SESS_CACHE_OFF", ffi_ext::SSL_SESS_CACHE_OFF)?;
    m.add("SESS_CACHE_CLIENT", ffi_ext::SSL_SESS_CACHE_CLIENT)?;
    m.add("SESS_CACHE_SERVER", ffi_ext::SSL_SESS_CACHE_SERVER)?;
    m.add("SESS_CACHE_BOTH", ffi_ext::SSL_SESS_CACHE_BOTH)?;
    m.add("SESS_CACHE_NO_AUTO_CLEAR", ffi_ext::SSL_SESS_CACHE_NO_AUTO_CLEAR)?;
    m.add(
        "SESS_CACHE_NO_INTERNAL_LOOKUP",
        ffi_ext::SSL_SESS_CACHE_NO_INTERNAL_LOOKUP,
    )?;
    m.add(
        "SESS_CACHE_NO_INTERNAL_STORE",
        ffi_ext::SSL_SESS_CACHE_NO_INTERNAL_STORE,
    )?;
    m.add("SESS_CACHE_NO_INTERNAL", ffi_ext::SSL_SESS_CACHE_NO_INTERNAL)?;

    m.add("SSL_ST_CONNECT", ffi_ext::SSL_ST_CONNECT)?;
    m.add("SSL_ST_ACCEPT", ffi_ext::SSL_ST_ACCEPT)?;
    m.add("SSL_ST_MASK", ffi_ext::SSL_ST_MASK)?;

    m.add("SSL_CB_LOOP", ffi_ext::SSL_CB_LOOP)?;
    m.add("SSL_CB_EXIT", ffi_ext::SSL_CB_EXIT)?;
    m.add("SSL_CB_READ", ffi_ext::SSL_CB_READ)?;
    m.add("SSL_CB_WRITE", ffi_ext::SSL_CB_WRITE)?;
    m.add("SSL_CB_ALERT", ffi_ext::SSL_CB_ALERT)?;
    m.add("SSL_CB_READ_ALERT", ffi_ext::SSL_CB_READ_ALERT)?;
    m.add("SSL_CB_WRITE_ALERT", ffi_ext::SSL_CB_WRITE_ALERT)?;
    m.add("SSL_CB_ACCEPT_LOOP", ffi_ext::SSL_CB_ACCEPT_LOOP)?;
    m.add("SSL_CB_ACCEPT_EXIT", ffi_ext::SSL_CB_ACCEPT_EXIT)?;
    m.add("SSL_CB_CONNECT_LOOP", ffi_ext::SSL_CB_CONNECT_LOOP)?;
    m.add("SSL_CB_CONNECT_EXIT", ffi_ext::SSL_CB_CONNECT_EXIT)?;
    m.add("SSL_CB_HANDSHAKE_START", ffi_ext::SSL_CB_HANDSHAKE_START)?;
    m.add("SSL_CB_HANDSHAKE_DONE", ffi_ext::SSL_CB_HANDSHAKE_DONE)?;

    m.add(
        "_CRYPTOGRAPHY_MANYLINUX_CA_DIR",
        pyo3::types::PyBytes::new(py, CRYPTOGRAPHY_MANYLINUX_CA_DIR),
    )?;
    m.add(
        "_CRYPTOGRAPHY_MANYLINUX_CA_FILE",
        pyo3::types::PyBytes::new(py, CRYPTOGRAPHY_MANYLINUX_CA_FILE),
    )?;
    m.add(
        "_CERTIFICATE_FILE_LOCATIONS",
        PyList::new(py, CERTIFICATE_FILE_LOCATIONS)?,
    )?;
    m.add(
        "_CERTIFICATE_PATH_LOCATIONS",
        PyList::new(py, CERTIFICATE_PATH_LOCATIONS)?,
    )?;
    m.add_function(pyo3::wrap_pyfunction!(_x509_get_default_cert_file, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(_x509_get_default_cert_dir, &m)?)?;

    // Feature flags (the cffi bindings exposed these via
    // `Cryptography_HAS_*`; tests use these spellings).
    m.add("_HAS_KEYLOG", true)?;
    m.add("_HAS_SSL_COOKIE", true)?;
    m.add("_HAS_SSL_GET0_GROUP_NAME", cfg!(ossl320))?;

    Ok(m)
}
