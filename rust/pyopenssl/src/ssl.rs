//! Implementation of the `OpenSSL.SSL` module.
//!
//! This is written against the safe `openssl` crate (rust-openssl)
//! wherever its API model permits:
//!
//! * `Context` wraps an `SslContextBuilder` (which is never `build()`-en,
//!   since pyOpenSSL contexts stay configurable until first use), and the
//!   verify/servername/keylog/cookie callbacks are safe closures.
//! * `Connection` wraps an `SslStream<PyBio>`, where `PyBio` is a stream
//!   that proxies either the Python socket's file descriptor or a pair of
//!   in-memory buffers (replacing the memory-BIO pair the cffi
//!   implementation used).
//!
//! The remaining openssl-sys usage is for APIs with no safe spelling:
//! renegotiation, `SSL_want`, the DTLS listen/timeout/MTU surface, the
//! info callback, the context-wide passphrase callback, the ALPN selection
//! callback (the safe one cannot return bytes not present in the client's
//! offer), the OCSP status callback (the safe one cannot express
//! NOACK/fatal distinctions pyOpenSSL needs), and assorted small getters.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use libc::{c_int, c_long, c_uchar, c_void};
use openssl::error::ErrorStack;
use openssl::pkey::PKeyRef;
use openssl::ssl::{
    NameType, ShutdownResult, ShutdownState, SniError, Ssl, SslContext,
    SslContextBuilder, SslContextRef, SslFiletype, SslMethod, SslMode, SslOptions,
    SslRef, SslSession, SslSessionCacheMode, SslStream, SslVerifyMode,
};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreRef;
use openssl::x509::{X509Name as SslX509Name, X509StoreContextRef, X509VerifyResult};
use openssl_sys as ffi;
use pyo3::exceptions::{PyNotImplementedError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

use crate::crypto::{self, PKey, PassphraseHelper, X509, X509Name, X509Store};
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

/// Convert an `ErrorStack` into an `OpenSSL.SSL.Error`.
fn err_stack_to_py(py: Python<'_>, e: ErrorStack) -> PyErr {
    util::error_stack_to_exception(py, &py.get_type::<Error>(), &e)
}

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
// ex_data indices (safe rust-openssl ex_data)
// ---------------------------------------------------------------------------

/// SSL ex_data slot holding a Python weakref to the Connection object.
fn conn_obj_idx() -> openssl::ex_data::Index<Ssl, Py<PyAny>> {
    static IDX: OnceLock<openssl::ex_data::Index<Ssl, Py<PyAny>>> = OnceLock::new();
    *IDX.get_or_init(|| Ssl::new_ex_index().expect("ex_data index allocation failed"))
}

/// SSL ex_data slot holding the per-connection callback state.
fn conn_state_idx() -> openssl::ex_data::Index<Ssl, Arc<ConnState>> {
    static IDX: OnceLock<openssl::ex_data::Index<Ssl, Arc<ConnState>>> = OnceLock::new();
    *IDX.get_or_init(|| Ssl::new_ex_index().expect("ex_data index allocation failed"))
}

/// SSL_CTX ex_data slot holding the per-context callback state (only
/// needed by the raw trampolines; the safe closures capture their state
/// directly).
fn ctx_state_idx() -> openssl::ex_data::Index<SslContext, Arc<CtxState>> {
    static IDX: OnceLock<openssl::ex_data::Index<SslContext, Arc<CtxState>>> =
        OnceLock::new();
    *IDX.get_or_init(|| {
        SslContext::new_ex_index().expect("ex_data index allocation failed")
    })
}

// ---------------------------------------------------------------------------
// Callback state
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CtxState {
    // Callbacks which still go through raw trampolines.
    info_cb: Mutex<Option<Py<PyAny>>>,
    alpn_select_cb: Mutex<Option<Py<PyAny>>>,
    ocsp_cb: Mutex<Option<Py<PyAny>>>,
    ocsp_data: Mutex<Option<Py<PyAny>>>,
    ocsp_is_server: std::sync::atomic::AtomicBool,
    // Exceptions raised inside Python callbacks, re-raised after the I/O
    // call that triggered them.
    problems: Mutex<Vec<PyErr>>,
}

impl CtxState {
    fn push_problem(&self, e: PyErr) {
        self.problems.lock().unwrap().push(e);
    }

    fn pop_problem(&self) -> Option<PyErr> {
        let mut problems = self.problems.lock().unwrap();
        if problems.is_empty() {
            None
        } else {
            Some(problems.remove(0))
        }
    }
}

#[derive(Default)]
pub struct ConnState {
    info_cb: Mutex<Option<Py<PyAny>>>,
    // Keeps the ALPN selection alive until OpenSSL has copied it out.
    alpn_buf: Mutex<Option<Vec<u8>>>,
    problems: Mutex<Vec<PyErr>>,
    registered: std::sync::atomic::AtomicBool,
}

impl ConnState {
    fn push_problem(&self, e: PyErr) {
        self.problems.lock().unwrap().push(e);
    }

    fn pop_problem(&self) -> Option<PyErr> {
        let mut problems = self.problems.lock().unwrap();
        if problems.is_empty() {
            None
        } else {
            Some(problems.remove(0))
        }
    }
}

/// Look up the Python Connection object for an SSL via the weakref stored
/// in its ex_data.
fn conn_from_ssl<'py>(py: Python<'py>, ssl: &SslRef) -> Option<Bound<'py, PyAny>> {
    let weak = ssl.ex_data(conn_obj_idx())?;
    let obj = weak.bind(py).call0().ok()?;
    if obj.is_none() {
        None
    } else {
        Some(obj)
    }
}

unsafe fn conn_from_ssl_ptr<'py>(
    py: Python<'py>,
    ssl: *const ffi::SSL,
) -> Option<Bound<'py, PyAny>> {
    conn_from_ssl(py, SslRef::from_ptr(ssl as *mut ffi::SSL))
}

unsafe fn ctx_state_from_ssl_ptr<'a>(ssl: *const ffi::SSL) -> Option<&'a Arc<CtxState>> {
    let ctx = ffi::SSL_get_SSL_CTX(ssl);
    if ctx.is_null() {
        return None;
    }
    SslContextRef::from_ptr(ctx).ex_data(ctx_state_idx())
}

unsafe fn conn_state_from_ssl_ptr<'a>(ssl: *const ffi::SSL) -> Option<&'a Arc<ConnState>> {
    SslRef::from_ptr(ssl as *mut ffi::SSL).ex_data(conn_state_idx())
}

// ---------------------------------------------------------------------------
// Safe callback closures
// ---------------------------------------------------------------------------

/// Build the verify-callback closure shared by `Context.set_verify` and
/// `Connection.set_verify`. `push_problem` routes callback exceptions to
/// the right (context or connection) problem queue.
fn make_verify_callback(
    callback: Py<PyAny>,
    push_problem: impl Fn(PyErr) + Send + Sync + 'static,
) -> impl Fn(bool, &mut X509StoreContextRef) -> bool + Send + Sync + 'static {
    move |ok, store_ctx| {
        Python::attach(|py| {
            // rust-openssl offers no safe accessor for the SSL associated
            // with an X509StoreContext during a handshake.
            let ssl = unsafe {
                let idx = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
                ffi::X509_STORE_CTX_get_ex_data(store_ctx.as_ptr(), idx) as *mut ffi::SSL
            };
            if ssl.is_null() {
                return false;
            }
            let conn = match unsafe { conn_from_ssl_ptr(py, ssl) } {
                Some(c) => c,
                None => return false,
            };

            let result: PyResult<bool> = (|| {
                let cert = store_ctx
                    .current_cert()
                    .map(|c| c.to_owned())
                    .expect("verify callback without a current certificate");
                let cert = Py::new(py, X509::from_openssl(cert))?;
                let error_number = store_ctx.error().as_raw();
                let error_depth = store_ctx.error_depth();
                let r = callback.bind(py).call1((
                    conn,
                    cert,
                    error_number,
                    error_depth,
                    ok as c_int,
                ))?;
                r.is_truthy()
            })();

            match result {
                Ok(true) => {
                    store_ctx.set_error(X509VerifyResult::OK);
                    true
                }
                Ok(false) => false,
                Err(e) => {
                    push_problem(e);
                    false
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Raw trampolines (callbacks rust-openssl does not expose, or exposes with
// signatures that cannot express pyOpenSSL's semantics)
// ---------------------------------------------------------------------------

/// Info callback: not exposed by rust-openssl at all.
unsafe fn run_info_callback(ssl: *const ffi::SSL, where_: c_int, ret: c_int, from_conn: bool) {
    Python::attach(|py| {
        let cb = if from_conn {
            conn_state_from_ssl_ptr(ssl)
                .and_then(|s| s.info_cb.lock().unwrap().as_ref().map(|c| c.clone_ref(py)))
        } else {
            ctx_state_from_ssl_ptr(ssl)
                .and_then(|s| s.info_cb.lock().unwrap().as_ref().map(|c| c.clone_ref(py)))
        };
        let (cb, conn) = match (cb, conn_from_ssl_ptr(py, ssl)) {
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

/// ALPN selection: rust-openssl's safe callback must return a subslice of
/// the client's protocol list, but pyOpenSSL's callback may return
/// arbitrary bytes, so we manage the output buffer ourselves.
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
            let cb = match ctx_state_from_ssl_ptr(ssl).and_then(|s| {
                s.alpn_select_cb.lock().unwrap().as_ref().map(|c| c.clone_ref(py))
            }) {
                Some(cb) => cb,
                None => return Ok(ffi::SSL_TLSEXT_ERR_NOACK),
            };
            let conn = match conn_from_ssl_ptr(py, ssl) {
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
            } else if let Ok(b) = outbytes.cast::<PyBytes>() {
                b.as_bytes().to_vec()
            } else {
                return Err(PyTypeError::new_err(
                    "ALPN callback must return a bytestring or the \
                     special NO_OVERLAPPING_PROTOCOLS sentinel value.",
                ));
            };

            // Save the callback result on the connection state to make
            // sure that it doesn't get freed before OpenSSL uses it. Then,
            // return it in the appropriate output parameters.
            let state = match conn_state_from_ssl_ptr(ssl) {
                Some(s) => s,
                None => return Ok(ffi::SSL_TLSEXT_ERR_ALERT_FATAL),
            };
            let mut buf = state.alpn_buf.lock().unwrap();
            *buf = Some(outvec);
            let stored = buf.as_ref().unwrap();
            *outlen = stored.len() as c_uchar;
            *out = stored.as_ptr();
            if !any_accepted {
                return Ok(ffi::SSL_TLSEXT_ERR_NOACK);
            }
            Ok(ffi::SSL_TLSEXT_ERR_OK)
        })();
        match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(s) = ctx_state_from_ssl_ptr(ssl) {
                    s.push_problem(e);
                }
                ffi::SSL_TLSEXT_ERR_ALERT_FATAL
            }
        }
    })
}

/// OCSP status callback: rust-openssl's safe `set_status_callback` returns
/// only Ok/fatal, but pyOpenSSL needs the full OK/NOACK/fatal (server) and
/// positive/zero/negative (client) result spaces.
unsafe extern "C" fn ocsp_cb(ssl: *mut ffi::SSL, _arg: *mut c_void) -> c_int {
    Python::attach(|py| {
        let state = match ctx_state_from_ssl_ptr(ssl) {
            Some(s) => s,
            None => return if ffi::SSL_is_server(ssl) == 1 { 3 } else { -1 },
        };
        let is_server = state.ocsp_is_server.load(std::sync::atomic::Ordering::Relaxed);
        let cb = match state.ocsp_cb.lock().unwrap().as_ref().map(|c| c.clone_ref(py)) {
            Some(cb) => cb,
            None => return if is_server { 3 } else { -1 },
        };
        let data = state
            .ocsp_data
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| c.clone_ref(py));
        let conn = match conn_from_ssl_ptr(py, ssl) {
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
                let ocsp_data = ocsp_data.cast::<PyBytes>().map_err(|_| {
                    PyTypeError::new_err("OCSP callback must return a bytestring.")
                })?;
                let bytes = ocsp_data.as_bytes();
                if bytes.is_empty() {
                    return Ok(3); // SSL_TLSEXT_ERR_NOACK
                }
                // `SslRef::set_ocsp_status` copies the response and hands
                // ownership to OpenSSL for us.
                SslRef::from_ptr_mut(ssl)
                    .set_ocsp_status(bytes)
                    .map_err(|e| err_stack_to_py(py, e))?;
                Ok(0) // SSL_TLSEXT_ERR_OK
            })();
            match result {
                Ok(r) => r,
                Err(e) => {
                    state.push_problem(e);
                    2 // SSL_TLSEXT_ERR_ALERT_FATAL
                }
            }
        } else {
            let result: PyResult<c_int> = (|| {
                let ocsp_data = SslRef::from_ptr(ssl).ocsp_status().unwrap_or(b"");
                let valid = cb
                    .bind(py)
                    .call1((conn, PyBytes::new(py, ocsp_data), data))?;
                Ok(valid.is_truthy()? as c_int)
            })();
            match result {
                Ok(r) => r,
                Err(e) => {
                    state.push_problem(e);
                    -1
                }
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
    session: Option<SslSession>,
}

#[pymethods]
impl Session {
    #[new]
    fn new() -> Session {
        Session { session: None }
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
    builder: SslContextBuilder,
    pub used: bool,
    state: Arc<CtxState>,
    passphrase_helper: Option<Box<PassphraseHelper>>,
    app_data: Py<PyAny>,
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
        self.builder.as_ptr()
    }

    /// View the builder as a built context. Sound: the builder and the
    /// built context are the same C object; rust-openssl just gates the
    /// setter methods on the builder type.
    fn ctx_ref(&self) -> &SslContextRef {
        unsafe { SslContextRef::from_ptr(self.builder.as_ptr()) }
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
        &mut self,
        py: Python<'_>,
        cafile: Option<&Bound<'_, PyAny>>,
        capath: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let cafile = match cafile {
            Some(f) if !f.is_none() => Some(path_from_arg(py, f)?),
            _ => None,
        };
        let capath = match capath {
            Some(p) if !p.is_none() => Some(path_from_arg(py, p)?),
            _ => None,
        };
        self.builder
            .load_verify_locations(cafile.as_deref(), capath.as_deref())
            .map_err(|e| err_stack_to_py(py, e))
    }
}

/// Convert a str/bytes/PathLike Python argument to a PathBuf.
fn path_from_arg(py: Python<'_>, arg: &Bound<'_, PyAny>) -> PyResult<std::path::PathBuf> {
    let bytes = util::path_bytes(py, arg)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
    }
    #[cfg(not(unix))]
    {
        let s = String::from_utf8(bytes)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(std::path::PathBuf::from(s))
    }
}

/// Convert an X509-or-cryptography-Certificate argument into a Py<X509>,
/// warning if a pyOpenSSL X509 was passed.
fn as_x509(py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<Py<X509>> {
    if let Ok(c) = cert.cast::<X509>() {
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
        Ok(converted.cast_into::<X509>()?.unbind())
    }
}

/// Convert a PKey-or-cryptography-key argument into a Py<PKey>, warning if
/// a pyOpenSSL PKey was passed.
fn as_pkey(py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<Py<PKey>> {
    if let Ok(k) = pkey.cast::<PKey>() {
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
        Ok(converted.cast_into::<PKey>()?.unbind())
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
        let (ssl_method, version): (SslMethod, Option<c_int>) = match method {
            SSLV23_METHOD => (SslMethod::tls(), None),
            TLSV1_METHOD => (SslMethod::tls(), Some(ffi::TLS1_VERSION)),
            TLSV1_1_METHOD => (SslMethod::tls(), Some(ffi::TLS1_1_VERSION)),
            TLSV1_2_METHOD => (SslMethod::tls(), Some(ffi::TLS1_2_VERSION)),
            TLS_METHOD => (SslMethod::tls(), None),
            TLS_SERVER_METHOD => (SslMethod::tls_server(), None),
            TLS_CLIENT_METHOD => (SslMethod::tls_client(), None),
            DTLS_METHOD => (SslMethod::dtls(), None),
            DTLS_SERVER_METHOD => (SslMethod::dtls_server(), None),
            DTLS_CLIENT_METHOD => (SslMethod::dtls_client(), None),
            _ => return Err(PyValueError::new_err("No such protocol")),
        };
        let mut builder =
            SslContextBuilder::new(ssl_method).map_err(|e| err_stack_to_py(py, e))?;

        let state = Arc::new(CtxState::default());
        builder.set_ex_data(ctx_state_idx(), state.clone());
        builder
            .set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
        if let Some(version) = version {
            // SslVersion cannot be constructed from a raw protocol number,
            // so set the pin via openssl-sys.
            unsafe {
                openssl_assert!(
                    py,
                    Error,
                    ffi::SSL_CTX_set_min_proto_version(builder.as_ptr(), version) == 1
                );
                openssl_assert!(
                    py,
                    Error,
                    ffi::SSL_CTX_set_max_proto_version(builder.as_ptr(), version) == 1
                );
            }
        }
        Ok(Context {
            builder,
            used: false,
            state,
            passphrase_helper: None,
            app_data: py.None(),
        })
    }

    /// Set the minimum supported protocol version.
    fn set_min_proto_version(&self, py: Python<'_>, version: c_int) -> PyResult<()> {
        self.require_not_used()?;
        // SslVersion cannot be constructed from a raw int, so this goes
        // through openssl-sys.
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_min_proto_version(self.builder.as_ptr(), version) }
                == 1
        );
        Ok(())
    }

    /// Set the maximum supported protocol version.
    fn set_max_proto_version(&self, py: Python<'_>, version: c_int) -> PyResult<()> {
        self.require_not_used()?;
        openssl_assert!(
            py,
            Error,
            unsafe { ffi::SSL_CTX_set_max_proto_version(self.builder.as_ptr(), version) }
                == 1
        );
        Ok(())
    }

    /// Let SSL know where we can find trusted certificates for the
    /// certificate chain. Note that the certificates have to be in PEM
    /// format.
    #[pyo3(signature = (cafile, capath=None))]
    fn load_verify_locations(
        &mut self,
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
        // SSL_CTX_set_default_passwd_cb has no safe wrapper (rust-openssl
        // only has per-call PEM passphrase closures, which
        // SSL_CTX_use_PrivateKey_file does not consult).
        unsafe {
            ffi_ext::SSL_CTX_set_default_passwd_cb(
                self.builder.as_ptr(),
                Some(crypto::raw_pem_password_cb),
            );
            ffi_ext::SSL_CTX_set_default_passwd_cb_userdata(
                self.builder.as_ptr(),
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
                slf.call_method1("_fallback_default_verify_paths", (files, dirs))?;
            }
        }
        Ok(())
    }

    /// Call ``SSL_CTX_set_default_verify_paths``; the testable C-call part
    /// of `set_default_verify_paths`.
    fn _set_default_verify_paths_openssl(&mut self, py: Python<'_>) -> PyResult<()> {
        self.builder
            .set_default_verify_paths()
            .map_err(|e| err_stack_to_py(py, e))
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
                slf.borrow_mut()
                    .load_verify_locations_impl(py, Some(&cafile), None)?;
                break;
            }
        }
        for capath in dir_path.try_iter()? {
            let capath = capath?;
            if os_path.call_method1("isdir", (&capath,))?.is_truthy()? {
                slf.borrow_mut()
                    .load_verify_locations_impl(py, None, Some(&capath))?;
                break;
            }
        }
        Ok(())
    }

    /// Load a certificate chain from a file.
    fn use_certificate_chain_file(
        &mut self,
        py: Python<'_>,
        certfile: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certfile = path_from_arg(py, certfile)?;
        self.builder
            .set_certificate_chain_file(certfile)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Load a certificate from a file
    #[pyo3(signature = (certfile, filetype=crypto::FILETYPE_PEM))]
    fn use_certificate_file(
        &mut self,
        py: Python<'_>,
        certfile: &Bound<'_, PyAny>,
        filetype: c_int,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certfile = path_from_arg(py, certfile)?;
        self.builder
            .set_certificate_file(certfile, SslFiletype::from_raw(filetype))
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Load a certificate from a X509 object
    fn use_certificate(&mut self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cert = as_x509(py, cert)?;
        let cert_ref = cert.borrow(py);
        self.builder
            .set_certificate(cert_ref.as_x509_ref())
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Add certificate to chain
    fn add_extra_chain_cert(
        &mut self,
        py: Python<'_>,
        certobj: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let certobj = as_x509(py, certobj)?;
        let copy = certobj.borrow(py).clone_openssl();
        self.builder
            .add_extra_chain_cert(copy)
            .map_err(|e| err_stack_to_py(py, e))
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
        let keyfile = path_from_arg(py, keyfile)?;
        let result = self
            .builder
            .set_private_key_file(keyfile, SslFiletype::from_raw(filetype));
        if result.is_err() {
            return Err(self.raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// Load a private key from a PKey object
    fn use_privatekey(&mut self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let pkey = as_pkey(py, pkey)?;
        let result = {
            let pkey_ref = pkey.borrow(py);
            self.builder.set_private_key(pkey_ref.as_private_ref())
        };
        if result.is_err() {
            return Err(self.raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// Check if the private key (loaded with `use_privatekey`) matches the
    /// certificate (loaded with `use_certificate`)
    fn check_privatekey(&self, py: Python<'_>) -> PyResult<()> {
        self.builder
            .check_private_key()
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Load the trusted certificates that will be sent to the client.
    fn load_client_ca(&mut self, py: Python<'_>, cafile: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cafile = util::text_to_bytes_and_warn(py, "cafile", cafile)?;
        let cafile = cafile.bind(py).extract::<Vec<u8>>()?;
        let cafile = cstring(py, &cafile)?;
        // SSL_load_client_CA_file has no safe wrapper.
        let ca_list = unsafe {
            let ca_list = ffi::SSL_load_client_CA_file(cafile.as_ptr());
            openssl_assert!(py, Error, !ca_list.is_null());
            Stack::<SslX509Name>::from_ptr(ca_list)
        };
        self.builder.set_client_ca_list(ca_list);
        Ok(())
    }

    /// Set the session id to *buf* within which a session can be reused
    /// for this Context object.
    fn set_session_id(&mut self, py: Python<'_>, buf: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        let buf = buf.bind(py).extract::<Vec<u8>>()?;
        self.builder
            .set_session_id_context(&buf)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the behavior of the session cache used by all connections using
    /// this Context. The previously set mode is returned.
    fn set_session_cache_mode(&mut self, mode: &Bound<'_, PyAny>) -> PyResult<i64> {
        self.require_not_used()?;
        let mode: c_long = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        let previous = self
            .builder
            .set_session_cache_mode(SslSessionCacheMode::from_bits_retain(mode));
        Ok(previous.bits() as i64)
    }

    /// Get the current session cache mode.
    fn get_session_cache_mode(&self) -> c_long {
        // No safe getter exists for the session cache mode.
        unsafe { ffi_ext::SSL_CTX_get_session_cache_mode(self.builder.as_ptr()) }
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
        let mode = SslVerifyMode::from_bits_retain(mode);
        match callback {
            None => {
                self.builder.set_verify(mode);
            }
            Some(callback) => {
                if !callback.is_callable() {
                    return Err(PyTypeError::new_err("callback must be callable"));
                }
                let state = self.state.clone();
                self.builder.set_verify_callback(
                    mode,
                    make_verify_callback(callback.clone().unbind(), move |e| {
                        state.push_problem(e)
                    }),
                );
            }
        }
        Ok(())
    }

    /// Set the maximum depth for the certificate chain verification that
    /// shall be allowed for this Context object.
    fn set_verify_depth(&mut self, depth: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let depth: u32 = depth
            .extract()
            .map_err(|_| PyTypeError::new_err("depth must be an integer"))?;
        self.builder.set_verify_depth(depth);
        Ok(())
    }

    /// Retrieve the Context object's verify mode, as set by `set_verify`.
    fn get_verify_mode(&self) -> c_int {
        // SslVerifyMode does not model SSL_VERIFY_CLIENT_ONCE, and
        // rust-openssl's verify_mode() panics on unknown bits.
        unsafe { ffi::SSL_CTX_get_verify_mode(self.builder.as_ptr()) }
    }

    /// Retrieve the Context object's verify depth, as set by
    /// `set_verify_depth`.
    fn get_verify_depth(&self) -> c_int {
        // No safe getter exists for the verify depth.
        unsafe { ffi_ext::SSL_CTX_get_verify_depth(self.builder.as_ptr()) }
    }

    /// Load parameters for Ephemeral Diffie-Hellman
    fn load_tmp_dh(&mut self, py: Python<'_>, dhfile: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let dhfile = path_from_arg(py, dhfile)?;
        let pem = std::fs::read(&dhfile).map_err(|e| {
            Error::new_err(format!("could not read DH parameters file: {}", e))
        })?;
        let dh =
            openssl::dh::Dh::params_from_pem(&pem).map_err(|e| err_stack_to_py(py, e))?;
        self.builder
            .set_tmp_dh(&dh)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Select a curve to use for ECDHE key exchange.
    fn set_tmp_ecdh(&mut self, py: Python<'_>, curve: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let nid = if let Ok(c) = curve.cast::<crypto::EllipticCurve>() {
            util::warn(
                py,
                "Passing pyOpenSSL elliptic curves to set_tmp_ecdh is \
                 deprecated. You should use cryptography's elliptic curve \
                 types instead.",
                "DeprecationWarning",
                3,
            )?;
            openssl::nid::Nid::from_raw(c.borrow().nid)
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
            openssl::nid::Nid::from_raw(nid)
        };
        let key =
            openssl::ec::EcKey::from_curve_name(nid).map_err(|e| err_stack_to_py(py, e))?;
        // The cffi implementation did not check the result of
        // SSL_CTX_set_tmp_ecdh (some builtin curves are not usable for
        // TLS and are silently rejected); drain the error queue instead
        // of raising.
        if self.builder.set_tmp_ecdh(&key).is_err() {
            let _ = ErrorStack::get();
        }
        Ok(())
    }

    /// Set the list of ciphers to be used in this context.
    fn set_cipher_list(&mut self, py: Python<'_>, cipher_list: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let cipher_list = util::text_to_bytes_and_warn(py, "cipher_list", cipher_list)?;
        let cipher_list = cipher_list
            .bind(py)
            .cast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("cipher_list must be a byte string."))?
            .as_bytes()
            .to_vec();
        let cipher_str = std::str::from_utf8(&cipher_list)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.builder
            .set_cipher_list(cipher_str)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the list of TLS 1.3 ciphers to be used in this context.
    fn set_tls13_ciphersuites(
        &mut self,
        py: Python<'_>,
        ciphersuites: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let ciphersuites = ciphersuites
            .cast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("ciphersuites must be a byte string."))?
            .as_bytes()
            .to_vec();
        let suites_str = std::str::from_utf8(&ciphersuites)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.builder
            .set_ciphersuites(suites_str)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the list of preferred client certificate signers for this
    /// server context.
    fn set_client_ca_list(
        &mut self,
        py: Python<'_>,
        certificate_authorities: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let mut stack = Stack::<SslX509Name>::new().map_err(|e| err_stack_to_py(py, e))?;
        for ca_name in certificate_authorities.try_iter()? {
            let ca_name = ca_name?;
            let ca_name = ca_name.cast::<X509Name>().map_err(|_| {
                PyTypeError::new_err(format!(
                    "client CAs must be X509Name objects, not {} objects",
                    ca_name
                        .get_type()
                        .name()
                        .map(|n| n.to_string())
                        .unwrap_or_default()
                ))
            })?;
            let copy = {
                let borrowed = ca_name.borrow();
                borrowed
                    .name_ref()?
                    .to_owned()
                    .map_err(|e| err_stack_to_py(py, e))?
            };
            stack.push(copy).map_err(|e| err_stack_to_py(py, e))?;
        }
        self.builder.set_client_ca_list(stack);
        Ok(())
    }

    /// Add the CA certificate to the list of preferred signers for this
    /// context.
    fn add_client_ca(
        &mut self,
        py: Python<'_>,
        certificate_authority: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.require_not_used()?;
        let cert = as_x509(py, certificate_authority)?;
        let cert_ref = cert.borrow(py);
        self.builder
            .add_client_ca(cert_ref.as_x509_ref())
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the timeout for newly created sessions for this Context object
    /// to *timeout*.
    fn set_timeout(&self, timeout: &Bound<'_, PyAny>) -> PyResult<c_long> {
        self.require_not_used()?;
        let timeout: c_long = timeout
            .extract()
            .map_err(|_| PyTypeError::new_err("timeout must be an integer"))?;
        // SSL_CTX_set_timeout has no safe wrapper.
        Ok(unsafe { ffi_ext::SSL_CTX_set_timeout(self.builder.as_ptr(), timeout) })
    }

    /// Retrieve session timeout, as set by `set_timeout`. The default is
    /// 300 seconds.
    fn get_timeout(&self) -> c_long {
        // SSL_CTX_get_timeout has no safe wrapper.
        unsafe { ffi_ext::SSL_CTX_get_timeout(self.builder.as_ptr()) }
    }

    /// Set the information callback to *callback*. This function will be
    /// called from time to time during SSL handshakes.
    fn set_info_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        *self.state.info_cb.lock().unwrap() = Some(callback.clone().unbind());
        // SSL_CTX_set_info_callback has no safe wrapper.
        unsafe {
            ffi_ext::SSL_CTX_set_info_callback(self.builder.as_ptr(), Some(info_cb_ctx));
        }
        Ok(())
    }

    /// Set the TLS key logging callback to *callback*. This function will
    /// be called whenever TLS key material is generated or received.
    fn set_keylog_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let callback = callback.clone().unbind();
        self.builder.set_keylog_callback(move |ssl, line| {
            Python::attach(|py| {
                let conn = match conn_from_ssl(py, ssl) {
                    Some(c) => c,
                    None => return,
                };
                if let Err(e) = callback
                    .bind(py)
                    .call1((conn, PyBytes::new(py, line.as_bytes())))
                {
                    e.write_unraisable(py, None);
                }
            })
        });
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
        let store: &X509StoreRef = self.ctx_ref().cert_store();
        unsafe {
            // pyOpenSSL hands out an owned store object; rust-openssl only
            // exposes a borrow, and X509_STORE_up_ref has no safe wrapper.
            ffi_ext::X509_STORE_up_ref(store.as_ptr());
            Some(X509Store::from_raw(store.as_ptr()))
        }
    }

    /// Add options. Options set before are not cleared! This method should
    /// be used with the `OP_*` constants.
    fn set_options(&mut self, options: &Bound<'_, PyAny>) -> PyResult<u64> {
        self.require_not_used()?;
        let options: u64 = options
            .extract()
            .map_err(|_| PyTypeError::new_err("options must be an integer"))?;
        let new = self
            .builder
            .set_options(SslOptions::from_bits_retain(options as _));
        Ok(new.bits() as u64)
    }

    /// Add modes via bitmask. Modes set before are not cleared! This
    /// method should be used with the `MODE_*` constants.
    fn set_mode(&mut self, mode: &Bound<'_, PyAny>) -> PyResult<i64> {
        self.require_not_used()?;
        let mode: c_long = mode
            .extract()
            .map_err(|_| PyTypeError::new_err("mode must be an integer"))?;
        let new = self.builder.set_mode(SslMode::from_bits_retain(mode));
        Ok(new.bits() as i64)
    }

    /// Modes previously set cannot be overwritten without being cleared
    /// first. This method should be used to clear existing modes.
    fn clear_mode(&self, mode_to_clear: c_long) -> PyResult<i64> {
        self.require_not_used()?;
        // SSL_CTX_clear_mode has no safe wrapper.
        Ok(
            unsafe { ffi_ext::SSL_CTX_clear_mode(self.builder.as_ptr(), mode_to_clear) }
                as i64,
        )
    }

    /// Specify a callback function to be called when clients specify a
    /// server name.
    fn set_tlsext_servername_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let callback = callback.clone().unbind();
        self.builder
            .set_servername_callback(move |ssl: &mut SslRef, _alert| {
                Python::attach(|py| {
                    let conn = match conn_from_ssl(py, ssl) {
                        Some(c) => c,
                        None => return Ok(()),
                    };
                    match callback.bind(py).call1((conn,)) {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            // The Python implementation routes this
                            // through sys.excepthook.
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
                            Err(SniError::ALERT_FATAL)
                        }
                    }
                })
            });
        Ok(())
    }

    /// Enable support for negotiating SRTP keying material.
    fn set_tlsext_use_srtp(&mut self, py: Python<'_>, profiles: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let profiles = profiles
            .cast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("profiles must be a byte string."))?
            .as_bytes()
            .to_vec();
        let profiles_str = std::str::from_utf8(&profiles)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.builder
            .set_tlsext_use_srtp(profiles_str)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Specify the protocols that the client is prepared to speak after
    /// the TLS connection has been negotiated using Application Layer
    /// Protocol Negotiation.
    fn set_alpn_protos(&mut self, py: Python<'_>, protos: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let protostr = build_alpn_wire_format(py, protos)?;
        self.builder
            .set_alpn_protos(&protostr)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Specify a callback function that will be called on the server when
    /// a client offers protocols using ALPN.
    fn set_alpn_select_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        *self.state.alpn_select_cb.lock().unwrap() = Some(callback.clone().unbind());
        // The safe `set_alpn_select_callback` requires the selected
        // protocol to be a subslice of the client's offer; pyOpenSSL's
        // callback may return arbitrary bytes, so register a raw callback.
        unsafe {
            ffi::SSL_CTX_set_alpn_select_cb__fixed_rust(
                self.builder.as_ptr(),
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
        let callback = callback.clone().unbind();
        let state = self.state.clone();
        self.builder.set_cookie_generate_cb(move |ssl, out| {
            Python::attach(|py| {
                let conn = match conn_from_ssl(py, ssl) {
                    Some(c) => c,
                    None => return Err(ErrorStack::get()),
                };
                let result: PyResult<usize> = (|| {
                    let cookie = callback.bind(py).call1((conn,))?;
                    let cookie = cookie.extract::<Vec<u8>>()?;
                    if cookie.len() > ffi_ext::DTLS1_COOKIE_LENGTH
                        || cookie.len() > out.len()
                    {
                        return Err(PyValueError::new_err(format!(
                            "Cookie too long (got {} bytes, max {})",
                            cookie.len(),
                            ffi_ext::DTLS1_COOKIE_LENGTH
                        )));
                    }
                    out[..cookie.len()].copy_from_slice(&cookie);
                    Ok(cookie.len())
                })();
                match result {
                    Ok(n) => Ok(n),
                    Err(e) => {
                        state.push_problem(e);
                        // "a zero return value can be used to abort the
                        // handshake"; an error from the closure aborts.
                        Err(ErrorStack::get())
                    }
                }
            })
        });
        Ok(())
    }

    fn set_cookie_verify_callback(&mut self, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        self.require_not_used()?;
        let callback = callback.clone().unbind();
        let state = self.state.clone();
        self.builder.set_cookie_verify_cb(move |ssl, cookie| {
            Python::attach(|py| {
                let conn = match conn_from_ssl(py, ssl) {
                    Some(c) => c,
                    None => return false,
                };
                let result: PyResult<bool> = (|| {
                    let r = callback.bind(py).call1((conn, PyBytes::new(py, cookie)))?;
                    r.is_truthy()
                })();
                match result {
                    Ok(b) => b,
                    Err(e) => {
                        state.push_problem(e);
                        false
                    }
                }
            })
        });
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
        *self.state.ocsp_cb.lock().unwrap() = Some(callback.clone().unbind());
        *self.state.ocsp_data.lock().unwrap() = data.map(|d| d.clone().unbind());
        self.state
            .ocsp_is_server
            .store(is_server, std::sync::atomic::Ordering::Relaxed);
        unsafe {
            let rc = ffi::SSL_CTX_set_tlsext_status_cb(self.builder.as_ptr(), Some(ocsp_cb));
            openssl_assert!(py, Error, rc == 1);
            let rc = ffi::SSL_CTX_set_tlsext_status_arg(
                self.builder.as_ptr(),
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
// PyBio: the stream type backing SslStream
// ---------------------------------------------------------------------------

/// The transport behind a Connection: either the Python socket's file
/// descriptor, or a pair of in-memory buffers driven by
/// `bio_read`/`bio_write` (replacing the cffi implementation's memory-BIO
/// pair).
pub enum PyBio {
    Fd(c_int),
    Memory {
        /// Ciphertext from the application, waiting to be read by OpenSSL.
        incoming: VecDeque<u8>,
        /// Ciphertext written by OpenSSL, waiting for `bio_read`.
        outgoing: VecDeque<u8>,
        /// Set by `bio_shutdown`: reads report EOF instead of WouldBlock.
        eof: bool,
    },
}

impl PyBio {
    fn new_memory() -> PyBio {
        PyBio::Memory {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            eof: false,
        }
    }
}

impl Read for PyBio {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PyBio::Fd(fd) => {
                let n =
                    unsafe { libc::read(*fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }
            PyBio::Memory { incoming, eof, .. } => {
                if incoming.is_empty() {
                    if *eof {
                        // Mirrors BIO_set_mem_eof_return(0).
                        Ok(0)
                    } else {
                        // Translated by rust-openssl's BIO into a retry
                        // flag, surfacing as WANT_READ.
                        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                    }
                } else {
                    let n = std::cmp::min(buf.len(), incoming.len());
                    for (i, b) in incoming.drain(..n).enumerate() {
                        buf[i] = b;
                    }
                    Ok(n)
                }
            }
        }
    }
}

impl Write for PyBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PyBio::Fd(fd) => {
                let n = unsafe { libc::write(*fd, buf.as_ptr() as *const c_void, buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }
            PyBio::Memory { outgoing, .. } => {
                outgoing.extend(buf);
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

#[pyclass(module = "OpenSSL.SSL", subclass, weakref, dict)]
pub struct Connection {
    /// The stream is locked only for I/O operations (handshake,
    /// read/write/shutdown, buffer access); the lock is acquired with the
    /// GIL released so that callbacks re-entering Python cannot deadlock.
    stream: Arc<Mutex<SslStream<PyBio>>>,
    /// Raw handle for lock-free, read-mostly `SslRef` access (callbacks
    /// re-enter Connection getters while the stream lock is held).
    ssl_ptr: CPtr<ffi::SSL>,
    context: Py<Context>,
    socket: Option<Py<PyAny>>,
    app_data: Py<PyAny>,
    is_memory: bool,
    state: Arc<ConnState>,
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
    /// A read-only view of the SSL. Used (instead of locking the stream)
    /// so that callbacks which re-enter Connection getters during a
    /// handshake do not deadlock; sound for the same reasons the cffi
    /// implementation was (GIL-serialized access).
    fn ssl_ref(&self) -> &SslRef {
        unsafe { SslRef::from_ptr(self.ssl_ptr.get()) }
    }

    /// A mutable view of the SSL, for safe rust-openssl setters
    /// (rust-openssl's `SslStream` does not expose a `&mut SslRef`).
    #[allow(clippy::mut_from_ref)]
    fn ssl_mut(&self) -> &mut SslRef {
        unsafe { SslRef::from_ptr_mut(self.ssl_ptr.get()) }
    }

    /// Register a weakref to the Python Connection object in the SSL's
    /// ex_data so that callbacks can find it.
    fn register(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        let this = slf.borrow();
        if this
            .state
            .registered
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }
        let weakref = py.import("weakref")?.call_method1("ref", (slf,))?;
        this.ssl_mut().set_ex_data(conn_obj_idx(), weakref.unbind());
        Ok(())
    }

    /// Run a blocking SSL operation: releases the GIL, then acquires the
    /// stream lock (in that order, so a thread blocked on the lock never
    /// holds the GIL while a callback in another thread needs it).
    fn with_stream<T: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&mut SslStream<PyBio>) -> T + Send,
    ) -> T {
        let stream = self.stream.clone();
        py.detach(move || {
            let mut guard = stream.lock().unwrap();
            f(&mut guard)
        })
    }

    fn pop_problem(&self, py: Python<'_>) -> Option<PyErr> {
        if let Some(problem) = self.context.borrow(py).state.pop_problem() {
            let _ = ErrorStack::get();
            return Some(problem);
        }
        if let Some(problem) = self.state.pop_problem() {
            let _ = ErrorStack::get();
            return Some(problem);
        }
        None
    }

    /// Map a rust-openssl `ssl::Error` onto pyOpenSSL's exception
    /// hierarchy, preferring any exception raised inside a Python
    /// callback.
    fn map_ssl_error(&self, py: Python<'_>, e: &openssl::ssl::Error) -> PyErr {
        use openssl::ssl::ErrorCode;
        if let Some(problem) = self.pop_problem(py) {
            return problem;
        }
        match e.code() {
            ErrorCode::WANT_READ => WantReadError::new_err(()),
            ErrorCode::WANT_WRITE => WantWriteError::new_err(()),
            ErrorCode::ZERO_RETURN => ZeroReturnError::new_err(()),
            code if code.as_raw() == ffi::SSL_ERROR_WANT_X509_LOOKUP => {
                WantX509LookupError::new_err(())
            }
            ErrorCode::SYSCALL => {
                let errno = e.io_error().and_then(|io| io.raw_os_error()).unwrap_or(0);
                let queue_empty = e.ssl_error().map_or(true, |s| s.errors().is_empty());
                if queue_empty || errno != 0 {
                    if errno != 0 {
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
                    util::error_stack_to_exception(
                        py,
                        &py.get_type::<Error>(),
                        e.ssl_error().unwrap(),
                    )
                }
            }
            ErrorCode::SSL => {
                // In 3.0.x an unexpected EOF no longer triggers a syscall
                // error, but we maintain compatibility with the historical
                // pyOpenSSL behavior by mapping it to SysCallError.
                let reason = e
                    .ssl_error()
                    .and_then(|s| {
                        s.errors().first().map(|err| ffi::ERR_GET_REASON(err.code() as _))
                    })
                    .unwrap_or(0);
                if reason == ffi_ext::SSL_R_UNEXPECTED_EOF_WHILE_READING {
                    SysCallError::new_err((-1, "Unexpected EOF"))
                } else if let Some(stack) = e.ssl_error() {
                    util::error_stack_to_exception(py, &py.get_type::<Error>(), stack)
                } else {
                    openssl_error!(py, Error)
                }
            }
            _ => match e.ssl_error() {
                Some(stack) => {
                    util::error_stack_to_exception(py, &py.get_type::<Error>(), stack)
                }
                None => openssl_error!(py, Error),
            },
        }
    }

    fn socket_or_typeerror<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.socket {
            Some(s) => Ok(s.bind(py).clone()),
            None => Err(PyTypeError::new_err("Connection sock was not None")),
        }
    }

    fn require_memory_bio(&self) -> PyResult<()> {
        if !self.is_memory {
            return Err(PyTypeError::new_err("Connection sock was not None"));
        }
        Ok(())
    }

    fn cert_stack_to_list(
        py: Python<'_>,
        certs: &openssl::stack::StackRef<openssl::x509::X509>,
        as_cryptography: bool,
    ) -> PyResult<Py<PyList>> {
        let result = PyList::empty(py);
        for cert in certs {
            let pycert = Py::new(py, X509::from_openssl(cert.to_owned()))?;
            if as_cryptography {
                result.append(pycert.bind(py).call_method0("to_cryptography")?)?;
            } else {
                result.append(pycert)?;
            }
        }
        Ok(result.unbind())
    }

    /// Error mapping for the few operations (DTLS) which still call
    /// openssl-sys directly and only have a raw SSL_get_error code.
    fn raise_raw_ssl_error(&self, py: Python<'_>, error: c_int, errno: i32) -> PyErr {
        if let Some(problem) = self.pop_problem(py) {
            return problem;
        }
        match error {
            ffi::SSL_ERROR_WANT_READ => WantReadError::new_err(()),
            ffi::SSL_ERROR_WANT_WRITE => WantWriteError::new_err(()),
            ffi::SSL_ERROR_ZERO_RETURN => ZeroReturnError::new_err(()),
            ffi::SSL_ERROR_WANT_X509_LOOKUP => WantX509LookupError::new_err(()),
            ffi::SSL_ERROR_SYSCALL => {
                if unsafe { ffi_ext::ERR_peek_error() } == 0 || errno != 0 {
                    if errno != 0 {
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
            _ => openssl_error!(py, Error),
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
            .cast::<Context>()
            .map_err(|_| PyTypeError::new_err("context must be a Context instance"))?;
        context.borrow_mut().used = true;

        let mut ssl = {
            let ctx = context.borrow();
            Ssl::new(ctx.ctx_ref()).map_err(|e| err_stack_to_py(py, e))?
        };
        // We set SSL_MODE_AUTO_RETRY to handle situations where OpenSSL
        // returns an SSL_ERROR_WANT_READ when processing a
        // non-application data packet even though there is still data on
        // the underlying transport.
        // See https://github.com/openssl/openssl/issues/6234.
        unsafe {
            ffi_ext::SSL_set_mode(ssl.as_ptr(), ffi_ext::SSL_MODE_AUTO_RETRY);
        }

        let state = Arc::new(ConnState::default());
        ssl.set_ex_data(conn_state_idx(), state.clone());
        let ssl_ptr = ssl.as_ptr();

        let socket = socket.filter(|s| !s.is_none());
        let (bio, is_memory, py_socket) = match socket {
            None => (PyBio::new_memory(), true, None),
            Some(socket) => {
                let fd = as_file_descriptor(socket)?;
                (PyBio::Fd(fd), false, Some(socket.clone().unbind()))
            }
        };

        let stream = SslStream::new(ssl, bio).map_err(|e| err_stack_to_py(py, e))?;

        Ok(Connection {
            stream: Arc::new(Mutex::new(stream)),
            ssl_ptr: CPtr(ssl_ptr),
            context: context.clone().unbind(),
            socket: py_socket,
            app_data: py.None(),
            is_memory,
            state,
        })
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
            .cast::<Context>()
            .map_err(|_| PyTypeError::new_err("context must be a Context instance"))?;
        self.ssl_mut()
            .set_ssl_context(context.borrow().ctx_ref())
            .map_err(|e| err_stack_to_py(py, e))?;
        self.context = context.clone().unbind();
        context.borrow_mut().used = true;
        Ok(())
    }

    /// Add options. Options set before are not cleared!
    fn set_options(&self, options: &Bound<'_, PyAny>) -> PyResult<u64> {
        let options: u64 = options
            .extract()
            .map_err(|_| PyTypeError::new_err("options must be an integer"))?;
        // SSL_set_options has no safe per-connection wrapper.
        Ok(unsafe { ffi_ext::SSL_set_options(self.ssl_ptr.get(), options) })
    }

    /// Retrieve the servername extension value if provided in the client
    /// hello message, or None if there wasn't one.
    fn get_servername(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        self.ssl_ref()
            .servername_raw(NameType::HOST_NAME)
            .map(|name| PyBytes::new(py, name).unbind())
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
        Connection::register(slf)?;
        let this = slf.borrow();
        let mode = SslVerifyMode::from_bits_retain(mode);
        match callback {
            None => this.ssl_mut().set_verify(mode),
            Some(callback) => {
                if !callback.is_callable() {
                    return Err(PyTypeError::new_err("callback must be callable"));
                }
                let state = this.state.clone();
                this.ssl_mut().set_verify_callback(
                    mode,
                    make_verify_callback(callback.clone().unbind(), move |e| {
                        state.push_problem(e)
                    }),
                );
            }
        }
        Ok(())
    }

    /// Retrieve the Connection object's verify mode, as set by
    /// `set_verify`.
    fn get_verify_mode(&self) -> c_int {
        // See Context::get_verify_mode.
        unsafe { ffi::SSL_get_verify_mode(self.ssl_ptr.get()) }
    }

    /// Load a certificate from a X509 object
    fn use_certificate(&self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        let cert = as_x509(py, cert)?;
        let cert_ref = cert.borrow(py);
        self.ssl_mut()
            .set_certificate(cert_ref.as_x509_ref())
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Load a private key from a PKey object
    fn use_privatekey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = as_pkey(py, pkey)?;
        let result = {
            let pkey_ref = pkey.borrow(py);
            let key: &PKeyRef<openssl::pkey::Private> = pkey_ref.as_private_ref();
            self.ssl_mut().set_private_key(key)
        };
        if result.is_err() {
            return Err(self.context.borrow_mut(py).raise_passphrase_exception(py));
        }
        Ok(())
    }

    /// For DTLS, set the maximum UDP payload size (*not* including IP/UDP
    /// overhead).
    fn set_ciphertext_mtu(&self, py: Python<'_>, mtu: u32) -> PyResult<()> {
        self.ssl_mut()
            .set_mtu(mtu)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// For DTLS, get the maximum size of unencrypted data you can pass to
    /// `write` without exceeding the MTU (as passed to
    /// `set_ciphertext_mtu`).
    fn get_cleartext_mtu(&self) -> usize {
        // DTLS_get_data_mtu has no safe wrapper.
        unsafe { ffi_ext::DTLS_get_data_mtu(self.ssl_ptr.get()) }
    }

    /// Set the value of the servername extension to send in the client
    /// hello.
    fn set_tlsext_host_name(&self, py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<()> {
        let name = name
            .cast::<PyBytes>()
            .map_err(|_| PyTypeError::new_err("name must be a byte string"))?
            .as_bytes();
        if name.contains(&0) {
            return Err(PyTypeError::new_err("name must not contain NUL byte"));
        }
        let name_str = std::str::from_utf8(name)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.ssl_mut()
            .set_hostname(name_str)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Get the number of bytes that can be safely read from the SSL
    /// buffer (**not** the underlying transport buffer).
    fn pending(&self) -> usize {
        self.ssl_ref().pending()
    }

    /// Send data on the connection. NOTE: If you get one of the WantRead,
    /// WantWrite or WantX509Lookup exceptions on this, you have to call
    /// the method again with the SAME buffer.
    #[pyo3(signature = (buf, flags=0))]
    fn send(slf: &Bound<'_, Self>, buf: &Bound<'_, PyAny>, flags: c_int) -> PyResult<usize> {
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
        Connection::register(slf)?;
        let this = slf.borrow();
        let result = this.with_stream(py, |stream| stream.ssl_write(&data));
        result.map_err(|e| this.map_ssl_error(py, &e))
    }

    /// Alias for send().
    #[pyo3(signature = (buf, flags=0))]
    fn write(slf: &Bound<'_, Self>, buf: &Bound<'_, PyAny>, flags: c_int) -> PyResult<usize> {
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
        Connection::register(slf)?;
        let this = slf.borrow();

        let mut total_sent: usize = 0;
        while total_sent < data.len() {
            // SSL_write's num arg is an int, so we cannot send more than
            // 2**31-1 bytes at once.
            let end = std::cmp::min(data.len(), total_sent + 2147483647);
            let chunk = &data[total_sent..end];
            let result = this.with_stream(py, |stream| stream.ssl_write(chunk));
            match result {
                Ok(n) => total_sent += n,
                Err(e) => return Err(this.map_ssl_error(py, &e)),
            }
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
        Connection::register(slf)?;
        let this = slf.borrow();
        let mut buf = vec![0u8; bufsiz];
        let peek = flags.map_or(false, |f| f & libc::MSG_PEEK != 0);
        let result = this.with_stream(py, |stream| {
            if peek {
                stream.ssl_peek(&mut buf)
            } else {
                stream.ssl_read(&mut buf)
            }
        });
        match result {
            Ok(n) => Ok(PyBytes::new(py, &buf[..n]).unbind()),
            Err(e) => Err(this.map_ssl_error(py, &e)),
        }
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
    ) -> PyResult<usize> {
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
        Connection::register(slf)?;
        let this = slf.borrow();
        let peek = flags.map_or(false, |f| f & libc::MSG_PEEK != 0);
        // The buffer is owned by the caller and alive for the duration of
        // this call; the GIL is released during the read, matching the
        // cffi implementation's behavior.
        let dest =
            unsafe { std::slice::from_raw_parts_mut(pybuf.buf_ptr() as *mut u8, nbytes) };
        let result = this.with_stream(py, |stream| {
            if peek {
                stream.ssl_peek(dest)
            } else {
                stream.ssl_read(dest)
            }
        });
        result.map_err(|e| this.map_ssl_error(py, &e))
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to read bytes from the write end of that memory BIO.
    fn bio_read(&self, py: Python<'_>, bufsiz: &Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
        self.require_memory_bio()?;
        let bufsiz: usize = bufsiz
            .extract()
            .map_err(|_| PyTypeError::new_err("bufsiz must be an integer"))?;
        let data = self.with_stream(py, |stream| match stream.get_mut() {
            PyBio::Memory { outgoing, .. } => {
                let n = std::cmp::min(bufsiz, outgoing.len());
                outgoing.drain(..n).collect::<Vec<u8>>()
            }
            PyBio::Fd(_) => Vec::new(),
        });
        if data.is_empty() {
            return Err(WantReadError::new_err(()));
        }
        Ok(PyBytes::new(py, &data).unbind())
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to add bytes to the read end of that memory BIO. The
    /// Connection can then read the bytes (for example, in response to a
    /// call to `recv`).
    fn bio_write(&self, py: Python<'_>, buf: &Bound<'_, PyAny>) -> PyResult<usize> {
        let buf = util::text_to_bytes_and_warn(py, "buf", buf)?;
        self.require_memory_bio()?;
        let data = util::buffer_to_vec(buf.bind(py))?;
        let n = data.len();
        self.with_stream(py, |stream| {
            if let PyBio::Memory { incoming, .. } = stream.get_mut() {
                incoming.extend(&data);
            }
        });
        Ok(n)
    }

    /// Renegotiate the session.
    fn renegotiate(&self, py: Python<'_>) -> PyResult<bool> {
        // SSL_renegotiate has no safe wrapper.
        if !self.renegotiate_pending() {
            openssl_assert!(
                py,
                Error,
                unsafe { ffi_ext::SSL_renegotiate(self.ssl_ptr.get()) } == 1
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
        Connection::register(slf)?;
        let this = slf.borrow();
        let result = this.with_stream(py, |stream| stream.do_handshake());
        result.map_err(|e| this.map_ssl_error(py, &e))
    }

    /// Check if there's a renegotiation in progress, it will return False
    /// once a renegotiation is finished.
    fn renegotiate_pending(&self) -> bool {
        // SSL_renegotiate_pending has no safe wrapper.
        unsafe { ffi_ext::SSL_renegotiate_pending(self.ssl_ptr.get()) == 1 }
    }

    /// Find out the total number of renegotiations.
    fn total_renegotiations(&self) -> c_long {
        // SSL_total_renegotiations has no safe wrapper.
        unsafe { ffi_ext::SSL_total_renegotiations(self.ssl_ptr.get()) }
    }

    /// Call the `connect` method of the underlying socket and set up SSL
    /// on the socket, using the `Context` object supplied to this
    /// `Connection` object at creation.
    fn connect(slf: &Bound<'_, Self>, addr: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        Connection::register(slf)?;
        let this = slf.borrow();
        this.ssl_mut().set_connect_state();
        let socket = this.socket_or_typeerror(py)?;
        Ok(socket.call_method1("connect", (addr,))?.unbind())
    }

    /// Call the `connect_ex` method of the underlying socket and set up
    /// SSL on the socket, using the Context object supplied to this
    /// Connection object at creation.
    fn connect_ex(slf: &Bound<'_, Self>, addr: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        Connection::register(slf)?;
        let this = slf.borrow();
        let socket = this.socket_or_typeerror(py)?;
        let connect_ex = socket.getattr("connect_ex")?;
        this.ssl_mut().set_connect_state();
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
        conn.borrow(py).ssl_mut().set_accept_state();
        Ok(PyTuple::new(py, [conn.into_any(), addr.unbind()])?.unbind())
    }

    /// Call the OpenSSL function DTLSv1_listen on this connection. See
    /// the OpenSSL manual for more details.
    #[allow(non_snake_case)]
    fn DTLSv1_listen(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        Connection::register(slf)?;
        let this = slf.borrow();
        // DTLSv1_listen has no safe wrapper.
        let (result, errno) = this.with_stream(py, |stream| unsafe {
            let bio_addr = ffi_ext::BIO_ADDR_new();
            let result = ffi_ext::DTLSv1_listen(stream.ssl().as_ptr(), bio_addr);
            ffi_ext::BIO_ADDR_free(bio_addr);
            (result, util::last_errno())
        });
        // DTLSv1_listen is weird. A zero return value means 'didn't find a
        // ClientHello with valid cookie, but keep trying'. So basically
        // WantReadError. But it doesn't work correctly with the usual
        // error mapping, so raise it manually.
        if let Some(problem) = this.pop_problem(py) {
            return Err(problem);
        }
        if result == 0 {
            return Err(WantReadError::new_err(()));
        }
        if result < 0 {
            let error = unsafe { ffi::SSL_get_error(this.ssl_ptr.get(), result) };
            return Err(this.raise_raw_ssl_error(py, error, errno));
        }
        Ok(())
    }

    /// Determine when the DTLS SSL object next needs to perform internal
    /// processing due to the passage of time.
    #[allow(non_snake_case)]
    fn DTLSv1_get_timeout(&self) -> Option<f64> {
        // DTLSv1_get_timeout has no safe wrapper.
        let mut tv = ffi_ext::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = unsafe { ffi_ext::DTLSv1_get_timeout(self.ssl_ptr.get(), &mut tv) };
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
        // DTLSv1_handle_timeout has no safe wrapper.
        let (result, errno) = self.with_stream(py, |stream| unsafe {
            let r = ffi_ext::DTLSv1_handle_timeout(stream.ssl().as_ptr());
            (r, util::last_errno())
        });
        if result < 0 {
            let error = unsafe { ffi::SSL_get_error(self.ssl_ptr.get(), result as c_int) };
            return Err(self.raise_raw_ssl_error(py, error, errno));
        }
        Ok(result > 0)
    }

    /// If the Connection was created with a memory BIO, this method can
    /// be used to indicate that *end of file* has been reached on the
    /// read end of that memory BIO.
    fn bio_shutdown(&self, py: Python<'_>) -> PyResult<()> {
        self.require_memory_bio()?;
        self.with_stream(py, |stream| {
            if let PyBio::Memory { eof, .. } = stream.get_mut() {
                *eof = true;
            }
        });
        Ok(())
    }

    /// Send the shutdown message to the Connection.
    fn shutdown(slf: &Bound<'_, Self>) -> PyResult<bool> {
        let py = slf.py();
        Connection::register(slf)?;
        let this = slf.borrow();
        let result = this.with_stream(py, |stream| stream.shutdown());
        match result {
            Ok(ShutdownResult::Sent) => Ok(false),
            Ok(ShutdownResult::Received) => Ok(true),
            Err(e) => Err(this.map_ssl_error(py, &e)),
        }
    }

    /// Retrieve the list of ciphers used by the Connection object.
    fn get_cipher_list(&self) -> Vec<String> {
        // SSL_get_cipher_list (by priority index) has no safe wrapper.
        let mut ciphers = Vec::new();
        let mut i = 0;
        loop {
            let result = unsafe { ffi_ext::SSL_get_cipher_list(self.ssl_ptr.get(), i) };
            if result.is_null() {
                break;
            }
            ciphers.push(unsafe { util::text(result) });
            i += 1;
        }
        ciphers
    }

    /// Get CAs whose certificates are suggested for client
    /// authentication.
    fn get_client_ca_list(&self, py: Python<'_>) -> PyResult<Vec<Py<X509Name>>> {
        // SSL_get_client_CA_list has no safe wrapper.
        unsafe {
            let ca_names = ffi_ext::SSL_get_client_CA_list(self.ssl_ptr.get());
            if ca_names.is_null() {
                return Ok(Vec::new());
            }
            let stack: &openssl::stack::StackRef<SslX509Name> =
                openssl::stack::StackRef::from_ptr(ca_names as *mut _);
            let mut result = Vec::new();
            for name in stack {
                let copy = name.to_owned().map_err(|e| err_stack_to_py(py, e))?;
                result.push(Py::new(py, X509Name::from_owned(copy))?);
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
        // No safe getter (SslStream only exposes the setter).
        unsafe { ffi::SSL_get_shutdown(self.ssl_ptr.get()) }
    }

    /// Set the shutdown state of the Connection.
    fn set_shutdown(&self, py: Python<'_>, state: &Bound<'_, PyAny>) -> PyResult<()> {
        let state: c_int = state
            .extract()
            .map_err(|_| PyTypeError::new_err("state must be an integer"))?;
        self.with_stream(py, |stream| {
            stream.set_shutdown(ShutdownState::from_bits_retain(state))
        });
        Ok(())
    }

    /// Retrieve a verbose string detailing the state of the Connection.
    fn get_state_string(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, self.ssl_ref().state_string_long().as_bytes()).unbind()
    }

    /// Retrieve the random value used with the server hello message.
    fn server_random(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        let ssl = self.ssl_ref();
        ssl.session()?;
        let len = ssl.server_random(&mut []);
        let mut buf = vec![0u8; len];
        ssl.server_random(&mut buf);
        Some(PyBytes::new(py, &buf).unbind())
    }

    /// Retrieve the random value used with the client hello message.
    fn client_random(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        let ssl = self.ssl_ref();
        ssl.session()?;
        let len = ssl.client_random(&mut []);
        let mut buf = vec![0u8; len];
        ssl.client_random(&mut buf);
        Some(PyBytes::new(py, &buf).unbind())
    }

    /// Retrieve the value of the master key for this session.
    fn master_key(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        let session = self.ssl_ref().session()?;
        let len = session.master_key(&mut []);
        let mut buf = vec![0u8; len];
        session.master_key(&mut buf);
        Some(PyBytes::new(py, &buf).unbind())
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
        let label_str = std::str::from_utf8(label)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.ssl_ref()
            .export_keying_material(&mut outp, label_str, context)
            .map_err(|e| err_stack_to_py(py, e))?;
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
        match self.ssl_ref().certificate() {
            None => Ok(None),
            Some(cert) => {
                let pycert = Py::new(py, X509::from_openssl(cert.to_owned()))?;
                if as_cryptography {
                    Ok(Some(
                        pycert.bind(py).call_method0("to_cryptography")?.unbind(),
                    ))
                } else {
                    Ok(Some(pycert.into_any()))
                }
            }
        }
    }

    /// Retrieve the other side's certificate (if any)
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_peer_certificate(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyAny>>> {
        match self.ssl_ref().peer_certificate() {
            None => Ok(None),
            Some(cert) => {
                let pycert = Py::new(py, X509::from_openssl(cert))?;
                if as_cryptography {
                    Ok(Some(
                        pycert.bind(py).call_method0("to_cryptography")?.unbind(),
                    ))
                } else {
                    Ok(Some(pycert.into_any()))
                }
            }
        }
    }

    /// Retrieve the other side's certificate chain (if any)
    #[pyo3(signature = (*, as_cryptography=false))]
    fn get_peer_cert_chain(
        &self,
        py: Python<'_>,
        as_cryptography: bool,
    ) -> PyResult<Option<Py<PyList>>> {
        match self.ssl_ref().peer_cert_chain() {
            None => Ok(None),
            Some(chain) => Ok(Some(Connection::cert_stack_to_list(
                py,
                chain,
                as_cryptography,
            )?)),
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
        match self.ssl_ref().verified_chain() {
            None => Ok(None),
            Some(chain) => Ok(Some(Connection::cert_stack_to_list(
                py,
                chain,
                as_cryptography,
            )?)),
        }
    }

    /// Checks if more data has to be read from the transport layer to
    /// complete an operation.
    fn want_read(&self) -> bool {
        // SSL_want has no safe wrapper.
        const SSL_READING: c_int = 3;
        unsafe { ffi_ext::SSL_want(self.ssl_ptr.get()) == SSL_READING }
    }

    /// Checks if there is data to write to the transport layer to
    /// complete an operation.
    fn want_write(&self) -> bool {
        const SSL_WRITING: c_int = 2;
        unsafe { ffi_ext::SSL_want(self.ssl_ptr.get()) == SSL_WRITING }
    }

    /// Set the connection to work in server mode. The handshake will be
    /// handled automatically by read/write.
    fn set_accept_state(&self) {
        self.ssl_mut().set_accept_state();
    }

    /// Set the connection to work in client mode. The handshake will be
    /// handled automatically by read/write.
    fn set_connect_state(&self) {
        self.ssl_mut().set_connect_state();
    }

    /// Returns the Session currently used.
    fn get_session(&self) -> Option<Session> {
        let session = self.ssl_ref().session()?.to_owned();
        Some(Session {
            session: Some(session),
        })
    }

    /// Set the session to be used when the TLS/SSL connection is
    /// established.
    fn set_session(&self, py: Python<'_>, session: &Bound<'_, PyAny>) -> PyResult<()> {
        let session = session
            .cast::<Session>()
            .map_err(|_| PyTypeError::new_err("session must be a Session instance"))?;
        let session_ref = session.borrow();
        let session_inner = session_ref
            .session
            .as_ref()
            .ok_or_else(|| PyTypeError::new_err("session is uninitialized"))?;
        // Safety contract of SslRef::set_session: the session must come
        // from a connection with the same context, which pyOpenSSL leaves
        // as the caller's responsibility (as the C API does).
        unsafe {
            self.ssl_mut()
                .set_session(session_inner)
                .map_err(|e| err_stack_to_py(py, e))
        }
    }

    /// Obtain the latest TLS Finished message that we sent.
    fn get_finished(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        let ssl = self.ssl_ref();
        let size = ssl.finished(&mut []);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        ssl.finished(&mut buf);
        Some(PyBytes::new(py, &buf).unbind())
    }

    /// Obtain the latest TLS Finished message that we received from the
    /// peer.
    fn get_peer_finished(&self, py: Python<'_>) -> Option<Py<PyBytes>> {
        let ssl = self.ssl_ref();
        let size = ssl.peer_finished(&mut []);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        ssl.peer_finished(&mut buf);
        Some(PyBytes::new(py, &buf).unbind())
    }

    /// Obtain the name of the currently used cipher.
    fn get_cipher_name(&self) -> Option<String> {
        self.ssl_ref().current_cipher().map(|c| c.name().to_string())
    }

    /// Obtain the number of secret bits of the currently used cipher.
    fn get_cipher_bits(&self) -> Option<i32> {
        self.ssl_ref().current_cipher().map(|c| c.bits().secret)
    }

    /// Obtain the protocol version of the currently used cipher.
    fn get_cipher_version(&self) -> Option<String> {
        self.ssl_ref()
            .current_cipher()
            .map(|c| c.version().to_string())
    }

    /// Retrieve the protocol version of the current connection.
    fn get_protocol_version_name(&self) -> String {
        self.ssl_ref().version_str().to_string()
    }

    /// Retrieve the SSL or TLS protocol version of the current
    /// connection.
    fn get_protocol_version(&self) -> c_int {
        // SslRef::version2 returns an opaque SslVersion; pyOpenSSL exposes
        // the raw protocol number.
        unsafe { ffi::SSL_version(self.ssl_ptr.get()) }
    }

    /// Specify the client's ALPN protocol list.
    fn set_alpn_protos(&self, py: Python<'_>, protos: &Bound<'_, PyAny>) -> PyResult<()> {
        let protostr = build_alpn_wire_format(py, protos)?;
        self.ssl_mut()
            .set_alpn_protos(&protostr)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Get the protocol that was negotiated by ALPN.
    fn get_alpn_proto_negotiated(&self, py: Python<'_>) -> Py<PyBytes> {
        match self.ssl_ref().selected_alpn_protocol() {
            Some(proto) => PyBytes::new(py, proto).unbind(),
            None => PyBytes::new(py, b"").unbind(),
        }
    }

    /// Get the SRTP protocol which was negotiated.
    fn get_selected_srtp_profile(&self, py: Python<'_>) -> Py<PyBytes> {
        match self.ssl_ref().selected_srtp_profile() {
            Some(profile) => PyBytes::new(py, profile.name().as_bytes()).unbind(),
            None => PyBytes::new(py, b"").unbind(),
        }
    }

    /// Get the name of the negotiated group for the key exchange.
    fn get_group_name(&self, py: Python<'_>) -> PyResult<Option<String>> {
        #[cfg(ossl320)]
        {
            // SSL_get0_group_name has no safe wrapper.
            // Do not remove this guard.
            // SSL_get0_group_name crashes with a segfault if called
            // without an established connection (should return NULL but
            // doesn't).
            unsafe {
                if self.ssl_ref().session().is_none() {
                    return Ok(None);
                }
                let group_name = ffi_ext::SSL_get0_group_name(self.ssl_ptr.get());
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
        self.ssl_mut()
            .set_status_type(openssl::ssl::StatusType::OCSP)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the information callback to *callback*. This function will be
    /// called from time to time during SSL handshakes.
    fn set_info_callback(slf: &Bound<'_, Self>, callback: &Bound<'_, PyAny>) -> PyResult<()> {
        Connection::register(slf)?;
        let this = slf.borrow();
        *this.state.info_cb.lock().unwrap() = Some(callback.clone().unbind());
        // SSL_set_info_callback has no safe wrapper.
        unsafe {
            ffi_ext::SSL_set_info_callback(this.ssl_ptr.get(), Some(info_cb_conn));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Return a string describing the version of OpenSSL in use.
#[pyfunction(name = "OpenSSL_version")]
fn openssl_version(py: Python<'_>, r#type: c_int) -> Py<PyBytes> {
    unsafe {
        let s = ffi::OpenSSL_version(r#type);
        PyBytes::new(py, std::ffi::CStr::from_ptr(s).to_bytes()).unbind()
    }
}

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
    m.add_function(pyo3::wrap_pyfunction!(_x509_get_default_cert_file, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(_x509_get_default_cert_dir, &m)?)?;

    m.add("OPENSSL_VERSION_NUMBER", openssl::version::number() as u64)?;
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

    m.add("SENT_SHUTDOWN", ShutdownState::SENT.bits())?;
    m.add("RECEIVED_SHUTDOWN", ShutdownState::RECEIVED.bits())?;

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
    m.add("OP_NO_SSLv3", SslOptions::NO_SSLV3.bits() as u64)?;
    m.add("OP_NO_TLSv1", SslOptions::NO_TLSV1.bits() as u64)?;
    m.add("OP_NO_TLSv1_1", SslOptions::NO_TLSV1_1.bits() as u64)?;
    m.add("OP_NO_TLSv1_2", SslOptions::NO_TLSV1_2.bits() as u64)?;
    m.add("OP_NO_TLSv1_3", SslOptions::NO_TLSV1_3.bits() as u64)?;

    m.add("MODE_RELEASE_BUFFERS", SslMode::RELEASE_BUFFERS.bits() as i64)?;

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
        SslOptions::CIPHER_SERVER_PREFERENCE.bits() as u64,
    )?;
    m.add("OP_TLS_ROLLBACK_BUG", ffi::SSL_OP_TLS_ROLLBACK_BUG)?;
    m.add("OP_PKCS1_CHECK_1", 0u64)?;
    m.add("OP_PKCS1_CHECK_2", 0u64)?;
    m.add("OP_NETSCAPE_CA_DN_BUG", 0u64)?;
    m.add("OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", 0u64)?;
    m.add("OP_NO_COMPRESSION", SslOptions::NO_COMPRESSION.bits() as u64)?;
    m.add("OP_NO_QUERY_MTU", SslOptions::NO_QUERY_MTU.bits() as u64)?;
    m.add("OP_COOKIE_EXCHANGE", SslOptions::COOKIE_EXCHANGE.bits() as u64)?;
    m.add("OP_NO_TICKET", SslOptions::NO_TICKET.bits() as u64)?;
    m.add(
        "OP_NO_RENEGOTIATION",
        SslOptions::NO_RENEGOTIATION.bits() as u64,
    )?;
    m.add("OP_IGNORE_UNEXPECTED_EOF", ffi::SSL_OP_IGNORE_UNEXPECTED_EOF)?;
    m.add("OP_LEGACY_SERVER_CONNECT", ffi::SSL_OP_LEGACY_SERVER_CONNECT)?;
    m.add("OP_ALL", SslOptions::ALL.bits() as u64)?;

    m.add("VERIFY_PEER", SslVerifyMode::PEER.bits())?;
    m.add(
        "VERIFY_FAIL_IF_NO_PEER_CERT",
        SslVerifyMode::FAIL_IF_NO_PEER_CERT.bits(),
    )?;
    m.add("VERIFY_CLIENT_ONCE", 0x4)?;
    m.add("VERIFY_NONE", SslVerifyMode::NONE.bits())?;

    m.add("SESS_CACHE_OFF", SslSessionCacheMode::OFF.bits() as i64)?;
    m.add("SESS_CACHE_CLIENT", SslSessionCacheMode::CLIENT.bits() as i64)?;
    m.add("SESS_CACHE_SERVER", SslSessionCacheMode::SERVER.bits() as i64)?;
    m.add("SESS_CACHE_BOTH", SslSessionCacheMode::BOTH.bits() as i64)?;
    m.add(
        "SESS_CACHE_NO_AUTO_CLEAR",
        SslSessionCacheMode::NO_AUTO_CLEAR.bits() as i64,
    )?;
    m.add(
        "SESS_CACHE_NO_INTERNAL_LOOKUP",
        SslSessionCacheMode::NO_INTERNAL_LOOKUP.bits() as i64,
    )?;
    m.add(
        "SESS_CACHE_NO_INTERNAL_STORE",
        SslSessionCacheMode::NO_INTERNAL_STORE.bits() as i64,
    )?;
    m.add(
        "SESS_CACHE_NO_INTERNAL",
        SslSessionCacheMode::NO_INTERNAL.bits() as i64,
    )?;

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

    // Feature flags (the cffi bindings exposed these via
    // `Cryptography_HAS_*`; tests use these spellings).
    m.add("_HAS_KEYLOG", true)?;
    m.add("_HAS_SSL_COOKIE", true)?;
    m.add("_HAS_SSL_GET0_GROUP_NAME", cfg!(ossl320))?;

    Ok(m)
}
