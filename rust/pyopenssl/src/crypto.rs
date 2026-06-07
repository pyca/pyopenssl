//! Implementation of the `OpenSSL.crypto` module.
//!
//! This is written against the safe `openssl` crate (rust-openssl) wherever
//! its API model permits. The exceptions, documented inline, are
//! pyOpenSSL's in-place mutation APIs (`X509.set_*`/`sign`,
//! `X509Name.__setattr__`, `X509Req.set_*`) and `X509Name`'s aliasing of
//! names embedded in certificates, which have no safe representation
//! (rust-openssl is strictly builder-based there), plus a handful of
//! functions rust-openssl does not expose (see `ffi_ext.rs`).

use foreign_types_shared::{ForeignType, ForeignTypeRef};
use libc::{c_char, c_int, c_long, c_uchar, c_void};
use openssl::asn1::Asn1Object;
use openssl::bn::BigNum;
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey as SslPKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::store::{X509StoreBuilder, X509StoreRef};
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{
    X509 as SslX509, X509NameRef, X509Ref, X509Req as SslX509Req,
    X509StoreContext as SslX509StoreContext,
};
use openssl_sys as ffi;
use pyo3::exceptions::{PyAttributeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyType};

use crate::ffi_ext::{self, CPtr};
use crate::util::{self, cstring, exception_from_error_queue};
use crate::{openssl_assert, openssl_error};

pyo3::create_exception!(
    OpenSSL.crypto,
    Error,
    pyo3::exceptions::PyException,
    "An error occurred in an `OpenSSL.crypto` API."
);

pub const FILETYPE_PEM: c_int = ffi_ext::SSL_FILETYPE_PEM;
pub const FILETYPE_ASN1: c_int = ffi_ext::SSL_FILETYPE_ASN1;
// TODO This was an API mistake.  OpenSSL has no such constant.
pub const FILETYPE_TEXT: c_int = 0xFFFF;

pub const TYPE_RSA: c_int = ffi::EVP_PKEY_RSA;
pub const TYPE_DSA: c_int = ffi::EVP_PKEY_DSA;
pub const TYPE_DH: c_int = ffi::EVP_PKEY_DH;
pub const TYPE_EC: c_int = ffi::EVP_PKEY_EC;

/// Convert an `ErrorStack` into an `OpenSSL.crypto.Error` carrying the
/// usual list of (lib, func, reason) tuples.
pub fn err_stack_to_py(py: Python<'_>, e: openssl::error::ErrorStack) -> PyErr {
    util::error_stack_to_exception(py, &py.get_type::<Error>(), &e)
}

// ---------------------------------------------------------------------------
// Passphrase helpers (port of `_PassphraseHelper`)
// ---------------------------------------------------------------------------

/// The state shared with PEM passphrase callbacks. The Python callback is
/// invoked from OpenSSL's pem_password_cb; exceptions are stashed and
/// re-raised after the OpenSSL call returns.
pub struct PassphraseHelper {
    passphrase: Option<Py<PyAny>>,
    more_args: bool,
    truncate: bool,
    userdata: Option<Py<PyAny>>,
    pub problems: Vec<PyErr>,
}

impl PassphraseHelper {
    pub fn new(
        py: Python<'_>,
        filetype: c_int,
        passphrase: Option<&Bound<'_, PyAny>>,
        more_args: bool,
        truncate: bool,
        userdata: Option<Py<PyAny>>,
    ) -> PyResult<PassphraseHelper> {
        if filetype != FILETYPE_PEM && passphrase.is_some() {
            return Err(PyValueError::new_err(
                "only FILETYPE_PEM key format supports encryption",
            ));
        }
        if let Some(p) = passphrase {
            if p.cast::<PyBytes>().is_err() && !p.is_callable() {
                return Err(PyTypeError::new_err(
                    "Last argument must be a byte string or a callable.",
                ));
            }
        }
        let _ = py;
        Ok(PassphraseHelper {
            passphrase: passphrase.map(|p| p.clone().unbind()),
            more_args,
            truncate,
            userdata,
            problems: Vec::new(),
        })
    }

    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }

    pub fn raise_if_problem(&mut self, py: Python<'_>) -> PyResult<()> {
        if !self.problems.is_empty() {
            // Flush the OpenSSL error queue
            let _ = openssl::error::ErrorStack::get();
            let _ = py;
            return Err(self.problems.remove(0));
        }
        Ok(())
    }

    /// Invoke the Python passphrase callback (or return the passphrase
    /// bytes), writing the result into `buf` (the buffer handed to us by
    /// OpenSSL's pem_password_cb).
    pub fn read_passphrase(
        &mut self,
        py: Python<'_>,
        buf: &mut [u8],
        rwflag: c_int,
    ) -> PyResult<usize> {
        let passphrase = self
            .passphrase
            .as_ref()
            .expect("callback invoked without passphrase")
            .bind(py);
        let result = if passphrase.is_callable() {
            if self.more_args {
                let userdata = match &self.userdata {
                    Some(u) => u.clone_ref(py).into_bound(py),
                    None => py.None().into_bound(py),
                };
                passphrase.call1((buf.len(), rwflag != 0, userdata))?
            } else {
                passphrase.call1((rwflag,))?
            }
        } else {
            passphrase.clone()
        };
        let result = result
            .cast::<PyBytes>()
            .map_err(|_| PyValueError::new_err("Bytes expected"))?;
        let mut data = result.as_bytes();
        if data.len() > buf.len() {
            if self.truncate {
                data = &data[..buf.len()];
            } else {
                return Err(PyValueError::new_err(
                    "passphrase returned by callback is too long",
                ));
            }
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    /// A closure suitable for rust-openssl's `*_from_pem_callback`
    /// functions.
    pub fn rust_callback<'a>(
        &'a mut self,
        py: Python<'a>,
        rwflag: c_int,
    ) -> impl FnOnce(&mut [u8]) -> Result<usize, openssl::error::ErrorStack> + 'a {
        move |buf| match self.read_passphrase(py, buf, rwflag) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.problems.push(e);
                // Returning an (empty) error stack aborts the PEM read.
                Err(openssl::error::ErrorStack::get())
            }
        }
    }
}

/// Raw pem_password_cb trampoline used for `SSL_CTX_set_default_passwd_cb`
/// (`Context.set_passwd_cb`), which rust-openssl does not expose: its safe
/// passphrase callbacks exist only as per-call closures on the PEM
/// functions, not as context-wide state consulted by
/// `SSL_CTX_use_PrivateKey_file`.
pub unsafe extern "C" fn raw_pem_password_cb(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
) -> c_int {
    let helper = &mut *(userdata as *mut PassphraseHelper);
    Python::attach(|py| {
        let buf = std::slice::from_raw_parts_mut(buf as *mut u8, size.max(0) as usize);
        match helper.read_passphrase(py, buf, rwflag) {
            Ok(n) => n as c_int,
            Err(e) => {
                helper.problems.push(e);
                0
            }
        }
    })
}

/// Resolve a passphrase eagerly into bytes (for the *encryption* direction
/// of `dump_privatekey`: rust-openssl's
/// `private_key_to_pem_pkcs8_passphrase` only accepts passphrase bytes, not
/// a callback).
fn resolve_passphrase(
    py: Python<'_>,
    filetype: c_int,
    passphrase: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<Vec<u8>>> {
    let mut helper =
        PassphraseHelper::new(py, filetype, passphrase, false, false, None)?;
    if !helper.has_passphrase() {
        return Ok(None);
    }
    // 1024 is the buffer size OpenSSL's PEM machinery uses.
    let mut buf = [0u8; 1024];
    let n = helper.read_passphrase(py, &mut buf, 1)?;
    Ok(Some(buf[..n].to_vec()))
}

// ---------------------------------------------------------------------------
// PKey
// ---------------------------------------------------------------------------

enum KeyInner {
    Private(SslPKey<Private>),
    Public(SslPKey<Public>),
}

impl KeyInner {
    fn as_ptr(&self) -> *mut ffi::EVP_PKEY {
        match self {
            KeyInner::Private(k) => k.as_ptr(),
            KeyInner::Public(k) => k.as_ptr(),
        }
    }

    fn id(&self) -> c_int {
        match self {
            KeyInner::Private(k) => k.id().as_raw(),
            KeyInner::Public(k) => k.id().as_raw(),
        }
    }

    fn bits(&self) -> u32 {
        match self {
            KeyInner::Private(k) => k.bits(),
            KeyInner::Public(k) => k.bits(),
        }
    }

    fn empty(py: Python<'_>) -> PyResult<KeyInner> {
        // A fresh `PKey()` wraps an EVP_PKEY with no key material
        // (`type()`/`bits()` return 0). rust-openssl cannot represent this
        // state (its PKey is always a real key), so wrap a bare
        // EVP_PKEY_new() pointer in the safe owner type.
        unsafe {
            let pkey = ffi::EVP_PKEY_new();
            openssl_assert!(py, Error, !pkey.is_null());
            Ok(KeyInner::Private(SslPKey::from_ptr(pkey)))
        }
    }
}

/// A class representing an DSA or RSA public key or key pair.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct PKey {
    key: KeyInner,
    pub only_public: bool,
    pub initialized: bool,
}

impl PKey {
    pub fn from_private(key: SslPKey<Private>) -> PKey {
        PKey {
            key: KeyInner::Private(key),
            only_public: false,
            initialized: true,
        }
    }

    pub fn from_public(key: SslPKey<Public>) -> PKey {
        PKey {
            key: KeyInner::Public(key),
            only_public: true,
            initialized: true,
        }
    }

    pub fn pkey_ptr(&self) -> *mut ffi::EVP_PKEY {
        self.key.as_ptr()
    }

    /// View this key as a private-key reference for passing to OpenSSL
    /// functions which type-check at runtime (`SSL_CTX_use_PrivateKey`
    /// etc.). pyOpenSSL's PKey is runtime-polymorphic, so when a
    /// public-only key is passed we still hand it to OpenSSL and let it
    /// produce the error, exactly as the Python implementation did.
    pub fn as_private_ref(&self) -> &PKeyRef<Private> {
        unsafe { PKeyRef::from_ptr(self.key.as_ptr()) }
    }

    fn private(&self) -> PyResult<&SslPKey<Private>> {
        match &self.key {
            KeyInner::Private(k) => Ok(k),
            KeyInner::Public(_) => Err(PyTypeError::new_err("public key only")),
        }
    }
}

#[pymethods]
impl PKey {
    #[new]
    fn new(py: Python<'_>) -> PyResult<PKey> {
        Ok(PKey {
            key: KeyInner::empty(py)?,
            only_public: false,
            initialized: false,
        })
    }

    #[getter(_only_public)]
    fn get_only_public(&self) -> bool {
        self.only_public
    }

    #[getter(_initialized)]
    fn get_initialized(&self) -> bool {
        self.initialized
    }

    /// Export as a ``cryptography`` key.
    fn to_cryptography_key(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let serialization =
            py.import("cryptography.hazmat.primitives.serialization")?;
        let this = slf.borrow();
        if this.only_public {
            let der = dump_publickey_impl(py, FILETYPE_ASN1, &this)?;
            Ok(serialization
                .call_method1("load_der_public_key", (PyBytes::new(py, &der),))?
                .unbind())
        } else {
            let der = dump_privatekey_impl(py, FILETYPE_ASN1, &this, None, None)?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("password", py.None())?;
            Ok(serialization
                .call_method(
                    "load_der_private_key",
                    (PyBytes::new(py, &der),),
                    Some(&kwargs),
                )?
                .unbind())
        }
    }

    /// Construct based on a ``cryptography`` *crypto_key*.
    #[classmethod]
    fn from_cryptography_key(
        cls: &Bound<'_, PyType>,
        crypto_key: &Bound<'_, PyAny>,
    ) -> PyResult<PKey> {
        let py = cls.py();
        let dsa = py.import("cryptography.hazmat.primitives.asymmetric.dsa")?;
        let ec = py.import("cryptography.hazmat.primitives.asymmetric.ec")?;
        let ed25519 =
            py.import("cryptography.hazmat.primitives.asymmetric.ed25519")?;
        let ed448 = py.import("cryptography.hazmat.primitives.asymmetric.ed448")?;
        let rsa = py.import("cryptography.hazmat.primitives.asymmetric.rsa")?;

        let private_types = [
            dsa.getattr("DSAPrivateKey")?,
            ec.getattr("EllipticCurvePrivateKey")?,
            ed25519.getattr("Ed25519PrivateKey")?,
            ed448.getattr("Ed448PrivateKey")?,
            rsa.getattr("RSAPrivateKey")?,
        ];
        let public_types = [
            dsa.getattr("DSAPublicKey")?,
            ec.getattr("EllipticCurvePublicKey")?,
            ed25519.getattr("Ed25519PublicKey")?,
            ed448.getattr("Ed448PublicKey")?,
            rsa.getattr("RSAPublicKey")?,
        ];

        let is_private = private_types
            .iter()
            .any(|t| crypto_key.is_instance(t).unwrap_or(false));
        let is_public = public_types
            .iter()
            .any(|t| crypto_key.is_instance(t).unwrap_or(false));

        if !is_private && !is_public {
            return Err(PyTypeError::new_err("Unsupported key type"));
        }

        let serialization =
            py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        if is_public {
            let fmt = serialization
                .getattr("PublicFormat")?
                .getattr("SubjectPublicKeyInfo")?;
            let der = crypto_key
                .call_method1("public_bytes", (encoding, fmt))?
                .extract::<Vec<u8>>()?;
            load_publickey_impl(py, FILETYPE_ASN1, &der)
        } else {
            let fmt = serialization.getattr("PrivateFormat")?.getattr("PKCS8")?;
            let enc = serialization.getattr("NoEncryption")?.call0()?;
            let der = crypto_key
                .call_method1("private_bytes", (encoding, fmt, enc))?
                .extract::<Vec<u8>>()?;
            load_privatekey_impl(py, FILETYPE_ASN1, &der, None)
        }
    }

    /// Generate a key pair of the given type, with the given number of bits.
    fn generate_key(
        &mut self,
        py: Python<'_>,
        r#type: &Bound<'_, PyAny>,
        bits: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let type_: c_int = r#type
            .extract()
            .map_err(|_| PyTypeError::new_err("type must be an integer"))?;
        let bits: c_long = bits
            .extract()
            .map_err(|_| PyTypeError::new_err("bits must be an integer"))?;

        if type_ == TYPE_RSA {
            if bits <= 0 {
                return Err(PyValueError::new_err("Invalid number of bits"));
            }
            let rsa = Rsa::generate(bits as u32).map_err(|e| err_stack_to_py(py, e))?;
            let key = SslPKey::from_rsa(rsa).map_err(|e| err_stack_to_py(py, e))?;
            self.key = KeyInner::Private(key);
        } else if type_ == TYPE_DSA {
            let dsa = Dsa::generate(bits as u32).map_err(|e| err_stack_to_py(py, e))?;
            let key = SslPKey::from_dsa(dsa).map_err(|e| err_stack_to_py(py, e))?;
            self.key = KeyInner::Private(key);
        } else {
            return Err(Error::new_err("No such key type"));
        }
        self.only_public = false;
        self.initialized = true;
        Ok(())
    }

    /// Check the consistency of an RSA private key.
    fn check(&self, py: Python<'_>) -> PyResult<bool> {
        if self.only_public {
            return Err(PyTypeError::new_err("public key only"));
        }
        if self.key.id() != ffi::EVP_PKEY_RSA {
            return Err(PyTypeError::new_err(
                "Only RSA keys can currently be checked.",
            ));
        }
        let rsa = self.private()?.rsa().map_err(|e| err_stack_to_py(py, e))?;
        match rsa.check_key() {
            Ok(true) => Ok(true),
            Ok(false) => Err(openssl_error!(py, Error)),
            Err(e) => Err(err_stack_to_py(py, e)),
        }
    }

    /// Returns the type of the key
    fn r#type(&self) -> c_int {
        self.key.id()
    }

    /// Returns the number of bits of the key
    fn bits(&self) -> u32 {
        self.key.bits()
    }
}

// ---------------------------------------------------------------------------
// _EllipticCurve
// ---------------------------------------------------------------------------

/// A representation of a supported elliptic curve.
#[pyclass(module = "OpenSSL.crypto", name = "_EllipticCurve")]
pub struct EllipticCurve {
    #[pyo3(get)]
    pub name: String,
    pub nid: c_int,
}

#[pymethods]
impl EllipticCurve {
    fn __repr__(&self) -> String {
        format!("<Curve '{}'>", self.name)
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = other.py();
        match other.cast::<EllipticCurve>() {
            Ok(o) => Ok((self.nid == o.borrow().nid)
                .into_pyobject(py)?
                .to_owned()
                .into_any()
                .unbind()),
            Err(_) => Ok(py.NotImplemented()),
        }
    }

    fn __ne__(&self, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let py = other.py();
        match other.cast::<EllipticCurve>() {
            Ok(o) => Ok((self.nid != o.borrow().nid)
                .into_pyobject(py)?
                .to_owned()
                .into_any()
                .unbind()),
            Err(_) => Ok(py.NotImplemented()),
        }
    }

    fn __hash__(&self) -> isize {
        self.nid as isize
    }

    /// Create a new OpenSSL EC_KEY structure initialized to use this
    /// curve (internal helper; the cffi implementation returned the
    /// EC_KEY, which has no meaningful Python-level API).
    #[allow(non_snake_case)]
    fn _to_EC_KEY(&self, py: Python<'_>) -> PyResult<()> {
        openssl::ec::EcKey::from_curve_name(Nid::from_raw(self.nid))
            .map_err(|e| err_stack_to_py(py, e))?;
        Ok(())
    }
}

fn load_elliptic_curves(py: Python<'_>) -> PyResult<Vec<Py<EllipticCurve>>> {
    // rust-openssl has no wrapper for EC_get_builtin_curves.
    unsafe {
        let num = ffi_ext::EC_get_builtin_curves(std::ptr::null_mut(), 0);
        let mut curves = Vec::with_capacity(num);
        curves.resize_with(num, || ffi_ext::EC_builtin_curve {
            nid: 0,
            comment: std::ptr::null(),
        });
        ffi_ext::EC_get_builtin_curves(curves.as_mut_ptr(), num);
        let mut result = Vec::with_capacity(num);
        for c in &curves {
            let name = Nid::from_raw(c.nid).short_name().unwrap_or("").to_string();
            result.push(Py::new(py, EllipticCurve { name, nid: c.nid })?);
        }
        Ok(result)
    }
}

fn get_elliptic_curves_impl(py: Python<'_>) -> PyResult<Vec<Py<EllipticCurve>>> {
    static CURVES: pyo3::sync::PyOnceLock<Vec<Py<EllipticCurve>>> =
        pyo3::sync::PyOnceLock::new();
    let curves = CURVES.get_or_try_init(py, || load_elliptic_curves(py))?;
    Ok(curves.iter().map(|c| c.clone_ref(py)).collect())
}

/// Return a set of objects representing the elliptic curves supported in
/// the OpenSSL build in use.
#[pyfunction]
fn get_elliptic_curves(py: Python<'_>) -> PyResult<Py<PyAny>> {
    util::warn(
        py,
        "get_elliptic_curves is deprecated. You should use the APIs in \
         cryptography instead.",
        "DeprecationWarning",
        2,
    )?;
    let curves = get_elliptic_curves_impl(py)?;
    let set = pyo3::types::PySet::empty(py)?;
    for c in curves {
        set.add(c)?;
    }
    Ok(set.into_any().unbind())
}

/// Return a single curve object selected by name.
#[pyfunction]
fn get_elliptic_curve(py: Python<'_>, name: &str) -> PyResult<Py<EllipticCurve>> {
    util::warn(
        py,
        "get_elliptic_curve is deprecated. You should use the APIs in \
         cryptography instead.",
        "DeprecationWarning",
        2,
    )?;
    for curve in get_elliptic_curves_impl(py)? {
        if curve.borrow(py).name == name {
            return Ok(curve);
        }
    }
    Err(PyValueError::new_err(("unknown curve name", name.to_string())))
}

// ---------------------------------------------------------------------------
// X509Name
// ---------------------------------------------------------------------------

/// An X.509 Distinguished Name.
///
/// This class cannot be written against safe rust-openssl: pyOpenSSL's
/// X509Name may *alias* the X509_NAME embedded inside an X509/X509Req
/// (mutating it mutates the certificate), while the safe API only offers a
/// read-only `X509NameRef` and a standalone, append-only
/// `X509NameBuilder`. We hold a raw pointer (owned or borrowed, with the
/// owner kept alive) and use safe `X509NameRef` views for read-only
/// operations.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509Name {
    pub name: CPtr<ffi::X509_NAME>,
    pub owned: bool,
    // Keeps the object owning the underlying X509_NAME alive (e.g. an X509
    // certificate when this name aliases its subject/issuer field).
    pub owner: Option<Py<PyAny>>,
    // Set when the name has been invalidated (the Python implementation
    // deleted `_name` to prevent use-after-free; we use a flag).
    pub dead: bool,
}

impl Drop for X509Name {
    fn drop(&mut self) {
        if self.owned && !self.name.is_null() {
            unsafe { ffi::X509_NAME_free(self.name.get()) }
        }
    }
}

impl X509Name {
    /// Takes ownership of `name`.
    pub fn from_owned_ptr(name: *mut ffi::X509_NAME) -> X509Name {
        X509Name {
            name: CPtr(name),
            owned: true,
            owner: None,
            dead: false,
        }
    }

    pub fn from_owned(name: openssl::x509::X509Name) -> X509Name {
        let ptr = name.as_ptr();
        std::mem::forget(name);
        X509Name::from_owned_ptr(ptr)
    }

    fn check(&self) -> PyResult<*mut ffi::X509_NAME> {
        if self.dead || self.name.is_null() {
            Err(PyAttributeError::new_err("No such attribute"))
        } else {
            Ok(self.name.get())
        }
    }

    /// A safe read-only view of the name. Sound for the same reason the
    /// cffi implementation was: accesses happen with the GIL held, and the
    /// owner (if any) is kept alive by `self.owner`.
    pub fn name_ref(&self) -> PyResult<&X509NameRef> {
        Ok(unsafe { X509NameRef::from_ptr(self.check()?) })
    }
}

fn x509_name_from_dup(py: Python<'_>, src: &X509NameRef) -> PyResult<X509Name> {
    let copy = src.to_owned().map_err(|e| err_stack_to_py(py, e))?;
    Ok(X509Name::from_owned(copy))
}

#[pymethods]
impl X509Name {
    /// Create a new X509Name, copying the given X509Name instance.
    #[new]
    fn new(py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<X509Name> {
        let name = name
            .cast::<X509Name>()
            .map_err(|_| PyTypeError::new_err("name must be an X509Name"))?;
        let borrowed = name.borrow();
        x509_name_from_dup(py, borrowed.name_ref()?)
    }

    fn __setattr__(
        slf: &Bound<'_, Self>,
        name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let py = slf.py();
        // Attributes with a leading underscore are stored on the instance
        // (the Python implementation routed these to object.__setattr__).
        if let Ok(s) = name.cast::<PyString>() {
            if name.get_type().is(&py.get_type::<PyString>())
                && s.to_cow()?.starts_with('_')
            {
                let dict = slf.getattr("__dict__")?;
                dict.set_item(s, value)?;
                return Ok(());
            }
        }
        // Note: we really do not want str subclasses here, so we do not use
        // isinstance.
        if !name.get_type().is(&py.get_type::<PyString>()) {
            let value_type = value.get_type().name()?.to_string();
            let mut truncated = value_type;
            truncated.truncate(200);
            return Err(PyTypeError::new_err(format!(
                "attribute name must be string, not '{}'",
                truncated
            )));
        }
        let attr = name.extract::<String>()?;
        let nid = unsafe {
            let attr_c = cstring(py, attr.as_bytes())?;
            ffi_ext::OBJ_txt2nid(attr_c.as_ptr())
        };
        if nid == 0 {
            // Flush the error queue (see lp#314814 in the Python version).
            let _ = openssl::error::ErrorStack::get();
            return Err(PyAttributeError::new_err("No such attribute"));
        }
        let this = slf.borrow();
        let name_ptr = this.check()?;
        // In-place mutation of an X509_NAME (possibly embedded in a
        // certificate) has no safe rust-openssl equivalent
        // (X509NameBuilder is standalone and append-only, and
        // X509_NAME_delete_entry is not exposed at all).
        unsafe {
            // If there's an old entry for this NID, remove it
            for i in 0..ffi::X509_NAME_entry_count(name_ptr) {
                let ent = ffi::X509_NAME_get_entry(name_ptr, i);
                let ent_obj = ffi::X509_NAME_ENTRY_get_object(ent);
                let ent_nid = ffi::OBJ_obj2nid(ent_obj);
                if nid == ent_nid {
                    let ent = ffi_ext::X509_NAME_delete_entry(name_ptr, i);
                    ffi::X509_NAME_ENTRY_free(ent);
                    break;
                }
            }
            let value_bytes: Vec<u8> = if let Ok(s) = value.cast::<PyString>() {
                s.to_cow()?.as_bytes().to_vec()
            } else {
                value.extract::<Vec<u8>>()?
            };
            const MBSTRING_UTF8: c_int = 0x1000;
            let add_result = ffi::X509_NAME_add_entry_by_NID(
                name_ptr,
                nid,
                MBSTRING_UTF8,
                value_bytes.as_ptr(),
                value_bytes.len() as c_int,
                -1,
                0,
            );
            if add_result == 0 {
                return Err(openssl_error!(py, Error));
            }
        }
        Ok(())
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let nid = unsafe {
            let name_c = cstring(py, name.as_bytes())?;
            ffi_ext::OBJ_txt2nid(name_c.as_ptr())
        };
        if nid == 0 {
            // OBJ_txt2nid pushed something onto the error queue; clean it up
            // so someone else doesn't bump into it later (see lp#314814).
            let _ = openssl::error::ErrorStack::get();
            return Err(PyAttributeError::new_err("No such attribute"));
        }
        let name_ref = self.name_ref()?;
        let first = name_ref
            .entries()
            .find(|e| e.object().nid().as_raw() == nid);
        match first {
            None => Ok(py.None()),
            Some(entry) => {
                // Asn1StringRef::as_utf8 truncates at NUL bytes (it goes
                // through CStr); use ASN1_STRING_to_UTF8 with its explicit
                // length so values containing NUL bytes round-trip.
                unsafe {
                    let mut buf: *mut c_uchar = std::ptr::null_mut();
                    let length =
                        ffi_ext::ASN1_STRING_to_UTF8(&mut buf, entry.data().as_ptr());
                    openssl_assert!(py, Error, length >= 0);
                    let slice = std::slice::from_raw_parts(buf, length as usize);
                    let result = std::str::from_utf8(slice)
                        .map(|s| PyString::new(py, s).into_any().unbind())
                        .map_err(|e| {
                            PyValueError::new_err(format!("invalid utf-8: {}", e))
                        });
                    ffi::CRYPTO_free(
                        buf as *mut c_void,
                        b"pyopenssl\0".as_ptr() as *const c_char,
                        0,
                    );
                    result
                }
            }
        }
    }

    fn __richcmp__(
        &self,
        py: Python<'_>,
        other: &Bound<'_, PyAny>,
        op: pyo3::basic::CompareOp,
    ) -> PyResult<Py<PyAny>> {
        let other = match other.cast::<X509Name>() {
            Ok(o) => o,
            Err(_) => return Ok(py.NotImplemented()),
        };
        let other_ref = other.borrow();
        let cmp = self
            .name_ref()?
            .try_cmp(other_ref.name_ref()?)
            .map_err(|e| err_stack_to_py(py, e))?;
        let result = match op {
            pyo3::basic::CompareOp::Eq => cmp.is_eq(),
            pyo3::basic::CompareOp::Ne => cmp.is_ne(),
            pyo3::basic::CompareOp::Lt => cmp.is_lt(),
            pyo3::basic::CompareOp::Le => cmp.is_le(),
            pyo3::basic::CompareOp::Gt => cmp.is_gt(),
            pyo3::basic::CompareOp::Ge => cmp.is_ge(),
        };
        Ok(result.into_pyobject(py)?.to_owned().into_any().unbind())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        // X509_NAME_oneline is not exposed by rust-openssl.
        let mut buf = vec![0u8; 512];
        let result = unsafe {
            ffi_ext::X509_NAME_oneline(
                self.check()?,
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as c_int,
            )
        };
        openssl_assert!(py, Error, !result.is_null());
        let s = unsafe { util::text(buf.as_ptr() as *const c_char) };
        Ok(format!("<X509Name object '{}'>", s))
    }

    /// Return an integer representation of the first four bytes of the
    /// MD5 digest of the DER representation of the name.
    fn hash(&self) -> PyResult<u64> {
        // X509_NAME_hash is not exposed by rust-openssl.
        Ok(unsafe { ffi_ext::X509_NAME_hash(self.check()?) as u64 })
    }

    /// Return the DER encoding of this name.
    fn der(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        // i2d_X509_NAME is not exposed by rust-openssl.
        unsafe {
            let mut buf: *mut c_uchar = std::ptr::null_mut();
            let len = ffi::i2d_X509_NAME(self.check()?, &mut buf);
            openssl_assert!(py, Error, len >= 0);
            let result =
                PyBytes::new(py, std::slice::from_raw_parts(buf, len as usize));
            ffi::CRYPTO_free(
                buf as *mut c_void,
                b"pyopenssl\0".as_ptr() as *const c_char,
                0,
            );
            Ok(result.unbind())
        }
    }

    /// Returns the components of this name, as a sequence of 2-tuples.
    fn get_components<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let result = PyList::empty(py);
        for entry in self.name_ref()?.entries() {
            let name = entry.object().nid().short_name().unwrap_or("");
            let value = entry.data().as_slice();
            result.append((
                PyBytes::new(py, name.as_bytes()),
                PyBytes::new(py, value),
            ))?;
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// X509Req
// ---------------------------------------------------------------------------

/// An X.509 certificate signing requests.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509Req {
    req: SslX509Req,
    // Names handed out by get_subject() which alias our X509_REQ.
    subject_names: Vec<Py<X509Name>>,
}

const X509REQ_DEPRECATION: &str = "CSR support in pyOpenSSL is deprecated. \
    You should use the APIs in cryptography.";

impl X509Req {
    pub fn from_openssl(req: SslX509Req) -> X509Req {
        X509Req {
            req,
            subject_names: Vec::new(),
        }
    }
}

#[pymethods]
impl X509Req {
    #[new]
    fn new(py: Python<'_>) -> PyResult<X509Req> {
        util::warn(py, X509REQ_DEPRECATION, "DeprecationWarning", 2)?;
        // rust-openssl only offers X509ReqBuilder (write-only, consumed by
        // build()); pyOpenSSL's X509Req is freely mutable, so create a raw
        // X509_REQ and wrap it in the safe owner type.
        let req = unsafe {
            let req = ffi::X509_REQ_new();
            openssl_assert!(py, Error, !req.is_null());
            // Default to version 0.
            openssl_assert!(py, Error, ffi::X509_REQ_set_version(req, 0) == 1);
            SslX509Req::from_ptr(req)
        };
        Ok(X509Req::from_openssl(req))
    }

    /// Export as a ``cryptography`` certificate signing request.
    fn to_cryptography(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let der = dump_certificate_request_impl(py, FILETYPE_ASN1, self)?;
        let x509 = py.import("cryptography.x509")?;
        Ok(x509
            .call_method1("load_der_x509_csr", (PyBytes::new(py, &der),))?
            .unbind())
    }

    /// Construct based on a ``cryptography`` *crypto_req*.
    #[classmethod]
    fn from_cryptography(
        cls: &Bound<'_, PyType>,
        crypto_req: &Bound<'_, PyAny>,
    ) -> PyResult<X509Req> {
        let py = cls.py();
        let x509 = py.import("cryptography.x509")?;
        if !crypto_req.is_instance(&x509.getattr("CertificateSigningRequest")?)? {
            return Err(PyTypeError::new_err(
                "Must be a certificate signing request",
            ));
        }
        let serialization =
            py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        let der = crypto_req
            .call_method1("public_bytes", (encoding,))?
            .extract::<Vec<u8>>()?;
        load_certificate_request_impl(py, FILETYPE_ASN1, &der)
    }

    /// Set the public key of the certificate signing request.
    fn set_pubkey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = pkey
            .cast::<PKey>()
            .map_err(|_| PyTypeError::new_err("pkey must be a PKey instance"))?;
        // In-place mutation; X509ReqBuilder has set_pubkey but cannot wrap
        // an existing request.
        let result = unsafe {
            ffi::X509_REQ_set_pubkey(self.req.as_ptr(), pkey.borrow().pkey_ptr())
        };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Get the public key of the certificate signing request.
    fn get_pubkey(&self, py: Python<'_>) -> PyResult<PKey> {
        let pkey = self.req.public_key().map_err(|e| err_stack_to_py(py, e))?;
        Ok(PKey::from_public(pkey))
    }

    /// Set the version subfield (RFC 2986, section 4.1) of the certificate
    /// request.
    fn set_version(&self, py: Python<'_>, version: &Bound<'_, PyAny>) -> PyResult<()> {
        let version: c_long = version
            .extract()
            .map_err(|_| PyTypeError::new_err("version must be an int"))?;
        if version != 0 {
            return Err(PyValueError::new_err(
                "Invalid version. The only valid version for X509Req is 0.",
            ));
        }
        let result = unsafe { ffi::X509_REQ_set_version(self.req.as_ptr(), version) };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Get the version subfield (RFC 2459, section 4.1.2.1) of the
    /// certificate request.
    fn get_version(&self) -> i64 {
        self.req.version() as i64
    }

    /// Return the subject of this certificate signing request.
    fn get_subject(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        let py = slf.py();
        // The returned X509Name aliases the name inside this X509_REQ (no
        // safe representation exists for that).
        let name_ptr =
            unsafe { ffi::X509_REQ_get_subject_name(slf.borrow().req.as_ptr()) };
        openssl_assert!(py, Error, !name_ptr.is_null());
        let name = Py::new(
            py,
            X509Name {
                name: CPtr(name_ptr),
                owned: false,
                owner: Some(slf.clone().into_any().unbind()),
                dead: false,
            },
        )?;
        slf.borrow_mut().subject_names.push(name.clone_ref(py));
        Ok(name)
    }

    /// Sign the certificate signing request with this key and digest type.
    fn sign(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>, digest: &str) -> PyResult<()> {
        let pkey = pkey
            .cast::<PKey>()
            .map_err(|_| PyTypeError::new_err("pkey must be a PKey instance"))?;
        let pkey_ref = pkey.borrow();
        if pkey_ref.only_public {
            return Err(PyValueError::new_err("Key has only public part"));
        }
        if !pkey_ref.initialized {
            return Err(PyValueError::new_err("Key is uninitialized"));
        }
        let digest_obj = digest_by_name(py, digest)?;
        // Signing an *existing* request is in-place mutation;
        // X509ReqBuilder::sign cannot wrap one.
        let result = unsafe {
            ffi_ext::X509_REQ_sign(self.req.as_ptr(), pkey_ref.pkey_ptr(), digest_obj)
        };
        openssl_assert!(py, Error, result > 0);
        Ok(())
    }

    /// Verifies the signature on this certificate signing request.
    fn verify(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<bool> {
        let pkey = pkey
            .cast::<PKey>()
            .map_err(|_| PyTypeError::new_err("pkey must be a PKey instance"))?;
        let pkey_ref = pkey.borrow();
        match self.req.verify(pkey_ref.as_private_ref()) {
            Ok(true) => Ok(true),
            Ok(false) => Err(openssl_error!(py, Error)),
            Err(e) => Err(err_stack_to_py(py, e)),
        }
    }
}

fn digest_by_name(py: Python<'_>, digest: &str) -> PyResult<*const ffi::EVP_MD> {
    let _ = py;
    match MessageDigest::from_name(digest) {
        Some(md) => Ok(md.as_ptr()),
        None => Err(PyValueError::new_err("No such digest method")),
    }
}

// ---------------------------------------------------------------------------
// X509
// ---------------------------------------------------------------------------

/// An X.509 certificate.
///
/// Reads go through safe `X509Ref` views; the mutation methods
/// (`set_version`, `set_serial_number`, `sign`, `set_subject`, ...) have no
/// safe rust-openssl equivalent (the safe `X509` is immutable and
/// `X509Builder` cannot wrap an existing certificate), so they use
/// openssl-sys on the same pointer.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509 {
    cert: SslX509,
    subject_names: Vec<Py<X509Name>>,
    issuer_names: Vec<Py<X509Name>>,
}

impl X509 {
    pub fn from_openssl(cert: SslX509) -> X509 {
        X509 {
            cert,
            subject_names: Vec::new(),
            issuer_names: Vec::new(),
        }
    }

    pub fn x509_ptr(&self) -> *mut ffi::X509 {
        self.cert.as_ptr()
    }

    pub fn as_x509_ref(&self) -> &X509Ref {
        &self.cert
    }

    /// A refcounted handle to the same certificate.
    pub fn clone_openssl(&self) -> SslX509 {
        self.cert.to_owned()
    }

    fn get_name(
        slf: &Bound<'_, Self>,
        which: unsafe extern "C" fn(*const ffi::X509) -> *mut ffi::X509_NAME,
        issuer: bool,
    ) -> PyResult<Py<X509Name>> {
        let py = slf.py();
        // The returned X509Name aliases the name inside this certificate
        // (no safe representation exists for that).
        let name_ptr = unsafe { which(slf.borrow().cert.as_ptr()) };
        openssl_assert!(py, Error, !name_ptr.is_null());
        let name = Py::new(
            py,
            X509Name {
                name: CPtr(name_ptr),
                owned: false,
                owner: Some(slf.clone().into_any().unbind()),
                dead: false,
            },
        )?;
        let mut this = slf.borrow_mut();
        if issuer {
            this.issuer_names.push(name.clone_ref(py));
        } else {
            this.subject_names.push(name.clone_ref(py));
        }
        Ok(name)
    }

    fn set_name(
        &mut self,
        py: Python<'_>,
        which: unsafe extern "C" fn(*mut ffi::X509, *const ffi::X509_NAME) -> c_int,
        name: &Bound<'_, PyAny>,
        issuer: bool,
    ) -> PyResult<()> {
        let name = name
            .cast::<X509Name>()
            .map_err(|_| PyTypeError::new_err("name must be an X509Name"))?;
        let result = unsafe { which(self.cert.as_ptr(), name.borrow().check()?) };
        openssl_assert!(py, Error, result == 1);
        // Breaks the previously handed out aliasing names, but also
        // prevents use-after-free!
        let names = if issuer {
            std::mem::take(&mut self.issuer_names)
        } else {
            std::mem::take(&mut self.subject_names)
        };
        for n in names {
            n.borrow_mut(py).dead = true;
        }
        Ok(())
    }
}

#[pymethods]
impl X509 {
    #[new]
    fn new(py: Python<'_>) -> PyResult<X509> {
        // A new, empty, mutable certificate; rust-openssl's X509 cannot be
        // created empty, so wrap a raw X509_new in the safe owner type.
        let cert = unsafe {
            let x509 = ffi::X509_new();
            openssl_assert!(py, Error, !x509.is_null());
            SslX509::from_ptr(x509)
        };
        Ok(X509::from_openssl(cert))
    }

    /// Export as a ``cryptography`` certificate.
    fn to_cryptography(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let der = dump_certificate_impl(py, FILETYPE_ASN1, self)?;
        let x509 = py.import("cryptography.x509")?;
        Ok(x509
            .call_method1("load_der_x509_certificate", (PyBytes::new(py, &der),))?
            .unbind())
    }

    /// Construct based on a ``cryptography`` *crypto_cert*.
    #[classmethod]
    fn from_cryptography(
        cls: &Bound<'_, PyType>,
        crypto_cert: &Bound<'_, PyAny>,
    ) -> PyResult<X509> {
        let py = cls.py();
        let x509 = py.import("cryptography.x509")?;
        if !crypto_cert.is_instance(&x509.getattr("Certificate")?)? {
            return Err(PyTypeError::new_err("Must be a certificate"));
        }
        let serialization =
            py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        let der = crypto_cert
            .call_method1("public_bytes", (encoding,))?
            .extract::<Vec<u8>>()?;
        load_certificate_impl(py, FILETYPE_ASN1, &der)
    }

    /// Set the version number of the certificate. Note that the
    /// version value is zero-based, eg. a value of 0 is V1.
    fn set_version(&self, py: Python<'_>, version: &Bound<'_, PyAny>) -> PyResult<()> {
        let version: c_long = version
            .extract()
            .map_err(|_| PyTypeError::new_err("version must be an integer"))?;
        let result = unsafe { ffi::X509_set_version(self.cert.as_ptr(), version) };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Return the version number of the certificate.
    fn get_version(&self) -> i32 {
        self.cert.version()
    }

    /// Get the public key of the certificate.
    fn get_pubkey(&self, py: Python<'_>) -> PyResult<PKey> {
        let pkey = self.cert.public_key().map_err(|e| err_stack_to_py(py, e))?;
        Ok(PKey::from_public(pkey))
    }

    /// Set the public key of the certificate.
    fn set_pubkey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = pkey
            .cast::<PKey>()
            .map_err(|_| PyTypeError::new_err("pkey must be a PKey instance"))?;
        let result =
            unsafe { ffi::X509_set_pubkey(self.cert.as_ptr(), pkey.borrow().pkey_ptr()) };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Sign the certificate with this key and digest type.
    fn sign(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>, digest: &str) -> PyResult<()> {
        let pkey = pkey
            .cast::<PKey>()
            .map_err(|_| PyTypeError::new_err("pkey must be a PKey instance"))?;
        let pkey_ref = pkey.borrow();
        if pkey_ref.only_public {
            return Err(PyValueError::new_err("Key only has public part"));
        }
        if !pkey_ref.initialized {
            return Err(PyValueError::new_err("Key is uninitialized"));
        }
        let evp_md = digest_by_name(py, digest)?;
        let result =
            unsafe { ffi_ext::X509_sign(self.cert.as_ptr(), pkey_ref.pkey_ptr(), evp_md) };
        openssl_assert!(py, Error, result > 0);
        Ok(())
    }

    /// Return the signature algorithm used in the certificate.
    fn get_signature_algorithm(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        // X509Ref::signature_algorithm() reads the *outer* signature
        // algorithm (X509_get0_signature); pyOpenSSL reads the one inside
        // the TBS structure, for which rust-openssl has no accessor.
        let nid = unsafe {
            let sig_alg = ffi_ext::X509_get0_tbs_sigalg(self.cert.as_ptr());
            let mut alg: *const ffi::ASN1_OBJECT = std::ptr::null();
            ffi::X509_ALGOR_get0(
                &mut alg,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sig_alg,
            );
            Nid::from_raw(ffi::OBJ_obj2nid(alg))
        };
        if nid == Nid::UNDEF {
            return Err(PyValueError::new_err("Undefined signature algorithm"));
        }
        let name = nid.long_name().map_err(|e| err_stack_to_py(py, e))?;
        Ok(PyBytes::new(py, name.as_bytes()).unbind())
    }

    /// Return the digest of the X509 object.
    fn digest(&self, py: Python<'_>, digest_name: &str) -> PyResult<Py<PyBytes>> {
        let md = MessageDigest::from_name(digest_name)
            .ok_or_else(|| PyValueError::new_err("No such digest method"))?;
        let digest = self.cert.digest(md).map_err(|e| err_stack_to_py(py, e))?;
        let hex: Vec<String> = digest.iter().map(|b| format!("{:02X}", b)).collect();
        Ok(PyBytes::new(py, hex.join(":").as_bytes()).unbind())
    }

    /// Return the hash of the X509 subject.
    fn subject_name_hash(&self) -> u64 {
        // X509_subject_name_hash is not exposed by rust-openssl.
        unsafe { ffi_ext::X509_subject_name_hash(self.cert.as_ptr()) as u64 }
    }

    /// Set the serial number of the certificate.
    fn set_serial_number(&self, py: Python<'_>, serial: &Bound<'_, PyAny>) -> PyResult<()> {
        if !serial.is_instance_of::<pyo3::types::PyInt>() {
            return Err(PyTypeError::new_err("serial must be an integer"));
        }
        let hex_serial = serial
            .call_method1("__format__", ("x",))?
            .extract::<String>()?;
        let bignum =
            BigNum::from_hex_str(&hex_serial).map_err(|e| err_stack_to_py(py, e))?;
        let asn1_serial = bignum
            .to_asn1_integer()
            .map_err(|e| err_stack_to_py(py, e))?;
        let result = unsafe {
            ffi::X509_set_serialNumber(self.cert.as_ptr(), asn1_serial.as_ptr())
        };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Return the serial number of this certificate.
    fn get_serial_number(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let bignum = self
            .cert
            .serial_number()
            .to_bn()
            .map_err(|e| err_stack_to_py(py, e))?;
        let hex = bignum.to_hex_str().map_err(|e| err_stack_to_py(py, e))?;
        let int_type = py.get_type::<pyo3::types::PyInt>();
        Ok(int_type.call1((hex.to_string(), 16))?.unbind())
    }

    /// Adjust the time stamp on which the certificate stops being valid.
    #[allow(non_snake_case)]
    fn gmtime_adj_notAfter(&self, amount: &Bound<'_, PyAny>) -> PyResult<()> {
        let amount: c_long = amount
            .extract()
            .map_err(|_| PyTypeError::new_err("amount must be an integer"))?;
        unsafe {
            let not_after = ffi_ext::X509_getm_notAfter(self.cert.as_ptr());
            ffi_ext::X509_gmtime_adj(not_after, amount);
        }
        Ok(())
    }

    /// Adjust the timestamp on which the certificate starts being valid.
    #[allow(non_snake_case)]
    fn gmtime_adj_notBefore(&self, amount: &Bound<'_, PyAny>) -> PyResult<()> {
        let amount: c_long = amount
            .extract()
            .map_err(|_| PyTypeError::new_err("amount must be an integer"))?;
        unsafe {
            let not_before = ffi_ext::X509_getm_notBefore(self.cert.as_ptr());
            ffi_ext::X509_gmtime_adj(not_before, amount);
        }
        Ok(())
    }

    /// Check whether the certificate has expired.
    fn has_expired(&self, py: Python<'_>) -> PyResult<bool> {
        let time_bytes = self.get_notAfter(py)?;
        let time_bytes = match time_bytes {
            Some(b) => b,
            None => {
                return Err(PyValueError::new_err("Unable to determine notAfter"))
            }
        };
        let datetime = py.import("datetime")?;
        let dt_class = datetime.getattr("datetime")?;
        let time_str = std::str::from_utf8(time_bytes.as_bytes(py))
            .map_err(|e| PyValueError::new_err(e.to_string()))?
            .to_string();
        let not_after =
            dt_class.call_method1("strptime", (time_str, "%Y%m%d%H%M%SZ"))?;
        let utc = datetime.getattr("timezone")?.getattr("utc")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("tzinfo", py.None())?;
        let utcnow = dt_class
            .call_method1("now", (utc,))?
            .call_method("replace", (), Some(&kwargs))?;
        Ok(not_after.lt(&utcnow)?)
    }

    /// Get the timestamp at which the certificate starts being valid.
    #[allow(non_snake_case)]
    fn get_notBefore(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        // pyOpenSSL exposes ASN.1 times as raw `YYYYMMDDhhmmssZ` strings;
        // safe Asn1TimeRef only supports Display formatting.
        unsafe {
            util::get_asn1_time(py, ffi_ext::X509_getm_notBefore(self.cert.as_ptr()))
        }
    }

    /// Set the timestamp at which the certificate starts being valid.
    #[allow(non_snake_case)]
    fn set_notBefore(&self, py: Python<'_>, when: &Bound<'_, PyAny>) -> PyResult<()> {
        unsafe {
            util::set_asn1_time(
                py,
                ffi_ext::X509_getm_notBefore(self.cert.as_ptr()),
                when,
            )
        }
    }

    /// Get the timestamp at which the certificate stops being valid.
    #[allow(non_snake_case)]
    fn get_notAfter(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            util::get_asn1_time(py, ffi_ext::X509_getm_notAfter(self.cert.as_ptr()))
        }
    }

    /// Set the timestamp at which the certificate stops being valid.
    #[allow(non_snake_case)]
    fn set_notAfter(&self, py: Python<'_>, when: &Bound<'_, PyAny>) -> PyResult<()> {
        unsafe {
            util::set_asn1_time(
                py,
                ffi_ext::X509_getm_notAfter(self.cert.as_ptr()),
                when,
            )
        }
    }

    /// Return the issuer of this certificate.
    fn get_issuer(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        X509::get_name(slf, ffi::X509_get_issuer_name, true)
    }

    /// Set the issuer of this certificate.
    fn set_issuer(&mut self, py: Python<'_>, issuer: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_name(py, ffi::X509_set_issuer_name, issuer, true)
    }

    /// Return the subject of this certificate.
    fn get_subject(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        X509::get_name(slf, ffi::X509_get_subject_name, false)
    }

    /// Set the subject of this certificate.
    fn set_subject(&mut self, py: Python<'_>, subject: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_name(py, ffi::X509_set_subject_name, subject, false)
    }

    /// Get the number of extensions on this certificate.
    fn get_extension_count(&self) -> c_int {
        // X509_get_ext_count is not exposed by rust-openssl.
        unsafe { ffi::X509_get_ext_count(self.cert.as_ptr()) }
    }
}

// ---------------------------------------------------------------------------
// X509StoreFlags
// ---------------------------------------------------------------------------

/// Flags for X509 verification, used to change the behavior of
/// `X509Store`.
#[pyclass(module = "OpenSSL.crypto")]
pub struct X509StoreFlags;

#[pymethods]
impl X509StoreFlags {
    #[classattr]
    const CRL_CHECK: u64 = 0x4;
    #[classattr]
    const CRL_CHECK_ALL: u64 = 0x8;
    #[classattr]
    const IGNORE_CRITICAL: u64 = 0x10;
    #[classattr]
    const X509_STRICT: u64 = 0x20;
    #[classattr]
    const ALLOW_PROXY_CERTS: u64 = 0x40;
    #[classattr]
    const POLICY_CHECK: u64 = 0x80;
    #[classattr]
    const EXPLICIT_POLICY: u64 = 0x100;
    #[classattr]
    const INHIBIT_MAP: u64 = 0x400;
    #[classattr]
    const CHECK_SS_SIGNATURE: u64 = 0x4000;
    #[classattr]
    const PARTIAL_CHAIN: u64 = 0x80000;
}

// ---------------------------------------------------------------------------
// X509Store
// ---------------------------------------------------------------------------

/// An X.509 store.
///
/// Internally this wraps an `X509StoreBuilder` which is never
/// `build()`-en: pyOpenSSL stores stay mutable forever, while
/// rust-openssl's built `X509Store` is immutable. (The builder and the
/// built store are the same C object, so viewing the builder as an
/// `X509StoreRef` for verification is sound.)
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509Store {
    builder: X509StoreBuilder,
}

impl X509Store {
    /// Takes ownership of (a reference to) `store`.
    pub fn from_raw(store: *mut ffi::X509_STORE) -> X509Store {
        X509Store {
            builder: unsafe { X509StoreBuilder::from_ptr(store) },
        }
    }

    pub fn store_ptr(&self) -> *mut ffi::X509_STORE {
        self.builder.as_ptr()
    }

    pub fn as_store_ref(&self) -> &X509StoreRef {
        unsafe { X509StoreRef::from_ptr(self.builder.as_ptr()) }
    }
}

#[pymethods]
impl X509Store {
    #[new]
    fn new(py: Python<'_>) -> PyResult<X509Store> {
        let builder = X509StoreBuilder::new().map_err(|e| err_stack_to_py(py, e))?;
        Ok(X509Store { builder })
    }

    /// Adds a trusted certificate to this store.
    fn add_cert(&mut self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        let cert = cert
            .cast::<X509>()
            .map_err(|_| PyTypeError::new_err(()))?;
        let cert = cert.borrow().clone_openssl();
        self.builder
            .add_cert(cert)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Add a certificate revocation list to this store.
    fn add_crl(&self, py: Python<'_>, crl: &Bound<'_, PyAny>) -> PyResult<()> {
        let x509_mod = py.import("cryptography.x509")?;
        if !crl.is_instance(&x509_mod.getattr("CertificateRevocationList")?)? {
            return Err(PyTypeError::new_err(
                "CRL must be of type cryptography.x509.CertificateRevocationList",
            ));
        }
        let serialization =
            py.import("cryptography.hazmat.primitives.serialization")?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        let der = crl
            .call_method1("public_bytes", (encoding,))?
            .extract::<Vec<u8>>()?;
        let crl =
            openssl::x509::X509Crl::from_der(&der).map_err(|e| err_stack_to_py(py, e))?;
        // X509_STORE_add_crl is not exposed by rust-openssl.
        let result =
            unsafe { ffi_ext::X509_STORE_add_crl(self.builder.as_ptr(), crl.as_ptr()) };
        openssl_assert!(py, Error, result != 0);
        Ok(())
    }

    /// Set verification flags to this store.
    fn set_flags(&mut self, py: Python<'_>, flags: u64) -> PyResult<()> {
        let flags = openssl::x509::verify::X509VerifyFlags::from_bits_retain(flags as _);
        self.builder
            .set_flags(flags)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Set the time against which the certificates are verified.
    fn set_time(&mut self, py: Python<'_>, vfy_time: &Bound<'_, PyAny>) -> PyResult<()> {
        let calendar = py.import("calendar")?;
        let timestamp: libc::time_t = calendar
            .call_method1("timegm", (vfy_time.call_method0("timetuple")?,))?
            .extract()?;
        let mut param = X509VerifyParam::new().map_err(|e| err_stack_to_py(py, e))?;
        param.set_time(timestamp);
        self.builder
            .set_param(&param)
            .map_err(|e| err_stack_to_py(py, e))
    }

    /// Let X509Store know where we can find trusted certificates for the
    /// certificate chain.
    #[pyo3(signature = (cafile, capath=None))]
    fn load_locations(
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
        // X509_STORE_load_locations is not exposed by rust-openssl.
        let result = unsafe {
            ffi_ext::X509_STORE_load_locations(
                self.builder.as_ptr(),
                cafile.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                capath.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            )
        };
        if result == 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(())
    }

    /// The number of objects (certificates and CRLs) currently in the
    /// store. Internal/test helper.
    fn _object_count(&self) -> usize {
        #[allow(deprecated)]
        self.as_store_ref().objects().len()
    }
}

// ---------------------------------------------------------------------------
// X509StoreContext & X509StoreContextError
// ---------------------------------------------------------------------------

static X509_STORE_CONTEXT_ERROR: pyo3::sync::PyOnceLock<Py<PyAny>> =
    pyo3::sync::PyOnceLock::new();

pub fn store_context_error(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    Ok(X509_STORE_CONTEXT_ERROR
        .get_or_try_init(py, || -> PyResult<Py<PyAny>> {
            let locals = PyDict::new(py);
            py.run(
                c"class X509StoreContextError(Exception):
    '''
    An exception raised when an error occurred while verifying a certificate
    using `OpenSSL.X509StoreContext.verify_certificate`.

    :ivar certificate: The certificate which caused verificate failure.
    :type certificate: :class:`X509`
    '''

    def __init__(self, message, errors, certificate):
        super().__init__(message)
        self.errors = errors
        self.certificate = certificate
",
                None,
                Some(&locals),
            )?;
            let cls = locals.get_item("X509StoreContextError")?.unwrap();
            cls.setattr("__module__", "OpenSSL.crypto")?;
            Ok(cls.unbind())
        })?
        .bind(py)
        .clone())
}

/// An X.509 store context.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509StoreContext {
    store: Py<X509Store>,
    cert: Py<X509>,
    chain: Vec<Py<X509>>,
}

impl X509StoreContext {
    fn build_chain_stack(&self, py: Python<'_>) -> PyResult<Stack<SslX509>> {
        let mut stack = Stack::new().map_err(|e| err_stack_to_py(py, e))?;
        for cert in &self.chain {
            stack
                .push(cert.borrow(py).clone_openssl())
                .map_err(|e| err_stack_to_py(py, e))?;
        }
        Ok(stack)
    }

    /// Run X509_verify_cert; on failure raise X509StoreContextError, on
    /// success invoke `on_success` with the store context (while it is
    /// still alive) to extract any results.
    fn verify_with<T>(
        &self,
        py: Python<'_>,
        on_success: impl FnOnce(&mut openssl::x509::X509StoreContextRef) -> PyResult<T>,
    ) -> PyResult<T> {
        let chain = self.build_chain_stack(py)?;
        let mut ctx = SslX509StoreContext::new().map_err(|e| err_stack_to_py(py, e))?;
        let store = self.store.borrow(py);
        let cert = self.cert.borrow(py);
        ctx.init(store.as_store_ref(), cert.as_x509_ref(), &chain, |ctx| {
            let ok = ctx.verify_cert()?;
            if ok {
                Ok(on_success(ctx))
            } else {
                let error = ctx.error();
                let message = error.error_string().to_string();
                let depth = ctx.error_depth();
                // A context error should always be associated with a
                // certificate, so we expect this to never be None.
                let failed_cert = ctx
                    .current_cert()
                    .map(|c| c.to_owned())
                    .expect("verification error without a certificate");
                Ok((|| -> PyResult<T> {
                    let errors = PyList::new(
                        py,
                        [
                            error.as_raw().into_pyobject(py)?.into_any(),
                            depth.into_pyobject(py)?.into_any(),
                            message.clone().into_pyobject(py)?.into_any(),
                        ],
                    )?;
                    let pycert = Py::new(py, X509::from_openssl(failed_cert))?;
                    let exc_type = store_context_error(py)?;
                    let exc = exc_type.call1((message, errors, pycert))?;
                    Err(PyErr::from_value(exc))
                })())
            }
        })
        .map_err(|e| err_stack_to_py(py, e))?
    }
}

#[pymethods]
impl X509StoreContext {
    #[new]
    #[pyo3(signature = (store, certificate, chain=None))]
    fn new(
        py: Python<'_>,
        store: &Bound<'_, PyAny>,
        certificate: &Bound<'_, PyAny>,
        chain: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<X509StoreContext> {
        let store = store
            .cast::<X509Store>()
            .map_err(|_| PyTypeError::new_err("store must be an X509Store"))?;
        let certificate = certificate
            .cast::<X509>()
            .map_err(|_| PyTypeError::new_err("certificate must be an X509"))?;
        let mut chain_vec = Vec::new();
        if let Some(chain) = chain {
            if !chain.is_none() {
                for item in chain.try_iter()? {
                    let item = item?;
                    let cert = item.cast::<X509>().map_err(|_| {
                        PyTypeError::new_err(
                            "One of the elements is not an X509 instance",
                        )
                    })?;
                    chain_vec.push(cert.clone().unbind());
                }
            }
        }
        let _ = py;
        Ok(X509StoreContext {
            store: store.clone().unbind(),
            cert: certificate.clone().unbind(),
            chain: chain_vec,
        })
    }

    /// Set the context's X.509 store.
    fn set_store(&mut self, store: &Bound<'_, PyAny>) -> PyResult<()> {
        let store = store
            .cast::<X509Store>()
            .map_err(|_| PyTypeError::new_err("store must be an X509Store"))?;
        self.store = store.clone().unbind();
        Ok(())
    }

    /// Verify a certificate in a context.
    fn verify_certificate(&self, py: Python<'_>) -> PyResult<()> {
        self.verify_with(py, |_| Ok(()))
    }

    /// Verify a certificate in a context and return the complete validated
    /// chain.
    fn get_verified_chain(&self, py: Python<'_>) -> PyResult<Vec<Py<X509>>> {
        self.verify_with(py, |ctx| {
            let mut result = Vec::new();
            if let Some(chain) = ctx.chain() {
                for cert in chain {
                    result.push(Py::new(py, X509::from_openssl(cert.to_owned()))?);
                }
            }
            Ok(result)
        })
    }
}

// ---------------------------------------------------------------------------
// load/dump functions
// ---------------------------------------------------------------------------

/// Coerce a Python "filetype" argument to a c_int; non-integers become -1
/// so that they fall through to the `ValueError` raised for unknown types.
fn filetype_arg(t: &Bound<'_, PyAny>) -> c_int {
    if t.is_instance_of::<pyo3::types::PyInt>() {
        t.extract().unwrap_or(-1)
    } else {
        -1
    }
}

fn str_or_bytes(py: Python<'_>, buffer: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(s) = buffer.cast::<PyString>() {
        let s = s.to_cow()?;
        if !s.is_ascii() {
            return Err(pyo3::exceptions::PyUnicodeEncodeError::new_err(
                "'ascii' codec can't encode characters",
            ));
        }
        let _ = py;
        Ok(s.as_bytes().to_vec())
    } else {
        util::buffer_to_vec(buffer)
    }
}

pub fn load_certificate_impl(
    py: Python<'_>,
    type_: c_int,
    buffer: &[u8],
) -> PyResult<X509> {
    let cert = if type_ == FILETYPE_PEM {
        SslX509::from_pem(buffer)
    } else if type_ == FILETYPE_ASN1 {
        SslX509::from_der(buffer)
    } else {
        return Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
        ));
    };
    Ok(X509::from_openssl(cert.map_err(|e| err_stack_to_py(py, e))?))
}

/// Load a certificate (X509) from the string *buffer* encoded with the
/// type *type*.
#[pyfunction]
fn load_certificate(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    buffer: &Bound<'_, PyAny>,
) -> PyResult<X509> {
    let buffer = str_or_bytes(py, buffer)?;
    load_certificate_impl(py, filetype_arg(r#type), &buffer)
}

pub fn dump_certificate_impl(py: Python<'_>, type_: c_int, cert: &X509) -> PyResult<Vec<u8>> {
    if type_ == FILETYPE_PEM {
        cert.cert.to_pem().map_err(|e| err_stack_to_py(py, e))
    } else if type_ == FILETYPE_ASN1 {
        cert.cert.to_der().map_err(|e| err_stack_to_py(py, e))
    } else if type_ == FILETYPE_TEXT {
        // X509_print_ex is not exposed by rust-openssl.
        let bio = util::MemBio::new(py)?;
        let result =
            unsafe { ffi_ext::X509_print_ex(bio.as_ptr(), cert.cert.as_ptr(), 0, 0) };
        openssl_assert!(py, Error, result == 1);
        Ok(bio.contents())
    } else {
        Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
             FILETYPE_TEXT",
        ))
    }
}

/// Dump the certificate *cert* into a buffer string encoded with the type
/// *type*.
#[pyfunction]
fn dump_certificate(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    cert: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let cert = cert
        .cast::<X509>()
        .map_err(|_| PyTypeError::new_err("cert must be an X509"))?;
    let result = dump_certificate_impl(py, filetype_arg(r#type), &cert.borrow())?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn dump_publickey_impl(py: Python<'_>, type_: c_int, pkey: &PKey) -> PyResult<Vec<u8>> {
    // Works for both public and private keys: the PUBKEY serializers only
    // consult the public half, so viewing the key as `PKeyRef<Public>` is
    // sound.
    let key_ref: &PKeyRef<Public> = unsafe { PKeyRef::from_ptr(pkey.pkey_ptr()) };
    let result = if type_ == FILETYPE_PEM {
        key_ref.public_key_to_pem()
    } else if type_ == FILETYPE_ASN1 {
        key_ref.public_key_to_der()
    } else {
        return Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
        ));
    };
    result.map_err(|e| err_stack_to_py(py, e))
}

/// Dump a public key to a buffer.
#[pyfunction]
fn dump_publickey(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    pkey: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let pkey = pkey
        .cast::<PKey>()
        .map_err(|_| PyTypeError::new_err("pkey must be a PKey"))?;
    let result = dump_publickey_impl(py, filetype_arg(r#type), &pkey.borrow())?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn dump_privatekey_impl(
    py: Python<'_>,
    type_: c_int,
    pkey: &PKey,
    cipher: Option<&str>,
    passphrase: Option<&Bound<'_, PyAny>>,
) -> PyResult<Vec<u8>> {
    let cipher_obj = if let Some(cipher) = cipher {
        if passphrase.is_none() {
            return Err(PyTypeError::new_err(
                "if a value is given for cipher one must also be given for \
                 passphrase",
            ));
        }
        let nid = Asn1Object::from_str(cipher)
            .map(|o| o.nid())
            .unwrap_or(Nid::UNDEF);
        match Cipher::from_nid(nid) {
            Some(c) => Some(c),
            None => return Err(PyValueError::new_err("Invalid cipher name")),
        }
    } else {
        None
    };

    // Validates the passphrase type and that encryption is only requested
    // for PEM output (raising ValueError otherwise).
    let passphrase_bytes = resolve_passphrase(py, type_, passphrase)?;

    let key_ref = pkey.as_private_ref();
    if type_ == FILETYPE_PEM {
        match cipher_obj {
            Some(cipher_obj) => {
                // rust-openssl's encrypting PEM serializer only accepts
                // passphrase *bytes* (no callback variant), so the Python
                // callback was resolved eagerly above.
                let passphrase_bytes =
                    passphrase_bytes.expect("cipher implies passphrase");
                key_ref
                    .private_key_to_pem_pkcs8_passphrase(cipher_obj, &passphrase_bytes)
                    .map_err(|e| err_stack_to_py(py, e))
            }
            None => key_ref
                .private_key_to_pem_pkcs8()
                .map_err(|e| err_stack_to_py(py, e)),
        }
    } else if type_ == FILETYPE_ASN1 {
        key_ref
            .private_key_to_der()
            .map_err(|e| err_stack_to_py(py, e))
    } else if type_ == FILETYPE_TEXT {
        if pkey.key.id() != ffi::EVP_PKEY_RSA {
            return Err(PyTypeError::new_err(
                "Only RSA keys are supported for FILETYPE_TEXT",
            ));
        }
        // RSA_print is not exposed by rust-openssl.
        let rsa = key_ref.rsa().map_err(|e| err_stack_to_py(py, e))?;
        let bio = util::MemBio::new(py)?;
        let result = unsafe { ffi_ext::RSA_print(bio.as_ptr(), rsa.as_ptr(), 0) };
        openssl_assert!(py, Error, result != 0);
        Ok(bio.contents())
    } else {
        Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
             FILETYPE_TEXT",
        ))
    }
}

/// Dump the private key *pkey* into a buffer string encoded with the type
/// *type*.
#[pyfunction]
#[pyo3(signature = (r#type, pkey, cipher=None, passphrase=None))]
fn dump_privatekey(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    pkey: &Bound<'_, PyAny>,
    cipher: Option<&str>,
    passphrase: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyBytes>> {
    let pkey = pkey
        .cast::<PKey>()
        .map_err(|_| PyTypeError::new_err("pkey must be a PKey"))?;
    let result = dump_privatekey_impl(
        py,
        filetype_arg(r#type),
        &pkey.borrow(),
        cipher,
        passphrase,
    )?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn load_publickey_impl(py: Python<'_>, type_: c_int, buffer: &[u8]) -> PyResult<PKey> {
    let key = if type_ == FILETYPE_PEM {
        SslPKey::public_key_from_pem(buffer)
    } else if type_ == FILETYPE_ASN1 {
        SslPKey::public_key_from_der(buffer)
    } else {
        return Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
        ));
    };
    Ok(PKey::from_public(key.map_err(|e| err_stack_to_py(py, e))?))
}

/// Load a public key from a buffer.
#[pyfunction]
fn load_publickey(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    buffer: &Bound<'_, PyAny>,
) -> PyResult<PKey> {
    let buffer = str_or_bytes(py, buffer)?;
    load_publickey_impl(py, filetype_arg(r#type), &buffer)
}

pub fn load_privatekey_impl(
    py: Python<'_>,
    type_: c_int,
    buffer: &[u8],
    passphrase: Option<&Bound<'_, PyAny>>,
) -> PyResult<PKey> {
    let mut helper = PassphraseHelper::new(py, type_, passphrase, false, false, None)?;
    let key = if type_ == FILETYPE_PEM {
        let result =
            SslPKey::private_key_from_pem_callback(buffer, helper.rust_callback(py, 0));
        helper.raise_if_problem(py)?;
        result
    } else if type_ == FILETYPE_ASN1 {
        SslPKey::private_key_from_der(buffer)
    } else {
        return Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
        ));
    };
    Ok(PKey::from_private(key.map_err(|e| err_stack_to_py(py, e))?))
}

/// Load a private key (PKey) from the string *buffer* encoded with the
/// type *type*.
#[pyfunction]
#[pyo3(signature = (r#type, buffer, passphrase=None))]
fn load_privatekey(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    buffer: &Bound<'_, PyAny>,
    passphrase: Option<&Bound<'_, PyAny>>,
) -> PyResult<PKey> {
    let buffer = str_or_bytes(py, buffer)?;
    load_privatekey_impl(py, filetype_arg(r#type), &buffer, passphrase)
}

pub fn dump_certificate_request_impl(
    py: Python<'_>,
    type_: c_int,
    req: &X509Req,
) -> PyResult<Vec<u8>> {
    if type_ == FILETYPE_PEM {
        req.req.to_pem().map_err(|e| err_stack_to_py(py, e))
    } else if type_ == FILETYPE_ASN1 {
        req.req.to_der().map_err(|e| err_stack_to_py(py, e))
    } else if type_ == FILETYPE_TEXT {
        // X509_REQ_print_ex is not exposed by rust-openssl.
        let bio = util::MemBio::new(py)?;
        let result =
            unsafe { ffi_ext::X509_REQ_print_ex(bio.as_ptr(), req.req.as_ptr(), 0, 0) };
        openssl_assert!(py, Error, result != 0);
        Ok(bio.contents())
    } else {
        Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
             FILETYPE_TEXT",
        ))
    }
}

/// Dump the certificate request *req* into a buffer string encoded with
/// the type *type*.
#[pyfunction]
fn dump_certificate_request(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    req: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    util::warn(py, X509REQ_DEPRECATION, "DeprecationWarning", 2)?;
    let req = req
        .cast::<X509Req>()
        .map_err(|_| PyTypeError::new_err("req must be an X509Req"))?;
    let result = dump_certificate_request_impl(py, filetype_arg(r#type), &req.borrow())?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn load_certificate_request_impl(
    py: Python<'_>,
    type_: c_int,
    buffer: &[u8],
) -> PyResult<X509Req> {
    let req = if type_ == FILETYPE_PEM {
        SslX509Req::from_pem(buffer)
    } else if type_ == FILETYPE_ASN1 {
        SslX509Req::from_der(buffer)
    } else {
        return Err(PyValueError::new_err(
            "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
        ));
    };
    Ok(X509Req::from_openssl(req.map_err(|e| err_stack_to_py(py, e))?))
}

/// Load a certificate request (X509Req) from the string *buffer* encoded
/// with the type *type*.
#[pyfunction]
fn load_certificate_request(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    buffer: &Bound<'_, PyAny>,
) -> PyResult<X509Req> {
    util::warn(py, X509REQ_DEPRECATION, "DeprecationWarning", 2)?;
    let buffer = str_or_bytes(py, buffer)?;
    load_certificate_request_impl(py, filetype_arg(r#type), &buffer)
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "_crypto")?;
    m.add("FILETYPE_PEM", FILETYPE_PEM)?;
    m.add("FILETYPE_ASN1", FILETYPE_ASN1)?;
    m.add("FILETYPE_TEXT", FILETYPE_TEXT)?;
    m.add("TYPE_RSA", TYPE_RSA)?;
    m.add("TYPE_DSA", TYPE_DSA)?;
    m.add("TYPE_DH", TYPE_DH)?;
    m.add("TYPE_EC", TYPE_EC)?;
    m.add("Error", py.get_type::<Error>())?;
    m.add_class::<PKey>()?;
    m.add_class::<EllipticCurve>()?;
    m.add_class::<X509Name>()?;
    m.add_class::<X509Req>()?;
    m.add_class::<X509>()?;
    m.add_class::<X509StoreFlags>()?;
    m.add_class::<X509Store>()?;
    m.add_class::<X509StoreContext>()?;
    m.add("X509StoreContextError", store_context_error(py)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_elliptic_curves, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(get_elliptic_curve, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(load_certificate, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(dump_certificate, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(dump_publickey, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(dump_privatekey, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(load_publickey, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(load_privatekey, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(dump_certificate_request, &m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(load_certificate_request, &m)?)?;
    let _ = exception_from_error_queue; // referenced via macro
    Ok(m)
}
