//! Implementation of the `OpenSSL.crypto` module.

use libc::{c_char, c_int, c_long, c_uchar, c_void};
use openssl_sys as ffi;
use pyo3::exceptions::{
    PyAttributeError, PyTypeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyTuple, PyType};

use crate::ffi_ext::{self, CPtr};
use crate::util::{
    self, cstring, exception_from_error_queue, MemBio,
};
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

// ---------------------------------------------------------------------------
// Passphrase helper (port of `_PassphraseHelper`)
// ---------------------------------------------------------------------------

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
            if p.downcast::<PyBytes>().is_err() && !p.is_callable() {
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

    pub fn callback(&self) -> ffi_ext::PasswdCb {
        if self.passphrase.is_some() {
            Some(raw_pem_password_cb)
        } else {
            None
        }
    }

    pub fn callback_args(&mut self) -> *mut c_void {
        if self.passphrase.is_some() {
            self as *mut PassphraseHelper as *mut c_void
        } else {
            std::ptr::null_mut()
        }
    }

    pub fn raise_if_problem(&mut self, py: Python<'_>) -> PyResult<()> {
        if !self.problems.is_empty() {
            // Flush the OpenSSL error queue
            let _ = util::error_queue(py)?;
            return Err(self.problems.remove(0));
        }
        Ok(())
    }

    fn read_passphrase(
        &mut self,
        py: Python<'_>,
        buf: *mut c_char,
        size: c_int,
        rwflag: c_int,
    ) -> PyResult<c_int> {
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
                passphrase.call1((size, rwflag != 0, userdata))?
            } else {
                passphrase.call1((rwflag,))?
            }
        } else {
            passphrase.clone()
        };
        let result = result
            .downcast::<PyBytes>()
            .map_err(|_| PyValueError::new_err("Bytes expected"))?;
        let mut data = result.as_bytes();
        if data.len() > size as usize {
            if self.truncate {
                data = &data[..size as usize];
            } else {
                return Err(PyValueError::new_err(
                    "passphrase returned by callback is too long",
                ));
            }
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf as *mut u8,
                data.len(),
            );
        }
        Ok(data.len() as c_int)
    }
}

pub unsafe extern "C" fn raw_pem_password_cb(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
) -> c_int {
    let helper = &mut *(userdata as *mut PassphraseHelper);
    Python::attach(|py| {
        match helper.read_passphrase(py, buf, size, rwflag) {
            Ok(n) => n,
            Err(e) => {
                helper.problems.push(e);
                0
            }
        }
    })
}

// ---------------------------------------------------------------------------
// PKey
// ---------------------------------------------------------------------------

/// A class representing an DSA or RSA public key or key pair.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct PKey {
    pkey: CPtr<ffi::EVP_PKEY>,
    pub only_public: bool,
    pub initialized: bool,
}

impl Drop for PKey {
    fn drop(&mut self) {
        if !self.pkey.is_null() {
            unsafe { ffi::EVP_PKEY_free(self.pkey.get()) }
        }
    }
}

impl PKey {
    pub fn from_raw(pkey: *mut ffi::EVP_PKEY, only_public: bool) -> PKey {
        PKey {
            pkey: CPtr(pkey),
            only_public,
            initialized: true,
        }
    }

    pub fn pkey_ptr(&self) -> *mut ffi::EVP_PKEY {
        self.pkey.get()
    }
}

#[pymethods]
impl PKey {
    #[new]
    fn new(py: Python<'_>) -> PyResult<PKey> {
        let pkey = unsafe { ffi::EVP_PKEY_new() };
        openssl_assert!(py, Error, !pkey.is_null());
        Ok(PKey {
            pkey: CPtr(pkey),
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
        let serialization = py.import(
            "cryptography.hazmat.primitives.serialization",
        )?;
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

        let serialization = py.import(
            "cryptography.hazmat.primitives.serialization",
        )?;
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
            unsafe {
                let exponent = ffi::BN_new();
                openssl_assert!(py, Error, !exponent.is_null());
                ffi::BN_set_word(exponent, ffi::RSA_F4 as ffi::BN_ULONG);
                let rsa = ffi::RSA_new();
                let result = ffi::RSA_generate_key_ex(
                    rsa,
                    bits as c_int,
                    exponent,
                    std::ptr::null_mut(),
                );
                ffi::BN_free(exponent);
                openssl_assert!(py, Error, result == 1);
                let result =
                    ffi::EVP_PKEY_assign(self.pkey.get(), ffi::EVP_PKEY_RSA, rsa as *mut c_void);
                openssl_assert!(py, Error, result == 1);
            }
        } else if type_ == TYPE_DSA {
            unsafe {
                let dsa = ffi::DSA_new();
                openssl_assert!(py, Error, !dsa.is_null());
                let res = ffi::DSA_generate_parameters_ex(
                    dsa,
                    bits as c_int,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if res != 1 {
                    ffi::DSA_free(dsa);
                    return Err(openssl_error!(py, Error));
                }
                if ffi::DSA_generate_key(dsa) != 1 {
                    ffi::DSA_free(dsa);
                    return Err(openssl_error!(py, Error));
                }
                let res = ffi::EVP_PKEY_set1_DSA(self.pkey.get(), dsa);
                ffi::DSA_free(dsa);
                openssl_assert!(py, Error, res == 1);
            }
        } else {
            return Err(Error::new_err("No such key type"));
        }
        self.initialized = true;
        Ok(())
    }

    /// Check the consistency of an RSA private key.
    fn check(&self, py: Python<'_>) -> PyResult<bool> {
        if self.only_public {
            return Err(PyTypeError::new_err("public key only"));
        }
        unsafe {
            if ffi::EVP_PKEY_id(self.pkey.get()) != ffi::EVP_PKEY_RSA {
                return Err(PyTypeError::new_err(
                    "Only RSA keys can currently be checked.",
                ));
            }
            let rsa = ffi::EVP_PKEY_get1_RSA(self.pkey.get());
            let result = ffi::RSA_check_key(rsa);
            ffi::RSA_free(rsa);
            if result == 1 {
                return Ok(true);
            }
            Err(openssl_error!(py, Error))
        }
    }

    /// Returns the type of the key
    fn r#type(&self) -> c_int {
        unsafe { ffi::EVP_PKEY_id(self.pkey.get()) }
    }

    /// Returns the number of bits of the key
    fn bits(&self) -> c_int {
        unsafe { ffi::EVP_PKEY_bits(self.pkey.get()) }
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
        match other.downcast::<EllipticCurve>() {
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
        match other.downcast::<EllipticCurve>() {
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
    fn _to_EC_KEY(&self, py: Python<'_>) -> PyResult<()> {
        unsafe {
            let key = ffi::EC_KEY_new_by_curve_name(self.nid);
            openssl_assert!(py, Error, !key.is_null());
            ffi::EC_KEY_free(key);
        }
        Ok(())
    }
}

fn load_elliptic_curves(py: Python<'_>) -> PyResult<Vec<Py<EllipticCurve>>> {
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
            let sn = ffi::OBJ_nid2sn(c.nid);
            let name = util::text(sn);
            result.push(Py::new(
                py,
                EllipticCurve { name, nid: c.nid },
            )?);
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
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509Name {
    pub name: CPtr<ffi::X509_NAME>,
    pub owned: bool,
    // Keeps the object owning the underlying X509_NAME alive (e.g. an X509
    // certificate when this name aliases its subject/issuer field).
    #[pyo3(get, name = "_owner")]
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

    fn check(&self) -> PyResult<*mut ffi::X509_NAME> {
        if self.dead || self.name.is_null() {
            Err(PyAttributeError::new_err("No such attribute"))
        } else {
            Ok(self.name.get())
        }
    }
}

fn x509_name_from_dup(
    py: Python<'_>,
    src: *mut ffi::X509_NAME,
) -> PyResult<X509Name> {
    let copy = unsafe { ffi::X509_NAME_dup(src) };
    openssl_assert!(py, Error, !copy.is_null());
    Ok(X509Name {
        name: CPtr(copy),
        owned: true,
        owner: None,
        dead: false,
    })
}

#[pymethods]
impl X509Name {
    /// Create a new X509Name, copying the given X509Name instance.
    #[new]
    fn new(py: Python<'_>, name: &Bound<'_, PyAny>) -> PyResult<X509Name> {
        let name = name.downcast::<X509Name>().map_err(|_| {
            PyTypeError::new_err("name must be an X509Name")
        })?;
        let src = name.borrow().check()?;
        x509_name_from_dup(py, src)
    }

    fn __setattr__(
        slf: &Bound<'_, Self>,
        name: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let py = slf.py();
        // Attributes with a leading underscore are stored on the instance
        // (the Python implementation routed these to object.__setattr__).
        if let Ok(s) = name.downcast::<PyString>() {
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
            let _ = util::error_queue(py)?;
            return Err(PyAttributeError::new_err("No such attribute"));
        }
        let this = slf.borrow();
        let name_ptr = this.check()?;
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
            let value_bytes: Vec<u8> = if let Ok(s) = value.downcast::<PyString>() {
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
            let _ = util::error_queue(py)?;
            return Err(PyAttributeError::new_err("No such attribute"));
        }
        let name_ptr = self.check()?;
        unsafe {
            let entry_index = ffi::X509_NAME_get_index_by_NID(name_ptr, nid, -1);
            if entry_index == -1 {
                return Ok(py.None());
            }
            let entry = ffi::X509_NAME_get_entry(name_ptr, entry_index);
            let data = ffi::X509_NAME_ENTRY_get_data(entry);
            let mut buf: *mut c_uchar = std::ptr::null_mut();
            let length = ffi_ext::ASN1_STRING_to_UTF8(&mut buf, data);
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

    fn __richcmp__(
        &self,
        py: Python<'_>,
        other: &Bound<'_, PyAny>,
        op: pyo3::basic::CompareOp,
    ) -> PyResult<Py<PyAny>> {
        let other = match other.downcast::<X509Name>() {
            Ok(o) => o,
            Err(_) => return Ok(py.NotImplemented()),
        };
        let cmp = unsafe {
            ffi::X509_NAME_cmp(self.check()?, other.borrow().check()?)
        };
        let result = match op {
            pyo3::basic::CompareOp::Eq => cmp == 0,
            pyo3::basic::CompareOp::Ne => cmp != 0,
            pyo3::basic::CompareOp::Lt => cmp < 0,
            pyo3::basic::CompareOp::Le => cmp <= 0,
            pyo3::basic::CompareOp::Gt => cmp > 0,
            pyo3::basic::CompareOp::Ge => cmp >= 0,
        };
        Ok(result.into_pyobject(py)?.to_owned().into_any().unbind())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
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
        Ok(unsafe { ffi_ext::X509_NAME_hash(self.check()?) as u64 })
    }

    /// Return the DER encoding of this name.
    fn der(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
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
    fn get_components<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyList>> {
        let result = PyList::empty(py);
        let name_ptr = self.check()?;
        unsafe {
            for i in 0..ffi::X509_NAME_entry_count(name_ptr) {
                let ent = ffi::X509_NAME_get_entry(name_ptr, i);
                let fname = ffi::X509_NAME_ENTRY_get_object(ent);
                let fval = ffi::X509_NAME_ENTRY_get_data(ent);
                let nid = ffi::OBJ_obj2nid(fname);
                let name = ffi::OBJ_nid2sn(nid);
                let name_bytes =
                    std::ffi::CStr::from_ptr(name).to_bytes();
                let data_len =
                    ffi::ASN1_STRING_length(fval as *const ffi::ASN1_STRING);
                let data_ptr =
                    ffi::ASN1_STRING_get0_data(fval as *const ffi::ASN1_STRING);
                let value =
                    std::slice::from_raw_parts(data_ptr, data_len as usize);
                result.append((
                    PyBytes::new(py, name_bytes),
                    PyBytes::new(py, value),
                ))?;
            }
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
    req: CPtr<ffi::X509_REQ>,
    // Names handed out by get_subject() which alias our X509_REQ.
    subject_names: Vec<Py<X509Name>>,
}

impl Drop for X509Req {
    fn drop(&mut self) {
        if !self.req.is_null() {
            unsafe { ffi::X509_REQ_free(self.req.get()) }
        }
    }
}

const X509REQ_DEPRECATION: &str = "CSR support in pyOpenSSL is deprecated. \
    You should use the APIs in cryptography.";

impl X509Req {
    fn from_raw(req: *mut ffi::X509_REQ) -> X509Req {
        X509Req {
            req: CPtr(req),
            subject_names: Vec::new(),
        }
    }
}

#[pymethods]
impl X509Req {
    #[new]
    fn new(py: Python<'_>) -> PyResult<X509Req> {
        util::warn(py, X509REQ_DEPRECATION, "DeprecationWarning", 2)?;
        let req = unsafe { ffi::X509_REQ_new() };
        openssl_assert!(py, Error, !req.is_null());
        let mut result = X509Req::from_raw(req);
        // Default to version 0.
        unsafe {
            openssl_assert!(py, Error, ffi::X509_REQ_set_version(result.req.get(), 0) == 1);
        }
        result.subject_names = Vec::new();
        Ok(result)
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
        let serialization = py.import(
            "cryptography.hazmat.primitives.serialization",
        )?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        let der = crypto_req
            .call_method1("public_bytes", (encoding,))?
            .extract::<Vec<u8>>()?;
        load_certificate_request_impl(py, FILETYPE_ASN1, &der)
    }

    /// Set the public key of the certificate signing request.
    fn set_pubkey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = pkey.downcast::<PKey>().map_err(|_| {
            PyTypeError::new_err("pkey must be a PKey instance")
        })?;
        let result = unsafe {
            ffi::X509_REQ_set_pubkey(self.req.get(), pkey.borrow().pkey_ptr())
        };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Get the public key of the certificate signing request.
    fn get_pubkey(&self, py: Python<'_>) -> PyResult<PKey> {
        let pkey = unsafe { ffi::X509_REQ_get_pubkey(self.req.get()) };
        openssl_assert!(py, Error, !pkey.is_null());
        Ok(PKey::from_raw(pkey, true))
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
        let result = unsafe { ffi::X509_REQ_set_version(self.req.get(), version) };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Get the version subfield (RFC 2459, section 4.1.2.1) of the
    /// certificate request.
    fn get_version(&self) -> c_long {
        unsafe { ffi::X509_REQ_get_version(self.req.get()) }
    }

    /// Return the subject of this certificate signing request.
    fn get_subject(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        let py = slf.py();
        let name_ptr = unsafe { ffi::X509_REQ_get_subject_name(slf.borrow().req.get()) };
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
        let pkey = pkey.downcast::<PKey>().map_err(|_| {
            PyTypeError::new_err("pkey must be a PKey instance")
        })?;
        let pkey_ref = pkey.borrow();
        if pkey_ref.only_public {
            return Err(PyValueError::new_err("Key has only public part"));
        }
        if !pkey_ref.initialized {
            return Err(PyValueError::new_err("Key is uninitialized"));
        }
        let digest_obj = unsafe {
            let digest_c = cstring(py, digest.as_bytes())?;
            ffi_ext::EVP_get_digestbyname(digest_c.as_ptr())
        };
        if digest_obj.is_null() {
            return Err(PyValueError::new_err("No such digest method"));
        }
        let result = unsafe {
            ffi_ext::X509_REQ_sign(self.req.get(), pkey_ref.pkey_ptr(), digest_obj)
        };
        openssl_assert!(py, Error, result > 0);
        Ok(())
    }

    /// Verifies the signature on this certificate signing request.
    fn verify(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<bool> {
        let pkey = pkey.downcast::<PKey>().map_err(|_| {
            PyTypeError::new_err("pkey must be a PKey instance")
        })?;
        let result = unsafe {
            ffi_ext::X509_REQ_verify(self.req.get(), pkey.borrow().pkey_ptr())
        };
        if result <= 0 {
            return Err(openssl_error!(py, Error));
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// X509
// ---------------------------------------------------------------------------

/// An X.509 certificate.
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509 {
    x509: CPtr<ffi::X509>,
    subject_names: Vec<Py<X509Name>>,
    issuer_names: Vec<Py<X509Name>>,
}

impl Drop for X509 {
    fn drop(&mut self) {
        if !self.x509.is_null() {
            unsafe { ffi::X509_free(self.x509.get()) }
        }
    }
}

impl X509 {
    /// Takes ownership of `x509`.
    pub fn from_raw(x509: *mut ffi::X509) -> X509 {
        X509 {
            x509: CPtr(x509),
            subject_names: Vec::new(),
            issuer_names: Vec::new(),
        }
    }

    pub fn x509_ptr(&self) -> *mut ffi::X509 {
        self.x509.get()
    }

    fn get_name(
        slf: &Bound<'_, Self>,
        which: unsafe extern "C" fn(*const ffi::X509) -> *mut ffi::X509_NAME,
        issuer: bool,
    ) -> PyResult<Py<X509Name>> {
        let py = slf.py();
        let name_ptr = unsafe { which(slf.borrow().x509.get()) };
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
        let name = name.downcast::<X509Name>().map_err(|_| {
            PyTypeError::new_err("name must be an X509Name")
        })?;
        let result = unsafe { which(self.x509.get(), name.borrow().check()?) };
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
        let x509 = unsafe { ffi::X509_new() };
        openssl_assert!(py, Error, !x509.is_null());
        Ok(X509::from_raw(x509))
    }

    /// Export as a ``cryptography`` certificate.
    fn to_cryptography(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let der = dump_certificate_impl(py, FILETYPE_ASN1, self)?;
        let x509 = py.import("cryptography.x509")?;
        Ok(x509
            .call_method1(
                "load_der_x509_certificate",
                (PyBytes::new(py, &der),),
            )?
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
        let serialization = py.import(
            "cryptography.hazmat.primitives.serialization",
        )?;
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
        let result = unsafe { ffi::X509_set_version(self.x509.get(), version) };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Return the version number of the certificate.
    fn get_version(&self) -> c_long {
        unsafe { ffi::X509_get_version(self.x509.get()) }
    }

    /// Get the public key of the certificate.
    fn get_pubkey(&self, py: Python<'_>) -> PyResult<PKey> {
        let pkey = unsafe { ffi::X509_get_pubkey(self.x509.get()) };
        if pkey.is_null() {
            return Err(openssl_error!(py, Error));
        }
        Ok(PKey::from_raw(pkey, true))
    }

    /// Set the public key of the certificate.
    fn set_pubkey(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let pkey = pkey.downcast::<PKey>().map_err(|_| {
            PyTypeError::new_err("pkey must be a PKey instance")
        })?;
        let result = unsafe {
            ffi::X509_set_pubkey(self.x509.get(), pkey.borrow().pkey_ptr())
        };
        openssl_assert!(py, Error, result == 1);
        Ok(())
    }

    /// Sign the certificate with this key and digest type.
    fn sign(&self, py: Python<'_>, pkey: &Bound<'_, PyAny>, digest: &str) -> PyResult<()> {
        let pkey = pkey.downcast::<PKey>().map_err(|_| {
            PyTypeError::new_err("pkey must be a PKey instance")
        })?;
        let pkey_ref = pkey.borrow();
        if pkey_ref.only_public {
            return Err(PyValueError::new_err("Key only has public part"));
        }
        if !pkey_ref.initialized {
            return Err(PyValueError::new_err("Key is uninitialized"));
        }
        let evp_md = unsafe {
            let digest_c = cstring(py, digest.as_bytes())?;
            ffi_ext::EVP_get_digestbyname(digest_c.as_ptr())
        };
        if evp_md.is_null() {
            return Err(PyValueError::new_err("No such digest method"));
        }
        let result =
            unsafe { ffi_ext::X509_sign(self.x509.get(), pkey_ref.pkey_ptr(), evp_md) };
        openssl_assert!(py, Error, result > 0);
        Ok(())
    }

    /// Return the signature algorithm used in the certificate.
    fn get_signature_algorithm(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        unsafe {
            let sig_alg = ffi_ext::X509_get0_tbs_sigalg(self.x509.get());
            let mut alg: *const ffi::ASN1_OBJECT = std::ptr::null();
            ffi::X509_ALGOR_get0(
                &mut alg,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sig_alg,
            );
            let nid = ffi::OBJ_obj2nid(alg);
            if nid == 0 {
                return Err(PyValueError::new_err(
                    "Undefined signature algorithm",
                ));
            }
            let name = std::ffi::CStr::from_ptr(ffi::OBJ_nid2ln(nid));
            Ok(PyBytes::new(py, name.to_bytes()).unbind())
        }
    }

    /// Return the digest of the X509 object.
    fn digest(&self, py: Python<'_>, digest_name: &str) -> PyResult<Py<PyBytes>> {
        let digest = unsafe {
            let digest_c = cstring(py, digest_name.as_bytes())?;
            ffi_ext::EVP_get_digestbyname(digest_c.as_ptr())
        };
        if digest.is_null() {
            return Err(PyValueError::new_err("No such digest method"));
        }
        const EVP_MAX_MD_SIZE: usize = 64;
        let mut buf = [0u8; EVP_MAX_MD_SIZE];
        let mut length: libc::c_uint = EVP_MAX_MD_SIZE as libc::c_uint;
        let result = unsafe {
            ffi_ext::X509_digest(
                self.x509.get(),
                digest,
                buf.as_mut_ptr(),
                &mut length,
            )
        };
        openssl_assert!(py, Error, result == 1);
        let hex: Vec<String> = buf[..length as usize]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        Ok(PyBytes::new(py, hex.join(":").as_bytes()).unbind())
    }

    /// Return the hash of the X509 subject.
    fn subject_name_hash(&self) -> u64 {
        unsafe { ffi_ext::X509_subject_name_hash(self.x509.get()) as u64 }
    }

    /// Set the serial number of the certificate.
    fn set_serial_number(
        &self,
        py: Python<'_>,
        serial: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        if !serial.is_instance_of::<pyo3::types::PyInt>() {
            return Err(PyTypeError::new_err("serial must be an integer"));
        }
        let hex_serial = serial
            .call_method1("__format__", ("x",))?
            .extract::<String>()?;
        let hex_serial_c = cstring(py, hex_serial.as_bytes())?;
        unsafe {
            let mut bignum_serial: *mut ffi::BIGNUM = std::ptr::null_mut();
            let result = ffi::BN_hex2bn(&mut bignum_serial, hex_serial_c.as_ptr());
            openssl_assert!(py, Error, result != 0);
            let asn1_serial =
                ffi::BN_to_ASN1_INTEGER(bignum_serial, std::ptr::null_mut());
            ffi::BN_free(bignum_serial);
            openssl_assert!(py, Error, !asn1_serial.is_null());
            let set_result = ffi::X509_set_serialNumber(self.x509.get(), asn1_serial);
            ffi::ASN1_INTEGER_free(asn1_serial);
            openssl_assert!(py, Error, set_result == 1);
        }
        Ok(())
    }

    /// Return the serial number of this certificate.
    fn get_serial_number(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        unsafe {
            let asn1_serial = ffi::X509_get_serialNumber(self.x509.get());
            let bignum_serial =
                ffi::ASN1_INTEGER_to_BN(asn1_serial, std::ptr::null_mut());
            let hex_serial = ffi::BN_bn2hex(bignum_serial);
            let hexstring = util::text(hex_serial);
            ffi::CRYPTO_free(
                hex_serial as *mut c_void,
                b"pyopenssl\0".as_ptr() as *const c_char,
                0,
            );
            ffi::BN_free(bignum_serial);
            let int_type = py.get_type::<pyo3::types::PyInt>();
            Ok(int_type.call1((hexstring, 16))?.unbind())
        }
    }

    /// Adjust the time stamp on which the certificate stops being valid.
    fn gmtime_adj_notAfter(&self, amount: &Bound<'_, PyAny>) -> PyResult<()> {
        let amount: c_long = amount
            .extract()
            .map_err(|_| PyTypeError::new_err("amount must be an integer"))?;
        unsafe {
            let not_after = ffi_ext::X509_getm_notAfter(self.x509.get());
            ffi_ext::X509_gmtime_adj(not_after, amount);
        }
        Ok(())
    }

    /// Adjust the timestamp on which the certificate starts being valid.
    fn gmtime_adj_notBefore(&self, amount: &Bound<'_, PyAny>) -> PyResult<()> {
        let amount: c_long = amount
            .extract()
            .map_err(|_| PyTypeError::new_err("amount must be an integer"))?;
        unsafe {
            let not_before = ffi_ext::X509_getm_notBefore(self.x509.get());
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
                return Err(PyValueError::new_err(
                    "Unable to determine notAfter",
                ))
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
        unsafe {
            util::get_asn1_time(py, ffi_ext::X509_getm_notBefore(self.x509.get()))
        }
    }

    /// Set the timestamp at which the certificate starts being valid.
    #[allow(non_snake_case)]
    fn set_notBefore(&self, py: Python<'_>, when: &Bound<'_, PyAny>) -> PyResult<()> {
        unsafe {
            util::set_asn1_time(py, ffi_ext::X509_getm_notBefore(self.x509.get()), when)
        }
    }

    /// Get the timestamp at which the certificate stops being valid.
    #[allow(non_snake_case)]
    fn get_notAfter(&self, py: Python<'_>) -> PyResult<Option<Py<PyBytes>>> {
        unsafe {
            util::get_asn1_time(py, ffi_ext::X509_getm_notAfter(self.x509.get()))
        }
    }

    /// Set the timestamp at which the certificate stops being valid.
    #[allow(non_snake_case)]
    fn set_notAfter(&self, py: Python<'_>, when: &Bound<'_, PyAny>) -> PyResult<()> {
        unsafe {
            util::set_asn1_time(py, ffi_ext::X509_getm_notAfter(self.x509.get()), when)
        }
    }

    /// Return the issuer of this certificate.
    fn get_issuer(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        X509::get_name(slf, ffi::X509_get_issuer_name, true)
    }

    /// Set the issuer of this certificate.
    fn set_issuer(
        &mut self,
        py: Python<'_>,
        issuer: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_name(py, ffi::X509_set_issuer_name, issuer, true)
    }

    /// Return the subject of this certificate.
    fn get_subject(slf: &Bound<'_, Self>) -> PyResult<Py<X509Name>> {
        X509::get_name(slf, ffi::X509_get_subject_name, false)
    }

    /// Set the subject of this certificate.
    fn set_subject(
        &mut self,
        py: Python<'_>,
        subject: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set_name(py, ffi::X509_set_subject_name, subject, false)
    }

    /// Get the number of extensions on this certificate.
    fn get_extension_count(&self) -> c_int {
        unsafe { ffi::X509_get_ext_count(self.x509.get()) }
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
#[pyclass(module = "OpenSSL.crypto", subclass, dict)]
pub struct X509Store {
    store: CPtr<ffi::X509_STORE>,
}

impl Drop for X509Store {
    fn drop(&mut self) {
        if !self.store.is_null() {
            unsafe { ffi::X509_STORE_free(self.store.get()) }
        }
    }
}

impl X509Store {
    /// Takes ownership of (a reference to) `store`.
    pub fn from_raw(store: *mut ffi::X509_STORE) -> X509Store {
        X509Store { store: CPtr(store) }
    }

    pub fn store_ptr(&self) -> *mut ffi::X509_STORE {
        self.store.get()
    }
}

#[pymethods]
impl X509Store {
    #[new]
    fn new(py: Python<'_>) -> PyResult<X509Store> {
        let store = unsafe { ffi::X509_STORE_new() };
        openssl_assert!(py, Error, !store.is_null());
        Ok(X509Store { store: CPtr(store) })
    }

    /// Adds a trusted certificate to this store.
    fn add_cert(&self, py: Python<'_>, cert: &Bound<'_, PyAny>) -> PyResult<()> {
        let cert = cert
            .downcast::<X509>()
            .map_err(|_| PyTypeError::new_err(()))?;
        let res = unsafe {
            ffi::X509_STORE_add_cert(self.store.get(), cert.borrow().x509_ptr())
        };
        openssl_assert!(py, Error, res == 1);
        Ok(())
    }

    /// Add a certificate revocation list to this store.
    fn add_crl(&self, py: Python<'_>, crl: &Bound<'_, PyAny>) -> PyResult<()> {
        let x509_mod = py.import("cryptography.x509")?;
        if !crl.is_instance(&x509_mod.getattr("CertificateRevocationList")?)? {
            return Err(PyTypeError::new_err(
                "CRL must be of type cryptography.x509.CertificateRevocationList",
            ));
        }
        let serialization = py.import(
            "cryptography.hazmat.primitives.serialization",
        )?;
        let encoding = serialization.getattr("Encoding")?.getattr("DER")?;
        let der = crl
            .call_method1("public_bytes", (encoding,))?
            .extract::<Vec<u8>>()?;
        let bio = MemBio::from_data(py, &der)?;
        unsafe {
            let openssl_crl =
                ffi_ext::d2i_X509_CRL_bio(bio.as_ptr(), std::ptr::null_mut());
            openssl_assert!(py, Error, !openssl_crl.is_null());
            let result = ffi_ext::X509_STORE_add_crl(self.store.get(), openssl_crl);
            ffi::X509_CRL_free(openssl_crl);
            openssl_assert!(py, Error, result != 0);
        }
        Ok(())
    }

    /// Set verification flags to this store.
    fn set_flags(&self, py: Python<'_>, flags: u64) -> PyResult<()> {
        let result = unsafe {
            ffi::X509_STORE_set_flags(self.store.get(), flags as libc::c_ulong)
        };
        openssl_assert!(py, Error, result != 0);
        Ok(())
    }

    /// Set the time against which the certificates are verified.
    fn set_time(&self, py: Python<'_>, vfy_time: &Bound<'_, PyAny>) -> PyResult<()> {
        let calendar = py.import("calendar")?;
        let timestamp: libc::time_t = calendar
            .call_method1("timegm", (vfy_time.call_method0("timetuple")?,))?
            .extract()?;
        unsafe {
            let param = ffi::X509_VERIFY_PARAM_new();
            openssl_assert!(py, Error, !param.is_null());
            ffi::X509_VERIFY_PARAM_set_time(param, timestamp);
            let result = ffi::X509_STORE_set1_param(self.store.get(), param);
            ffi::X509_VERIFY_PARAM_free(param);
            openssl_assert!(py, Error, result != 0);
        }
        Ok(())
    }

    /// The number of objects (certificates and CRLs) currently in the
    /// store. Internal/test helper.
    fn _object_count(&self) -> i32 {
        unsafe {
            let sk_obj = ffi::X509_STORE_get0_objects(self.store.get());
            if sk_obj.is_null() {
                return 0;
            }
            ffi::OPENSSL_sk_num(sk_obj as *mut ffi::OPENSSL_STACK)
        }
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
            Some(f) => Some(cstring(py, &util::path_bytes(py, f)?)?),
            None => None,
        };
        let capath = match capath {
            Some(p) => Some(cstring(py, &util::path_bytes(py, p)?)?),
            None => None,
        };
        let result = unsafe {
            ffi_ext::X509_STORE_load_locations(
                self.store.get(),
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

struct OwnedStack(*mut ffi::stack_st_X509);

impl Drop for OwnedStack {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                // Equivalent to sk_X509_pop_free.
                let sk = self.0 as *mut ffi::OPENSSL_STACK;
                for i in 0..ffi::OPENSSL_sk_num(sk) {
                    let x = ffi::OPENSSL_sk_value(sk, i) as *mut ffi::X509;
                    ffi::X509_free(x);
                }
                ffi::OPENSSL_sk_free(sk);
            }
        }
    }
}

impl X509StoreContext {
    fn build_certificate_stack(
        py: Python<'_>,
        certificates: &[Py<X509>],
    ) -> PyResult<OwnedStack> {
        if certificates.is_empty() {
            return Ok(OwnedStack(std::ptr::null_mut()));
        }
        unsafe {
            let stack = ffi::OPENSSL_sk_new_null() as *mut ffi::stack_st_X509;
            openssl_assert!(py, Error, !stack.is_null());
            let stack = OwnedStack(stack);
            for cert in certificates {
                let ptr = cert.borrow(py).x509_ptr();
                openssl_assert!(py, Error, ffi::X509_up_ref(ptr) > 0);
                if ffi::OPENSSL_sk_push(
                    stack.0 as *mut ffi::OPENSSL_STACK,
                    ptr as *const c_void,
                ) <= 0
                {
                    ffi::X509_free(ptr);
                    return Err(openssl_error!(py, Error));
                }
            }
            Ok(stack)
        }
    }

    /// Convert an OpenSSL native context error failure into a Python
    /// exception.
    unsafe fn exception_from_context(
        py: Python<'_>,
        store_ctx: *mut ffi::X509_STORE_CTX,
    ) -> PyResult<PyErr> {
        let error = ffi::X509_STORE_CTX_get_error(store_ctx);
        let message =
            util::text(ffi::X509_verify_cert_error_string(error as c_long));
        let errors = PyList::new(
            py,
            [
                error.into_pyobject(py)?.into_any(),
                ffi::X509_STORE_CTX_get_error_depth(store_ctx)
                    .into_pyobject(py)?
                    .into_any(),
                message.clone().into_pyobject(py)?.into_any(),
            ],
        )?;
        // A context error should always be associated with a certificate.
        let x509 = ffi::X509_STORE_CTX_get_current_cert(store_ctx);
        let cert = ffi::X509_dup(x509);
        let pycert = Py::new(py, X509::from_raw(cert))?;
        let exc_type = store_context_error(py)?;
        let exc = exc_type.call1((message, errors, pycert))?;
        Ok(PyErr::from_value(exc))
    }

    fn verify_certificate_impl(
        &self,
        py: Python<'_>,
    ) -> PyResult<VerifiedStoreCtx> {
        unsafe {
            let store_ctx = ffi::X509_STORE_CTX_new();
            openssl_assert!(py, Error, !store_ctx.is_null());
            let store_ctx = VerifiedStoreCtx(store_ctx);
            let chain = X509StoreContext::build_certificate_stack(py, &self.chain)?;
            let ret = ffi::X509_STORE_CTX_init(
                store_ctx.0,
                self.store.borrow(py).store_ptr(),
                self.cert.borrow(py).x509_ptr(),
                chain.0,
            );
            openssl_assert!(py, Error, ret == 1);
            let ret = ffi::X509_verify_cert(store_ctx.0);
            if ret <= 0 {
                return Err(X509StoreContext::exception_from_context(
                    py, store_ctx.0,
                )?);
            }
            // Keep the chain alive until verification has finished.
            drop(chain);
            Ok(store_ctx)
        }
    }
}

struct VerifiedStoreCtx(*mut ffi::X509_STORE_CTX);

impl Drop for VerifiedStoreCtx {
    fn drop(&mut self) {
        unsafe { ffi::X509_STORE_CTX_free(self.0) }
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
            .downcast::<X509Store>()
            .map_err(|_| PyTypeError::new_err("store must be an X509Store"))?;
        let certificate = certificate
            .downcast::<X509>()
            .map_err(|_| PyTypeError::new_err("certificate must be an X509"))?;
        let mut chain_vec = Vec::new();
        if let Some(chain) = chain {
            if !chain.is_none() {
                for item in chain.try_iter()? {
                    let item = item?;
                    let cert = item.downcast::<X509>().map_err(|_| {
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
            .downcast::<X509Store>()
            .map_err(|_| PyTypeError::new_err("store must be an X509Store"))?;
        self.store = store.clone().unbind();
        Ok(())
    }

    /// Verify a certificate in a context.
    fn verify_certificate(&self, py: Python<'_>) -> PyResult<()> {
        self.verify_certificate_impl(py)?;
        Ok(())
    }

    /// Verify a certificate in a context and return the complete validated
    /// chain.
    fn get_verified_chain(&self, py: Python<'_>) -> PyResult<Vec<Py<X509>>> {
        let store_ctx = self.verify_certificate_impl(py)?;
        unsafe {
            // X509_STORE_CTX_get1_chain returns a deep copy of the chain.
            let cert_stack = ffi_ext::X509_STORE_CTX_get1_chain(store_ctx.0);
            openssl_assert!(py, Error, !cert_stack.is_null());
            let sk = cert_stack as *mut ffi::OPENSSL_STACK;
            let mut result = Vec::new();
            for i in 0..ffi::OPENSSL_sk_num(sk) {
                let cert = ffi::OPENSSL_sk_value(sk, i) as *mut ffi::X509;
                openssl_assert!(py, Error, !cert.is_null());
                result.push(Py::new(py, X509::from_raw(cert))?);
            }
            // Free the stack but not the members, which are now owned by
            // the X509 instances.
            ffi::OPENSSL_sk_free(sk);
            Ok(result)
        }
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
    if let Ok(s) = buffer.downcast::<PyString>() {
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
    let bio = MemBio::from_data(py, buffer)?;
    let x509 = unsafe {
        if type_ == FILETYPE_PEM {
            ffi::PEM_read_bio_X509(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        } else if type_ == FILETYPE_ASN1 {
            ffi::d2i_X509_bio(bio.as_ptr(), std::ptr::null_mut())
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
            ));
        }
    };
    if x509.is_null() {
        return Err(openssl_error!(py, Error));
    }
    Ok(X509::from_raw(x509))
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

pub fn dump_certificate_impl(
    py: Python<'_>,
    type_: c_int,
    cert: &X509,
) -> PyResult<Vec<u8>> {
    let bio = MemBio::new(py)?;
    let result_code = unsafe {
        if type_ == FILETYPE_PEM {
            ffi::PEM_write_bio_X509(bio.as_ptr(), cert.x509_ptr())
        } else if type_ == FILETYPE_ASN1 {
            ffi::i2d_X509_bio(bio.as_ptr(), cert.x509_ptr())
        } else if type_ == FILETYPE_TEXT {
            ffi_ext::X509_print_ex(bio.as_ptr(), cert.x509_ptr(), 0, 0)
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
                 FILETYPE_TEXT",
            ));
        }
    };
    openssl_assert!(py, Error, result_code == 1);
    Ok(bio.contents())
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
        .downcast::<X509>()
        .map_err(|_| PyTypeError::new_err("cert must be an X509"))?;
    let result = dump_certificate_impl(py, filetype_arg(r#type), &cert.borrow())?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn dump_publickey_impl(
    py: Python<'_>,
    type_: c_int,
    pkey: &PKey,
) -> PyResult<Vec<u8>> {
    let bio = MemBio::new(py)?;
    let result_code = unsafe {
        if type_ == FILETYPE_PEM {
            ffi_ext::PEM_write_bio_PUBKEY(bio.as_ptr(), pkey.pkey_ptr())
        } else if type_ == FILETYPE_ASN1 {
            ffi_ext::i2d_PUBKEY_bio(bio.as_ptr(), pkey.pkey_ptr())
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
            ));
        }
    };
    if result_code != 1 {
        return Err(openssl_error!(py, Error));
    }
    Ok(bio.contents())
}

/// Dump a public key to a buffer.
#[pyfunction]
fn dump_publickey(
    py: Python<'_>,
    r#type: &Bound<'_, PyAny>,
    pkey: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    let pkey = pkey
        .downcast::<PKey>()
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
    let bio = MemBio::new(py)?;
    let cipher_obj = if let Some(cipher) = cipher {
        if passphrase.is_none() {
            return Err(PyTypeError::new_err(
                "if a value is given for cipher one must also be given for \
                 passphrase",
            ));
        }
        let cipher_c = cstring(py, cipher.as_bytes())?;
        let obj = unsafe { ffi::EVP_get_cipherbyname(cipher_c.as_ptr()) };
        if obj.is_null() {
            return Err(PyValueError::new_err("Invalid cipher name"));
        }
        obj
    } else {
        std::ptr::null()
    };

    let mut helper =
        PassphraseHelper::new(py, type_, passphrase, false, false, None)?;
    let result_code = unsafe {
        if type_ == FILETYPE_PEM {
            let r = ffi_ext::PEM_write_bio_PrivateKey(
                bio.as_ptr(),
                pkey.pkey_ptr(),
                cipher_obj,
                std::ptr::null(),
                0,
                helper.callback(),
                helper.callback_args(),
            );
            helper.raise_if_problem(py)?;
            r
        } else if type_ == FILETYPE_ASN1 {
            ffi_ext::i2d_PrivateKey_bio(bio.as_ptr(), pkey.pkey_ptr())
        } else if type_ == FILETYPE_TEXT {
            if ffi::EVP_PKEY_id(pkey.pkey_ptr()) != ffi::EVP_PKEY_RSA {
                return Err(PyTypeError::new_err(
                    "Only RSA keys are supported for FILETYPE_TEXT",
                ));
            }
            let rsa = ffi::EVP_PKEY_get1_RSA(pkey.pkey_ptr());
            let r = ffi_ext::RSA_print(bio.as_ptr(), rsa, 0);
            ffi::RSA_free(rsa);
            r
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
                 FILETYPE_TEXT",
            ));
        }
    };
    openssl_assert!(py, Error, result_code != 0);
    Ok(bio.contents())
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
        .downcast::<PKey>()
        .map_err(|_| PyTypeError::new_err("pkey must be a PKey"))?;
    let result =
        dump_privatekey_impl(py, filetype_arg(r#type), &pkey.borrow(), cipher, passphrase)?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn load_publickey_impl(
    py: Python<'_>,
    type_: c_int,
    buffer: &[u8],
) -> PyResult<PKey> {
    let bio = MemBio::from_data(py, buffer)?;
    let evp_pkey = unsafe {
        if type_ == FILETYPE_PEM {
            ffi_ext::PEM_read_bio_PUBKEY(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        } else if type_ == FILETYPE_ASN1 {
            ffi_ext::d2i_PUBKEY_bio(bio.as_ptr(), std::ptr::null_mut())
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
            ));
        }
    };
    if evp_pkey.is_null() {
        return Err(openssl_error!(py, Error));
    }
    Ok(PKey::from_raw(evp_pkey, true))
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
    let bio = MemBio::from_data(py, buffer)?;
    let mut helper =
        PassphraseHelper::new(py, type_, passphrase, false, false, None)?;
    let evp_pkey = unsafe {
        if type_ == FILETYPE_PEM {
            let r = ffi_ext::PEM_read_bio_PrivateKey(
                bio.as_ptr(),
                std::ptr::null_mut(),
                helper.callback(),
                helper.callback_args(),
            );
            helper.raise_if_problem(py)?;
            r
        } else if type_ == FILETYPE_ASN1 {
            ffi_ext::d2i_PrivateKey_bio(bio.as_ptr(), std::ptr::null_mut())
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
            ));
        }
    };
    if evp_pkey.is_null() {
        return Err(openssl_error!(py, Error));
    }
    Ok(PKey::from_raw(evp_pkey, false))
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
    let bio = MemBio::new(py)?;
    let result_code = unsafe {
        if type_ == FILETYPE_PEM {
            ffi::PEM_write_bio_X509_REQ(bio.as_ptr(), req.req.get())
        } else if type_ == FILETYPE_ASN1 {
            ffi::i2d_X509_REQ_bio(bio.as_ptr(), req.req.get())
        } else if type_ == FILETYPE_TEXT {
            ffi_ext::X509_REQ_print_ex(bio.as_ptr(), req.req.get(), 0, 0)
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or \
                 FILETYPE_TEXT",
            ));
        }
    };
    openssl_assert!(py, Error, result_code != 0);
    Ok(bio.contents())
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
        .downcast::<X509Req>()
        .map_err(|_| PyTypeError::new_err("req must be an X509Req"))?;
    let result = dump_certificate_request_impl(py, filetype_arg(r#type), &req.borrow())?;
    Ok(PyBytes::new(py, &result).unbind())
}

pub fn load_certificate_request_impl(
    py: Python<'_>,
    type_: c_int,
    buffer: &[u8],
) -> PyResult<X509Req> {
    let bio = MemBio::from_data(py, buffer)?;
    let req = unsafe {
        if type_ == FILETYPE_PEM {
            ffi::PEM_read_bio_X509_REQ(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            )
        } else if type_ == FILETYPE_ASN1 {
            ffi_ext::d2i_X509_REQ_bio(bio.as_ptr(), std::ptr::null_mut())
        } else {
            return Err(PyValueError::new_err(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1",
            ));
        }
    };
    if req.is_null() {
        return Err(openssl_error!(py, Error));
    }
    Ok(X509Req::from_raw(req))
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
