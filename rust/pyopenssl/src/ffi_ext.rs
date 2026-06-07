//! Declarations for OpenSSL functions, macros, and constants that
//! rust-openssl (`openssl-sys` 0.9.x) does not currently expose. Everything
//! in this module is a workaround for missing rust-openssl functionality;
//! if these are ever added upstream this module should shrink.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_long, c_uchar, c_ulong, c_void, size_t, time_t};
use openssl_sys as ffi;

/// A raw pointer wrapper which we promise to only access while holding the
/// GIL (matching the thread-safety level of the old cffi implementation).
pub struct CPtr<T>(pub *mut T);
unsafe impl<T> Send for CPtr<T> {}
unsafe impl<T> Sync for CPtr<T> {}

impl<T> CPtr<T> {
    pub fn get(&self) -> *mut T {
        self.0
    }
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

#[repr(C)]
pub struct EC_builtin_curve {
    pub nid: c_int,
    pub comment: *const c_char,
}

pub enum BIO_ADDR {}

pub type PasswdCb =
    Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>;

extern "C" {
    // libssl
    pub fn SSL_set_fd(ssl: *mut ffi::SSL, fd: c_int) -> c_int;
    pub fn SSL_want(ssl: *const ffi::SSL) -> c_int;
    pub fn SSL_get1_session(ssl: *mut ffi::SSL) -> *mut ffi::SSL_SESSION;
    pub fn SSL_renegotiate(ssl: *mut ffi::SSL) -> c_int;
    pub fn SSL_renegotiate_pending(ssl: *const ffi::SSL) -> c_int;
    pub fn SSL_get_client_CA_list(
        ssl: *const ffi::SSL,
    ) -> *mut ffi::stack_st_X509_NAME;
    pub fn DTLSv1_listen(ssl: *mut ffi::SSL, addr: *mut BIO_ADDR) -> c_int;
    pub fn DTLS_get_data_mtu(ssl: *const ffi::SSL) -> size_t;
    pub fn BIO_ADDR_new() -> *mut BIO_ADDR;
    pub fn BIO_ADDR_free(addr: *mut BIO_ADDR);
    pub fn SSL_CTX_set_default_passwd_cb(ctx: *mut ffi::SSL_CTX, cb: PasswdCb);
    pub fn SSL_CTX_set_default_passwd_cb_userdata(
        ctx: *mut ffi::SSL_CTX,
        u: *mut c_void,
    );
    pub fn SSL_CTX_set_info_callback(
        ctx: *mut ffi::SSL_CTX,
        cb: Option<unsafe extern "C" fn(*const ffi::SSL, c_int, c_int)>,
    );
    pub fn SSL_set_info_callback(
        ssl: *mut ffi::SSL,
        cb: Option<unsafe extern "C" fn(*const ffi::SSL, c_int, c_int)>,
    );
    pub fn SSL_CTX_set_keylog_callback(
        ctx: *mut ffi::SSL_CTX,
        cb: Option<unsafe extern "C" fn(*const ffi::SSL, *const c_char)>,
    );
    pub fn SSL_CTX_set_cookie_generate_cb(
        ctx: *mut ffi::SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                *mut ffi::SSL,
                *mut c_uchar,
                *mut libc::c_uint,
            ) -> c_int,
        >,
    );
    pub fn SSL_CTX_set_cookie_verify_cb(
        ctx: *mut ffi::SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                *mut ffi::SSL,
                *const c_uchar,
                libc::c_uint,
            ) -> c_int,
        >,
    );
    #[cfg(ossl320)]
    pub fn SSL_get0_group_name(ssl: *mut ffi::SSL) -> *const c_char;
    pub fn SSL_CTX_get_verify_depth(ctx: *const ffi::SSL_CTX) -> c_int;
    pub fn SSL_CTX_set_timeout(ctx: *mut ffi::SSL_CTX, t: c_long) -> c_long;
    pub fn SSL_CTX_get_timeout(ctx: *const ffi::SSL_CTX) -> c_long;
    pub fn SSL_set_options(ssl: *mut ffi::SSL, op: u64) -> u64;
    pub fn X509_STORE_up_ref(store: *mut ffi::X509_STORE) -> c_int;
    pub fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut ffi::BIO;

    // libcrypto
    pub fn ERR_peek_error() -> c_ulong;
    pub fn BIO_free(bio: *mut ffi::BIO) -> c_int;
    pub fn OBJ_txt2nid(s: *const c_char) -> c_int;
    pub fn X509_get0_tbs_sigalg(x: *const ffi::X509) -> *const ffi::X509_ALGOR;
    pub fn d2i_X509_CRL_bio(
        bio: *mut ffi::BIO,
        crl: *mut *mut ffi::X509_CRL,
    ) -> *mut ffi::X509_CRL;
    pub fn d2i_X509_REQ_bio(
        bio: *mut ffi::BIO,
        req: *mut *mut ffi::X509_REQ,
    ) -> *mut ffi::X509_REQ;
    pub fn X509_STORE_add_crl(
        store: *mut ffi::X509_STORE,
        crl: *mut ffi::X509_CRL,
    ) -> c_int;
    pub fn ASN1_TIME_to_generalizedtime(
        t: *const ffi::ASN1_TIME,
        out: *mut *mut ffi::ASN1_GENERALIZEDTIME,
    ) -> *mut ffi::ASN1_GENERALIZEDTIME;
    pub fn BIO_test_flags(bio: *const ffi::BIO, flags: c_int) -> c_int;
    pub fn X509_check_private_key(
        x509: *const ffi::X509,
        pkey: *const ffi::EVP_PKEY,
    ) -> c_int;
    pub fn X509_print_ex(
        bio: *mut ffi::BIO,
        x509: *mut ffi::X509,
        nmflag: c_ulong,
        cflag: c_ulong,
    ) -> c_int;
    pub fn X509_REQ_print_ex(
        bio: *mut ffi::BIO,
        req: *mut ffi::X509_REQ,
        nmflag: c_ulong,
        cflag: c_ulong,
    ) -> c_int;
    pub fn RSA_print(bio: *mut ffi::BIO, rsa: *mut ffi::RSA, offset: c_int) -> c_int;
    pub fn X509_NAME_oneline(
        name: *const ffi::X509_NAME,
        buf: *mut c_char,
        size: c_int,
    ) -> *mut c_char;
    pub fn X509_NAME_delete_entry(
        name: *mut ffi::X509_NAME,
        loc: c_int,
    ) -> *mut ffi::X509_NAME_ENTRY;
    pub fn X509_NAME_hash_ex(
        name: *const ffi::X509_NAME,
        libctx: *mut c_void,
        propq: *const c_char,
        ok: *mut c_int,
    ) -> c_ulong;
    pub fn EC_get_builtin_curves(r: *mut EC_builtin_curve, nitems: size_t) -> size_t;
    pub fn X509_STORE_load_locations(
        store: *mut ffi::X509_STORE,
        file: *const c_char,
        dir: *const c_char,
    ) -> c_int;
    pub fn X509_STORE_CTX_get1_chain(
        ctx: *mut ffi::X509_STORE_CTX,
    ) -> *mut ffi::stack_st_X509;
    pub fn d2i_PrivateKey_bio(
        bio: *mut ffi::BIO,
        a: *mut *mut ffi::EVP_PKEY,
    ) -> *mut ffi::EVP_PKEY;
    pub fn d2i_PUBKEY_bio(
        bio: *mut ffi::BIO,
        a: *mut *mut ffi::EVP_PKEY,
    ) -> *mut ffi::EVP_PKEY;
    pub fn i2d_PrivateKey_bio(bio: *mut ffi::BIO, pkey: *const ffi::EVP_PKEY)
        -> c_int;
    pub fn i2d_PUBKEY_bio(bio: *mut ffi::BIO, pkey: *const ffi::EVP_PKEY) -> c_int;
    pub fn PEM_write_bio_PUBKEY(bio: *mut ffi::BIO, pkey: *const ffi::EVP_PKEY)
        -> c_int;
    pub fn PEM_read_bio_PUBKEY(
        bio: *mut ffi::BIO,
        out: *mut *mut ffi::EVP_PKEY,
        cb: PasswdCb,
        u: *mut c_void,
    ) -> *mut ffi::EVP_PKEY;
    pub fn PEM_write_bio_PrivateKey(
        bio: *mut ffi::BIO,
        pkey: *const ffi::EVP_PKEY,
        enc: *const ffi::EVP_CIPHER,
        kstr: *const c_uchar,
        klen: c_int,
        cb: PasswdCb,
        u: *mut c_void,
    ) -> c_int;
    pub fn PEM_read_bio_PrivateKey(
        bio: *mut ffi::BIO,
        out: *mut *mut ffi::EVP_PKEY,
        cb: PasswdCb,
        u: *mut c_void,
    ) -> *mut ffi::EVP_PKEY;
    pub fn ASN1_TIME_new() -> *mut ffi::ASN1_TIME;
    pub fn ASN1_TIME_set_string(s: *mut ffi::ASN1_TIME, str: *const c_char) -> c_int;
    pub fn X509_gmtime_adj(s: *mut ffi::ASN1_TIME, adj: c_long)
        -> *mut ffi::ASN1_TIME;
    pub fn X509_getm_notBefore(x: *const ffi::X509) -> *mut ffi::ASN1_TIME;
    pub fn X509_getm_notAfter(x: *const ffi::X509) -> *mut ffi::ASN1_TIME;
    pub fn ASN1_STRING_to_UTF8(
        out: *mut *mut c_uchar,
        in_: *const ffi::ASN1_STRING,
    ) -> c_int;
    pub fn X509_get_default_cert_file() -> *const c_char;
    pub fn X509_get_default_cert_dir() -> *const c_char;
    pub fn ERR_new();
    pub fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char);
    pub fn ERR_set_error(lib: c_int, reason: c_int, fmt: *const c_char, ...);
    pub fn EVP_get_digestbyname(name: *const c_char) -> *const ffi::EVP_MD;
    pub fn X509_sign(
        x509: *mut ffi::X509,
        pkey: *mut ffi::EVP_PKEY,
        md: *const ffi::EVP_MD,
    ) -> c_int;
    pub fn X509_REQ_sign(
        req: *mut ffi::X509_REQ,
        pkey: *mut ffi::EVP_PKEY,
        md: *const ffi::EVP_MD,
    ) -> c_int;
    pub fn X509_REQ_verify(req: *mut ffi::X509_REQ, pkey: *mut ffi::EVP_PKEY)
        -> c_int;
    pub fn X509_digest(
        x509: *const ffi::X509,
        md: *const ffi::EVP_MD,
        buf: *mut c_uchar,
        len: *mut libc::c_uint,
    ) -> c_int;
    pub fn X509_subject_name_hash(x509: *mut ffi::X509) -> c_ulong;
}

// C macros re-implemented in terms of (SSL_|BIO_|SSL_CTX_)ctrl, plus
// constants missing from openssl-sys.

pub const SSL_CTRL_GET_TOTAL_RENEGOTIATIONS: c_int = 12;
pub const DTLS_CTRL_GET_TIMEOUT: c_int = 73;
pub const DTLS_CTRL_HANDLE_TIMEOUT: c_int = 74;
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;
pub const BIO_FLAGS_READ: c_int = 0x01;
pub const BIO_FLAGS_WRITE: c_int = 0x02;
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

pub const SSL_SENT_SHUTDOWN: c_int = 1;
pub const SSL_RECEIVED_SHUTDOWN: c_int = 2;

pub const SSL_ST_CONNECT: c_int = 0x1000;
pub const SSL_ST_ACCEPT: c_int = 0x2000;
pub const SSL_ST_MASK: c_int = 0x0FFF;

pub const SSL_CB_LOOP: c_int = 0x01;
pub const SSL_CB_EXIT: c_int = 0x02;
pub const SSL_CB_READ: c_int = 0x04;
pub const SSL_CB_WRITE: c_int = 0x08;
pub const SSL_CB_ALERT: c_int = 0x4000;
pub const SSL_CB_READ_ALERT: c_int = SSL_CB_ALERT | SSL_CB_READ;
pub const SSL_CB_WRITE_ALERT: c_int = SSL_CB_ALERT | SSL_CB_WRITE;
pub const SSL_CB_ACCEPT_LOOP: c_int = SSL_ST_ACCEPT | SSL_CB_LOOP;
pub const SSL_CB_ACCEPT_EXIT: c_int = SSL_ST_ACCEPT | SSL_CB_EXIT;
pub const SSL_CB_CONNECT_LOOP: c_int = SSL_ST_CONNECT | SSL_CB_LOOP;
pub const SSL_CB_CONNECT_EXIT: c_int = SSL_ST_CONNECT | SSL_CB_EXIT;
pub const SSL_CB_HANDSHAKE_START: c_int = 0x10;
pub const SSL_CB_HANDSHAKE_DONE: c_int = 0x20;

pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x2;
pub const SSL_MODE_AUTO_RETRY: c_long = 0x4;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x10;

pub const SSL_OP_COOKIE_EXCHANGE: u64 = 0x2000;
pub const DTLS1_COOKIE_LENGTH: usize = 255;

pub const SSL_SESS_CACHE_OFF: c_long = 0x0;
pub const SSL_SESS_CACHE_CLIENT: c_long = 0x1;
pub const SSL_SESS_CACHE_SERVER: c_long = 0x2;
pub const SSL_SESS_CACHE_BOTH: c_long = 0x3;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_long = 0x80;
pub const SSL_SESS_CACHE_NO_INTERNAL_LOOKUP: c_long = 0x100;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_long = 0x200;
pub const SSL_SESS_CACHE_NO_INTERNAL: c_long =
    SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE;
pub const SSL_CTRL_GET_SESS_CACHE_MODE: c_int = 45;

pub const SSL_R_UNEXPECTED_EOF_WHILE_READING: c_int = 294;

pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_FILETYPE_ASN1: c_int = 2;

pub const OPENSSL_VERSION_T: c_int = 0;
pub const OPENSSL_CFLAGS_T: c_int = 1;
pub const OPENSSL_BUILT_ON_T: c_int = 2;
pub const OPENSSL_PLATFORM_T: c_int = 3;
pub const OPENSSL_DIR_T: c_int = 4;

pub unsafe fn SSL_total_renegotiations(ssl: *mut ffi::SSL) -> c_long {
    ffi::SSL_ctrl(
        ssl,
        SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,
        0,
        std::ptr::null_mut(),
    )
}

#[repr(C)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: c_long,
}

pub unsafe fn DTLSv1_get_timeout(ssl: *mut ffi::SSL, tv: *mut timeval) -> c_long {
    ffi::SSL_ctrl(ssl, DTLS_CTRL_GET_TIMEOUT, 0, tv as *mut c_void)
}

pub unsafe fn DTLSv1_handle_timeout(ssl: *mut ffi::SSL) -> c_long {
    ffi::SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut())
}

pub unsafe fn BIO_set_mem_eof_return(bio: *mut ffi::BIO, v: c_long) -> c_long {
    ffi::BIO_ctrl(bio, BIO_C_SET_BUF_MEM_EOF_RETURN, v, std::ptr::null_mut())
}

pub unsafe fn BIO_should_retry(bio: *mut ffi::BIO) -> bool {
    BIO_test_flags(bio, BIO_FLAGS_SHOULD_RETRY) != 0
}

pub unsafe fn BIO_should_read(bio: *mut ffi::BIO) -> bool {
    BIO_test_flags(bio, BIO_FLAGS_READ) != 0
}

pub unsafe fn BIO_should_write(bio: *mut ffi::BIO) -> bool {
    BIO_test_flags(bio, BIO_FLAGS_WRITE) != 0
}

pub unsafe fn BIO_should_io_special(bio: *mut ffi::BIO) -> bool {
    BIO_test_flags(bio, BIO_FLAGS_IO_SPECIAL) != 0
}

pub unsafe fn SSL_CTX_get_session_cache_mode(ctx: *mut ffi::SSL_CTX) -> c_long {
    ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_GET_SESS_CACHE_MODE, 0, std::ptr::null_mut())
}

pub const SSL_CTRL_CLEAR_MODE: c_int = 78;

pub unsafe fn SSL_CTX_clear_mode(ctx: *mut ffi::SSL_CTX, mode: c_long) -> c_long {
    ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_MODE, mode, std::ptr::null_mut())
}

pub unsafe fn X509_NAME_hash(name: *mut ffi::X509_NAME) -> c_ulong {
    let mut ok: c_int = 0;
    let h = X509_NAME_hash_ex(name, std::ptr::null_mut(), std::ptr::null(), &mut ok);
    if ok == 0 {
        0
    } else {
        h
    }
}

extern "C" {
    pub fn SSL_get_cipher_list(ssl: *const ffi::SSL, priority: c_int) -> *const c_char;
}

pub const SSL_CTRL_MODE: c_int = 33;

pub unsafe fn SSL_set_mode(ssl: *mut ffi::SSL, mode: c_long) -> c_long {
    ffi::SSL_ctrl(ssl, SSL_CTRL_MODE, mode, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_mode_long(ctx: *mut ffi::SSL_CTX, mode: c_long) -> c_long {
    ffi::SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, mode, std::ptr::null_mut())
}

/// Port of the OpenSSL 3.0 `ERR_put_error` macro.
pub unsafe fn ERR_put_error(
    lib: c_int,
    func: c_int,
    reason: c_int,
    file: *const c_char,
    line: c_int,
) {
    let _ = func;
    ERR_new();
    ERR_set_debug(file, line, std::ptr::null());
    ERR_set_error(lib, reason, std::ptr::null::<c_char>());
}
