from time import time

from OpenSSL.xcrypto import *

from tls.c import api as _api

FILETYPE_PEM = _api.SSL_FILETYPE_PEM
FILETYPE_ASN1 = _api.SSL_FILETYPE_ASN1

# TODO This was an API mistake.  OpenSSL has no such constant.
FILETYPE_TEXT = 2 ** 16 - 1

TYPE_RSA = _api.EVP_PKEY_RSA
TYPE_DSA = _api.EVP_PKEY_DSA


def _bio_to_string(bio):
    """
    Copy the contents of an OpenSSL BIO object into a Python byte string.
    """
    result_buffer = _api.new('char**')
    buffer_length = _api.BIO_get_mem_data(bio, result_buffer)
    return _api.buffer(result_buffer[0], buffer_length)[:]



def _raise_current_error():
    errors = []
    while True:
        error = _api.ERR_get_error()
        if error == 0:
            break
        errors.append((
                _api.string(_api.ERR_lib_error_string(error)),
                _api.string(_api.ERR_func_error_string(error)),
                _api.string(_api.ERR_reason_error_string(error))))

    raise Error(errors)

_exception_from_error_queue = _raise_current_error


class Error(Exception):
    pass



class PKey(object):
    _only_public = False

    def __init__(self):
        self._pkey = _api.EVP_PKEY_new()


    def generate_key(self, type, bits):
        """
        Generate a key of a given type, with a given number of a bits

        :param type: The key type (TYPE_RSA or TYPE_DSA)
        :param bits: The number of bits

        :return: None
        """
        if not isinstance(type, int):
            raise TypeError("type must be an integer")

        if not isinstance(bits, int):
            raise TypeError("bits must be an integer")

        exponent = _api.new("BIGNUM**")
        # TODO Check error return
        # TODO Free the exponent[0]
        _api.BN_hex2bn(exponent, "10001")

        if type == TYPE_RSA:
            if bits <= 0:
                raise ValueError("Invalid number of bits")

            rsa = _api.RSA_new();

            # TODO Release GIL?
            result = _api.RSA_generate_key_ex(rsa, bits, exponent[0], _api.NULL)
            if result == -1:
                1/0

            result = _api.EVP_PKEY_assign_RSA(self._pkey, rsa)
            if not result:
                1/0

        elif type == TYPE_DSA:
            pass
        else:
            raise Error("No such key type")



    def check(self):
        """
        Check the consistency of an RSA private key.

        :return: True if key is consistent.
        :raise Error: if the key is inconsistent.
        :raise TypeError: if the key is of a type which cannot be checked.
            Only RSA keys can currently be checked.
        """
        if _api.EVP_PKEY_type(self._pkey.type) != _api.EVP_PKEY_RSA:
            raise TypeError("key type unsupported")

        rsa = _api.EVP_PKEY_get1_RSA(self._pkey)
        result = _api.RSA_check_key(rsa)
        if result:
            return True
        _raise_current_error()



class X509(object):
    def __init__(self):
        # TODO Allocation failure?  And why not __new__ instead of __init__?
        self._x509 = _api.X509_new()


    def set_version(self, version):
        """
        Set version number of the certificate

        :param version: The version number
        :type version: :py:class:`int`

        :return: None
        """
        if not isinstance(version, int):
            raise TypeError("version must be an integer")

        _api.X509_set_version(self._x509, version)


    def get_version(self):
        """
        Return version number of the certificate

        :return: Version number as a Python integer
        """
        return _api.X509_get_version(self._x509)


    def get_pubkey(self):
        """
        Get the public key of the certificate

        :return: The public key
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _api.X509_get_pubkey(self._x509)
        if pkey._pkey == _api.NULL:
            _raise_current_error()
        pkey._only_public = True
        return pkey


    def set_pubkey(self, pkey):
        """
        Set the public key of the certificate

        :param pkey: The public key

        :return: None
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")

        set_result = _api.X509_set_pubkey(self._x509, pkey._pkey)
        if not set_result:
            _raise_current_error()


    def sign(self, pkey, digest):
        """
        Sign the certificate using the supplied key and digest

        :param pkey: The key to sign with
        :param digest: The message digest to use
        :return: None
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")

        if pkey._only_public:
            raise ValueError("Key only has public part")

        evp_md = _api.EVP_get_digestbyname(digest)
        if evp_md == _api.NULL:
            raise ValueError("No such digest method")

        sign_result = _api.X509_sign(self._x509, pkey._pkey, evp_md)
        if not sign_result:
            _raise_current_error()


    def subject_name_hash(self):
        """
        Return the hash of the X509 subject.

        :return: The hash of the subject.
        """
        return _api.X509_subject_name_hash(self._x509)


    def set_serial_number(self, serial):
        """
        Set serial number of the certificate

        :param serial: The serial number
        :type serial: :py:class:`int`

        :return: None
        """
        if not isinstance(serial, (int, long)):
            raise TypeError("serial must be an integer")

        hex_serial = hex(serial)[2:]
        if not isinstance(hex_serial, bytes):
            hex_serial = hex_serial.encode('ascii')

        bignum_serial = _api.new("BIGNUM**")

        # BN_hex2bn stores the result in &bignum.  Unless it doesn't feel like
        # it.  If bignum is still NULL after this call, then the return value is
        # actually the result.  I hope.  -exarkun
        small_serial = _api.BN_hex2bn(bignum_serial, hex_serial)

        if bignum_serial[0] == _api.NULL:
            set_result = ASN1_INTEGER_set(
                _api.X509_get_serialNumber(self._x509), small_serial)
            if set_result:
                # TODO Not tested
                _raise_current_error()
        else:
            asn1_serial = _api.BN_to_ASN1_INTEGER(bignum_serial[0], _api.NULL)
            _api.BN_free(bignum_serial[0])
            if asn1_serial == _api.NULL:
                # TODO Not tested
                _raise_current_error()
            set_result = _api.X509_set_serialNumber(self._x509, asn1_serial)
            if not set_result:
                # TODO Not tested
                _raise_current_error()


    def get_serial_number(self):
        """
        Return serial number of the certificate

        :return: Serial number as a Python integer
        """
        asn1_serial = _api.X509_get_serialNumber(self._x509)
        bignum_serial = _api.ASN1_INTEGER_to_BN(asn1_serial, _api.NULL)
        try:
            hex_serial = _api.BN_bn2hex(bignum_serial)
            try:
                hexstring_serial = _api.string(hex_serial)
                serial = int(hexstring_serial, 16)
                return serial
            finally:
                _api.OPENSSL_free(hex_serial)
        finally:
            _api.BN_free(bignum_serial)


    def gmtime_adj_notAfter(self, amount):
        """
        Adjust the time stamp for when the certificate stops being valid

        :param amount: The number of seconds by which to adjust the ending
                       validity time.
        :type amount: :py:class:`int`

        :return: None
        """
        if not isinstance(amount, int):
            raise TypeError("amount must be an integer")

        notAfter = _api.X509_get_notAfter(self._x509)
        _api.X509_gmtime_adj(notAfter, amount)


    def has_expired(self):
        """
        Check whether the certificate has expired.

        :return: True if the certificate has expired, false otherwise
        """
        now = int(time())
        notAfter = _api.X509_get_notAfter(self._x509)
        return _api.ASN1_UTCTIME_cmp_time_t(notAfter, now) < 0


    def get_notBefore(self):
        """
        Retrieve the time stamp for when the certificate starts being valid

        :return: A string giving the timestamp, in the format::

                         YYYYMMDDhhmmssZ\n\
                         YYYYMMDDhhmmss+hhmm\n\
                         YYYYMMDDhhmmss-hhmm\n\

                 or None if there is no value set.
        """


    def set_notBefore(self, when):
        """
        Set the time stamp for when the certificate starts being valid

        :param when: A string giving the timestamp, in the format:

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm
        :type when: :py:class:`bytes`

        :return: None
        """
        notBefore = _api.X509_get_notBefore(self._x509)
        _api.ASN1_GENERALIZEDTIME_set_string(notBefore, when)


    def set_notAfter(self, when):
        """
        Set the time stamp for when the certificate stops being valid

        :param when: A string giving the timestamp, in the format:

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm
        :type when: :py:class:`bytes`

        :return: None
        """
        notAfter = _api.X509_get_notAfter(self._x509)
        _api.ASN1_GENERALIZEDTIME_set_string(notAfter, when)
X509Type = X509



def load_certificate(type, buffer):
    """
    Load a certificate from a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)

    :param buffer: The buffer the certificate is stored in
    :type buffer: :py:class:`bytes`

    :return: The X509 object
    """
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))

    try:
        if type == FILETYPE_PEM:
            x509 = _api.PEM_read_bio_X509(bio, _api.NULL, _api.NULL, _api.NULL)
        elif type == FILETYPE_ASN1:
            x509 = _api.d2i_X509_bio(bio, _api.NULL);
        else:
            raise ValueError(
                "type argument must be FILETYPE_PEM or FILETYPE_ASN1")
    finally:
        _api.BIO_free(bio)

    if x509 == _api.NULL:
        _raise_current_error()

    cert = X509.__new__(X509)
    cert._x509 = x509
    return cert


def dump_certificate(type, cert):
    """
    Dump a certificate to a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param cert: The certificate to dump
    :return: The buffer with the dumped certificate in
    """
    bio = _api.BIO_new(_api.BIO_s_mem())
    if type == FILETYPE_PEM:
        result_code = _api.PEM_write_bio_X509(bio, cert._x509)
    elif type == FILETYPE_ASN1:
        result_code = _api.i2d_X509_bio(bio, cert._x509)
    elif type == FILETYPE_TEXT:
        result_code = _api.X509_print_ex(bio, cert._x509, 0, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or "
            "FILETYPE_TEXT")

    return _bio_to_string(bio)



def dump_privatekey(type, pkey, cipher=None, passphrase=None):
    """
    Dump a private key to a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param pkey: The PKey to dump
    :param cipher: (optional) if encrypted PEM format, the cipher to
                   use
    :param passphrase: (optional) if encrypted PEM format, this can be either
                       the passphrase to use, or a callback for providing the
                       passphrase.
    :return: The buffer with the dumped key in
    :rtype: :py:data:`str`
    """
    # TODO incomplete
    bio = _api.BIO_new(_api.BIO_s_mem())

    if type == FILETYPE_PEM:
        result_code = _api.PEM_write_bio_PrivateKey(
            bio, pkey._pkey, _api.NULL, _api.NULL, 0, _api.NULL, _api.NULL)
    elif type == FILETYPE_ASN1:
        result_code = _api.i2d_PrivateKey_bio(bio, pkey._pkey)
    elif type == FILETYPE_TEXT:
        rsa = _api.EVP_PKEY_get1_RSA(pkey._pkey)
        result_code = _api.RSA_print(bio, rsa, 0)
        # TODO RSA_free(rsa)?
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or "
            "FILETYPE_TEXT")

    if result_code == 0:
        _raise_current_error()

    return _bio_to_string(bio)



def load_privatekey(type, buffer, passphrase=None):
    """
    Load a private key from a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the key is stored in
    :param passphrase: (optional) if encrypted PEM format, this can be
                       either the passphrase to use, or a callback for
                       providing the passphrase.

    :return: The PKey object
    """
    # TODO incomplete
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))

    if type == FILETYPE_PEM:
        evp_pkey = _api.PEM_read_bio_PrivateKey(bio, _api.NULL, _api.NULL, _api.NULL)
    elif type == FILETYPE_ASN1:
        evp_pkey = _api.d2i_PrivateKey_bio(bio, _api.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    pkey = PKey.__new__(PKey)
    pkey._pkey = evp_pkey
    return pkey



def dump_certificate_request(type, req):
    """
    Dump a certificate request to a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param req: The certificate request to dump
    :return: The buffer with the dumped certificate request in
    """



def load_certificate_request(type, buffer):
    """
    Load a certificate request from a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the certificate request is stored in
    :return: The X509Req object
    """
