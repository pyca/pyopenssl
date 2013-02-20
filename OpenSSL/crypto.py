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
    _initialized = True

    def __init__(self):
        self._pkey = _api.EVP_PKEY_new()
        self._initialized = False


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

        self._initialized = True


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



class X509Name(object):
    def __init__(self, name):
        """
        Create a new X509Name, copying the given X509Name instance.

        :param name: An X509Name object to copy
        """
        self._name = _api.X509_NAME_dup(name._name)


    def __setattr__(self, name, value):
        if name.startswith('_'):
            return super(X509Name, self).__setattr__(name, value)

        if type(name) is not str:
            raise TypeError("attribute name must be string, not '%.200s'" % (
                    type(value).__name__,))

        nid = _api.OBJ_txt2nid(name)
        if nid == _api.NID_undef:
            try:
                _raise_current_error()
            except Error:
                pass
            raise AttributeError("No such attribute")

        # If there's an old entry for this NID, remove it
        for i in range(_api.X509_NAME_entry_count(self._name)):
            ent = _api.X509_NAME_get_entry(self._name, i)
            ent_obj = _api.X509_NAME_ENTRY_get_object(ent)
            ent_nid = _api.OBJ_obj2nid(ent_obj)
            if nid == ent_nid:
                ent = _api.X509_NAME_delete_entry(self._name, i)
                _api.X509_NAME_ENTRY_free(ent)
                break

        if isinstance(value, unicode):
            value = value.encode('utf-8')

        add_result = _api.X509_NAME_add_entry_by_NID(
            self._name, nid, _api.MBSTRING_UTF8, value, -1, -1, 0)
        if not add_result:
            # TODO Untested
            1/0


    def __getattr__(self, name):
        """
        Find attribute. An X509Name object has the following attributes:
        countryName (alias C), stateOrProvince (alias ST), locality (alias L),
        organization (alias O), organizationalUnit (alias OU), commonName (alias
        CN) and more...
        """
        nid = _api.OBJ_txt2nid(name)
        if nid == _api.NID_undef:
            # This is a bit weird.  OBJ_txt2nid indicated failure, but it seems
            # a lower level function, a2d_ASN1_OBJECT, also feels the need to
            # push something onto the error queue.  If we don't clean that up
            # now, someone else will bump into it later and be quite confused.
            # See lp#314814.
            try:
                _raise_current_error()
            except Error:
                pass
            return super(X509Name, self).__getattr__(name)

        entry_index = _api.X509_NAME_get_index_by_NID(self._name, nid, -1)
        if entry_index == -1:
            return None

        entry = _api.X509_NAME_get_entry(self._name, entry_index)
        data = _api.X509_NAME_ENTRY_get_data(entry)

        result_buffer = _api.new("unsigned char**")
        data_length = _api.ASN1_STRING_to_UTF8(result_buffer, data)
        if data_length < 0:
            1/0

        result = _api.buffer(result_buffer[0], data_length)[:].decode('utf-8')
        _api.OPENSSL_free(result_buffer[0])
        return result


    def __cmp__(self, other):
        if not isinstance(other, X509Name):
            return NotImplemented

        result = _api.X509_NAME_cmp(self._name, other._name)
        # TODO result == -2 is an error case that maybe should be checked for
        return result


    def __repr__(self):
        """
        String representation of an X509Name
        """
        result_buffer = _api.new("char[]", 512);
        format_result = _api.X509_NAME_oneline(
            self._name, result_buffer, len(result_buffer))

        if format_result == _api.NULL:
            1/0

        return "<X509Name object '%s'>" % (_api.string(result_buffer),)


    def hash(self):
        """
        Return the hash value of this name

        :return: None
        """
        return _api.X509_NAME_hash(self._name)


    def der(self):
        """
        Return the DER encoding of this name

        :return: A :py:class:`bytes` instance giving the DER encoded form of
            this name.
        """
        result_buffer = _api.new('unsigned char**')
        encode_result = _api.i2d_X509_NAME(self._name, result_buffer)
        if encode_result < 0:
            1/0

        string_result = _api.buffer(result_buffer[0], encode_result)[:]
        _api.OPENSSL_free(result_buffer[0])
        return string_result


    def get_components(self):
        """
        Returns the split-up components of this name.

        :return: List of tuples (name, value).
        """
        result = []
        for i in range(_api.X509_NAME_entry_count(self._name)):
            ent = _api.X509_NAME_get_entry(self._name, i)

            fname = _api.X509_NAME_ENTRY_get_object(ent)
            fval = _api.X509_NAME_ENTRY_get_data(ent)

            nid = _api.OBJ_obj2nid(fname)
            name = _api.OBJ_nid2sn(nid)

            result.append((
                    _api.string(name),
                    _api.string(
                        _api.ASN1_STRING_data(fval),
                        _api.ASN1_STRING_length(fval))))

        return result
X509NameType = X509Name



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

        if not pkey._initialized:
            raise ValueError("Key is uninitialized")

        evp_md = _api.EVP_get_digestbyname(digest)
        if evp_md == _api.NULL:
            raise ValueError("No such digest method")

        sign_result = _api.X509_sign(self._x509, pkey._pkey, evp_md)
        if not sign_result:
            _raise_current_error()


    def get_signature_algorithm(self):
        """
        Retrieve the signature algorithm used in the certificate

        :return: A byte string giving the name of the signature algorithm used in
                 the certificate.
        :raise ValueError: If the signature algorithm is undefined.
        """
        alg = self._x509.cert_info.signature.algorithm
        nid = _api.OBJ_obj2nid(alg)
        if nid == _api.NID_undef:
            raise ValueError("Undefined signature algorithm")
        return _api.string(_api.OBJ_nid2ln(nid))


    def digest(self, digest_name):
        """
        Return the digest of the X509 object.

        :param digest_name: The name of the digest algorithm to use.
        :type digest_name: :py:class:`bytes`

        :return: The digest of the object
        """
        digest = _api.EVP_get_digestbyname(digest_name)
        if digest == _api.NULL:
            raise ValueError("No such digest method")

        result_buffer = _api.new("char[]", _api.EVP_MAX_MD_SIZE)
        result_length = _api.new("unsigned int[]", 1)
        result_length[0] = len(result_buffer)

        digest_result = _api.X509_digest(
            self._x509, digest, result_buffer, result_length)

        if not digest_result:
            1/0

        return ':'.join([
                ch.encode('hex').upper() for ch
                in _api.buffer(result_buffer, result_length[0])])


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
        return _api.ASN1_UTCTIME_cmp_time_t(
            _api.cast('ASN1_UTCTIME*', notAfter), now) < 0


    def _get_boundary_time(self, which):
        timestamp = which(self._x509)
        string_timestamp = _api.cast('ASN1_STRING*', timestamp)
        if _api.ASN1_STRING_length(string_timestamp) == 0:
            return None
        elif _api.ASN1_STRING_type(string_timestamp) == _api.V_ASN1_GENERALIZEDTIME:
            return _api.string(_api.ASN1_STRING_data(string_timestamp))
        else:
            generalized_timestamp = _api.new("ASN1_GENERALIZEDTIME**")
            _api.ASN1_TIME_to_generalizedtime(timestamp, generalized_timestamp)
            if generalized_timestamp[0] == _api.NULL:
                1/0
            else:
                string_timestamp = _api.string(
                    _api.cast("char*", generalized_timestamp[0].data))
                _api.ASN1_GENERALIZEDTIME_free(generalized_timestamp[0])
                return string_timestamp


    def get_notBefore(self):
        """
        Retrieve the time stamp for when the certificate starts being valid

        :return: A string giving the timestamp, in the format::

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm

                 or None if there is no value set.
        """
        return self._get_boundary_time(_api.X509_get_notBefore)


    def _set_boundary_time(self, which, when):
        if not isinstance(when, bytes):
            raise TypeError("when must be a byte string")

        boundary = which(self._x509)
        set_result = _api.ASN1_GENERALIZEDTIME_set_string(
            _api.cast('ASN1_GENERALIZEDTIME*', boundary), when)
        if set_result == 0:
            dummy = _api.ASN1_STRING_new()
            _api.ASN1_STRING_set(dummy, when, len(when))
            check_result = _api.ASN1_GENERALIZEDTIME_check(
                _api.cast('ASN1_GENERALIZEDTIME*', dummy))
            if not check_result:
                raise ValueError("Invalid string")
            else:
                # TODO No tests for this case
                raise RuntimeError("Unknown ASN1_GENERALIZEDTIME_set_string failure")


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
        return self._set_boundary_time(_api.X509_get_notBefore, when)


    def get_notAfter(self):
        """
        Retrieve the time stamp for when the certificate stops being valid

        :return: A string giving the timestamp, in the format::

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm

                 or None if there is no value set.
        """
        return self._get_boundary_time(_api.X509_get_notAfter)


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
        return self._set_boundary_time(_api.X509_get_notAfter, when)


    def _get_name(self, which):
        name = X509Name.__new__(X509Name)
        name._name = which(self._x509)
        if name._name == _api.NULL:
            1/0
        return name


    def _set_name(self, which, name):
        set_result = which(self._x509, name._name)
        if not set_result:
            1/0


    def get_issuer(self):
        """
        Create an X509Name object for the issuer of the certificate

        :return: An X509Name object
        """
        return self._get_name(_api.X509_get_issuer_name)


    def set_issuer(self, issuer):
        """
        Set the issuer of the certificate

        :param issuer: The issuer name
        :type issuer: :py:class:`X509Name`

        :return: None
        """
        return self._set_name(_api.X509_set_issuer_name, issuer)


    def get_subject(self):
        """
        Create an X509Name object for the subject of the certificate

        :return: An X509Name object
        """
        return self._get_name(_api.X509_get_subject_name)


    def set_subject(self, subject):
        """
        Set the subject of the certificate

        :param subject: The subject name
        :type subject: :py:class:`X509Name`
        :return: None
        """
        return self._set_name(_api.X509_set_subject_name, subject)
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
