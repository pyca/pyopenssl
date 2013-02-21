from time import time

from OpenSSL.xcrypto import PKCS7Type, load_pkcs7_data

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



def _set_asn1_time(boundary, when):
    if not isinstance(when, bytes):
        raise TypeError("when must be a byte string")

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



def _get_asn1_time(timestamp):
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
            string_timestamp = _api.cast(
                "ASN1_STRING*", generalized_timestamp[0])
            string_data = _api.ASN1_STRING_data(string_timestamp)
            string_result = _api.string(string_data)
            _api.ASN1_GENERALIZEDTIME_free(generalized_timestamp[0])
            return string_result



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
            dsa = _api.DSA_generate_parameters(
                bits, _api.NULL, 0, _api.NULL, _api.NULL, _api.NULL, _api.NULL)
            if dsa == _api.NULL:
                1/0
            if not _api.DSA_generate_key(dsa):
                1/0
            if not _api.EVP_PKEY_assign_DSA(self._pkey, dsa):
                1/0
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
        if self._only_public:
            raise TypeError("public key only")

        if _api.EVP_PKEY_type(self._pkey.type) != _api.EVP_PKEY_RSA:
            raise TypeError("key type unsupported")

        rsa = _api.EVP_PKEY_get1_RSA(self._pkey)
        result = _api.RSA_check_key(rsa)
        if result:
            return True
        _raise_current_error()


    def type(self):
        """
        Returns the type of the key

        :return: The type of the key.
        """
        return self._pkey.type


    def bits(self):
        """
        Returns the number of bits of the key

        :return: The number of bits of the key.
        """
        return _api.EVP_PKEY_bits(self._pkey)
PKeyType = PKey



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


class X509Extension(object):
    def __init__(self, type_name, critical, value, subject=None, issuer=None):
        """
        :param typename: The name of the extension to create.
        :type typename: :py:data:`str`

        :param critical: A flag indicating whether this is a critical extension.

        :param value: The value of the extension.
        :type value: :py:data:`str`

        :param subject: Optional X509 cert to use as subject.
        :type subject: :py:class:`X509`

        :param issuer: Optional X509 cert to use as issuer.
        :type issuer: :py:class:`X509`

        :return: The X509Extension object
        """
        ctx = _api.new("X509V3_CTX*")

        # A context is necessary for any extension which uses the r2i conversion
        # method.  That is, X509V3_EXT_nconf may segfault if passed a NULL ctx.
        # Start off by initializing most of the fields to NULL.
        _api.X509V3_set_ctx(ctx, _api.NULL, _api.NULL, _api.NULL, _api.NULL, 0)

        # We have no configuration database - but perhaps we should (some
        # extensions may require it).
        _api.X509V3_set_ctx_nodb(ctx)

        # Initialize the subject and issuer, if appropriate.  ctx is a local,
        # and as far as I can tell none of the X509V3_* APIs invoked here steal
        # any references, so no need to mess with reference counts or duplicates.
        if issuer is not None:
            if not isinstance(issuer, X509):
                raise TypeError("issuer must be an X509 instance")
            ctx.issuer_cert = issuer._x509
        if subject is not None:
            if not isinstance(subject, X509):
                raise TypeError("subject must be an X509 instance")
            ctx.subject_cert = subject._x509

        if critical:
            # There are other OpenSSL APIs which would let us pass in critical
            # separately, but they're harder to use, and since value is already
            # a pile of crappy junk smuggling a ton of utterly important
            # structured data, what's the point of trying to avoid nasty stuff
            # with strings? (However, X509V3_EXT_i2d in particular seems like it
            # would be a better API to invoke.  I do not know where to get the
            # ext_struc it desires for its last parameter, though.)
            value = "critical," + value

        self._extension = _api.X509V3_EXT_nconf(
            _api.NULL, ctx, type_name, value)
        if self._extension == _api.NULL:
            _raise_current_error()


    def __str__(self):
        """
        :return: a nice text representation of the extension
        """
        bio = _api.BIO_new(_api.BIO_s_mem())
        if bio == _api.NULL:
            1/0

        print_result = _api.X509V3_EXT_print(bio, self._extension, 0, 0)
        if not print_result:
            1/0

        return _bio_to_string(bio)


    def get_critical(self):
        """
        Returns the critical field of the X509Extension

        :return: The critical field.
        """
        return _api.X509_EXTENSION_get_critical(self._extension)


    def get_short_name(self):
        """
        Returns the short version of the type name of the X509Extension

        :return: The short type name.
        """
        obj = _api.X509_EXTENSION_get_object(self._extension)
        nid = _api.OBJ_obj2nid(obj)
        return _api.string(_api.OBJ_nid2sn(nid))


    def get_data(self):
        """
        Returns the data of the X509Extension

        :return: A :py:data:`str` giving the X509Extension's ASN.1 encoded data.
        """
        octet_result = _api.X509_EXTENSION_get_data(self._extension)
        string_result = _api.cast('ASN1_STRING*', octet_result)
        char_result = _api.ASN1_STRING_data(string_result)
        result_length = _api.ASN1_STRING_length(string_result)
        return _api.buffer(char_result, result_length)[:]

X509ExtensionType = X509Extension


class X509Req(object):
    def __init__(self):
        self._req = _api.X509_REQ_new()


    def set_pubkey(self, pkey):
        """
        Set the public key of the certificate request

        :param pkey: The public key to use
        :return: None
        """
        set_result = _api.X509_REQ_set_pubkey(self._req, pkey._pkey)
        if not set_result:
            1/0


    def get_pubkey(self):
        """
        Get the public key from the certificate request

        :return: The public key
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _api.X509_REQ_get_pubkey(self._req)
        if pkey._pkey == _api.NULL:
            1/0
        pkey._only_public = True
        return pkey


    def set_version(self, version):
        """
        Set the version subfield (RFC 2459, section 4.1.2.1) of the certificate
        request.

        :param version: The version number
        :return: None
        """
        set_result = _api.X509_REQ_set_version(self._req, version)
        if not set_result:
            _raise_current_error()


    def get_version(self):
        """
        Get the version subfield (RFC 2459, section 4.1.2.1) of the certificate
        request.

        :return: an integer giving the value of the version subfield
        """
        return _api.X509_REQ_get_version(self._req)


    def get_subject(self):
        """
        Create an X509Name object for the subject of the certificate request

        :return: An X509Name object
        """
        name = X509Name.__new__(X509Name)
        name._name = _api.X509_REQ_get_subject_name(self._req)
        if name._name == _api.NULL:
            1/0
        return name


    def add_extensions(self, extensions):
        """
        Add extensions to the request.

        :param extensions: a sequence of X509Extension objects
        :return: None
        """
        stack = _api.sk_X509_EXTENSION_new_null()
        if stack == _api.NULL:
            1/0

        for ext in extensions:
            if not isinstance(ext, X509Extension):
                raise ValueError("One of the elements is not an X509Extension")

            _api.sk_X509_EXTENSION_push(stack, ext._extension)

        add_result = _api.X509_REQ_add_extensions(self._req, stack)
        if not add_result:
            1/0


    def sign(self, pkey, digest):
        """
        Sign the certificate request using the supplied key and digest

        :param pkey: The key to sign with
        :param digest: The message digest to use
        :return: None
        """
        if pkey._only_public:
            raise ValueError("Key has only public part")

        if not pkey._initialized:
            raise ValueError("Key is uninitialized")

        digest_obj = _api.EVP_get_digestbyname(digest)
        if digest_obj == _api.NULL:
            raise ValueError("No such digest method")

        sign_result = _api.X509_REQ_sign(self._req, pkey._pkey, digest_obj)
        if not sign_result:
            1/0


X509ReqType = X509Req



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


    def gmtime_adj_notBefore(self, amount):
        """
        Change the timestamp for when the certificate starts being valid to the current
        time plus an offset.

        :param amount: The number of seconds by which to adjust the starting validity
                       time.
        :return: None
        """
        if not isinstance(amount, int):
            raise TypeError("amount must be an integer")

        notBefore = _api.X509_get_notBefore(self._x509)
        _api.X509_gmtime_adj(notBefore, amount)


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
        return _get_asn1_time(which(self._x509))


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
        return _set_asn1_time(which(self._x509), when)


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
        if not isinstance(name, X509Name):
            raise TypeError("name must be an X509Name")
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


    def get_extension_count(self):
        """
        Get the number of extensions on the certificate.

        :return: The number of extensions as an integer.
        """
        return _api.X509_get_ext_count(self._x509)


    def add_extensions(self, extensions):
        """
        Add extensions to the certificate.

        :param extensions: a sequence of X509Extension objects
        :return: None
        """
        for ext in extensions:
            if not isinstance(ext, X509Extension):
                raise ValueError("One of the elements is not an X509Extension")

            add_result = _api.X509_add_ext(self._x509, ext._extension, -1)
            if not add_result:
                _raise_current_error()


    def get_extension(self, index):
        """
        Get a specific extension of the certificate by index.

        :param index: The index of the extension to retrieve.
        :return: The X509Extension object at the specified index.
        """
        ext = X509Extension.__new__(X509Extension)
        ext._extension = _api.X509_get_ext(self._x509, index)
        if ext._extension == _api.NULL:
            raise IndexError("extension index out of bounds")

        ext._extension = _api.X509_EXTENSION_dup(ext._extension)
        return ext

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
    if bio == _api.NULL:
        1/0

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
    if bio == _api.NULL:
        1/0

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
    bio = _api.BIO_new(_api.BIO_s_mem())
    if bio == _api.NULL:
        1/0

    if cipher is not None:
        cipher_obj = _api.EVP_get_cipherbyname(cipher)
        if cipher_obj == _api.NULL:
            raise ValueError("Invalid cipher name")
    else:
        cipher_obj = _api.NULL

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        result_code = _api.PEM_write_bio_PrivateKey(
            bio, pkey._pkey, cipher_obj, _api.NULL, 0,
            helper.callback, helper.callback_args)
        helper.raise_if_problem()
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



def _X509_REVOKED_dup(original):
    copy = _api.X509_REVOKED_new()
    if copy == _api.NULL:
        1/0

    if original.serialNumber != _api.NULL:
        copy.serialNumber = _api.ASN1_INTEGER_dup(original.serialNumber)

    if original.revocationDate != _api.NULL:
        copy.revocationDate = _api.M_ASN1_TIME_dup(original.revocationDate)

    if original.extensions != _api.NULL:
        extension_stack = _api.sk_X509_EXTENSION_new_null()
        for i in range(_api.sk_X509_EXTENSION_num(original.extensions)):
            original_ext = _api.sk_X509_EXTENSION_value(original.extensions, i)
            copy_ext = _api.X509_EXTENSION_dup(original_ext)
            _api.sk_X509_EXTENSION_push(extension_stack, copy_ext)
        copy.extensions = extension_stack

    copy.sequence = original.sequence
    return copy



class Revoked(object):
    # http://www.openssl.org/docs/apps/x509v3_config.html#CRL_distribution_points_
    # which differs from crl_reasons of crypto/x509v3/v3_enum.c that matches
    # OCSP_crl_reason_str.  We use the latter, just like the command line
    # program.
    _crl_reasons = [
        "unspecified",
        "keyCompromise",
        "CACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        # "removeFromCRL",
        ]

    def __init__(self):
        self._revoked = _api.X509_REVOKED_new()


    def set_serial(self, hex_str):
        """
        Set the serial number of a revoked Revoked structure

        :param hex_str: The new serial number.
        :type hex_str: :py:data:`str`
        :return: None
        """
        bignum_serial = _api.new("BIGNUM**")
        bn_result = _api.BN_hex2bn(bignum_serial, hex_str)
        if not bn_result:
            raise ValueError("bad hex string")

        asn1_serial = _api.BN_to_ASN1_INTEGER(bignum_serial[0], _api.NULL)
        _api.X509_REVOKED_set_serialNumber(self._revoked, asn1_serial)


    def get_serial(self):
        """
        Return the serial number of a Revoked structure

        :return: The serial number as a string
        """
        bio = _api.BIO_new(_api.BIO_s_mem())
        if bio == _api.NULL:
            1/0

        result = _api.i2a_ASN1_INTEGER(bio, self._revoked.serialNumber)
        if result < 0:
            1/0

        return _bio_to_string(bio)


    def _delete_reason(self):
        stack = self._revoked.extensions
        for i in range(_api.sk_X509_EXTENSION_num(stack)):
            ext = _api.sk_X509_EXTENSION_value(stack, i)
            if _api.OBJ_obj2nid(ext.object) == _api.NID_crl_reason:
                _api.sk_X509_EXTENSION_delete(stack, i)
                break


    def set_reason(self, reason):
        """
        Set the reason of a Revoked object.

        If :py:data:`reason` is :py:data:`None`, delete the reason instead.

        :param reason: The reason string.
        :type reason: :py:class:`str` or :py:class:`NoneType`
        :return: None
        """
        if reason is None:
            self._delete_reason()
        elif not isinstance(reason, bytes):
            raise TypeError("reason must be None or a byte string")
        else:
            reason = reason.lower().replace(' ', '')
            reason_code = [r.lower() for r in self._crl_reasons].index(reason)

            new_reason_ext = _api.ASN1_ENUMERATED_new()
            if new_reason_ext == _api.NULL:
                1/0

            set_result = _api.ASN1_ENUMERATED_set(new_reason_ext, reason_code)
            if set_result == _api.NULL:
                1/0

            self._delete_reason()
            add_result = _api.X509_REVOKED_add1_ext_i2d(
                self._revoked, _api.NID_crl_reason, new_reason_ext, 0, 0)

            if not add_result:
                1/0


    def get_reason(self):
        """
        Return the reason of a Revoked object.

        :return: The reason as a string
        """
        extensions = self._revoked.extensions
        for i in range(_api.sk_X509_EXTENSION_num(extensions)):
            ext = _api.sk_X509_EXTENSION_value(extensions, i)
            if _api.OBJ_obj2nid(ext.object) == _api.NID_crl_reason:
                bio = _api.BIO_new(_api.BIO_s_mem())
                if bio == _api.NULL:
                    1/0

                print_result = _api.X509V3_EXT_print(bio, ext, 0, 0)
                if not print_result:
                    print_result = _api.M_ASN1_OCTET_STRING_print(bio, ext.value)
                    if print_result == 0:
                        1/0

                return _bio_to_string(bio)


    def all_reasons(self):
        """
        Return a list of all the supported reason strings.

        :return: A list of reason strings.
        """
        return self._crl_reasons[:]


    def set_rev_date(self, when):
        """
        Set the revocation timestamp

        :param when: A string giving the timestamp, in the format:

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm

        :return: None
        """
        return _set_asn1_time(self._revoked.revocationDate, when)


    def get_rev_date(self):
        """
        Retrieve the revocation date

        :return: A string giving the timestamp, in the format:

                         YYYYMMDDhhmmssZ
                         YYYYMMDDhhmmss+hhmm
                         YYYYMMDDhhmmss-hhmm
        """
        return _get_asn1_time(self._revoked.revocationDate)



class CRL(object):
    def __init__(self):
        """
        Create a new empty CRL object.
        """
        self._crl = _api.X509_CRL_new()


    def get_revoked(self):
        """
        Return revoked portion of the CRL structure (by value not reference).

        :return: A tuple of Revoked objects.
        """
        results = []
        revoked_stack = self._crl.crl.revoked
        for i in range(_api.sk_X509_REVOKED_num(revoked_stack)):
            revoked = _api.sk_X509_REVOKED_value(revoked_stack, i)
            revoked_copy = _X509_REVOKED_dup(revoked)
            pyrev = Revoked.__new__(Revoked)
            pyrev._revoked = revoked_copy
            results.append(pyrev)
        if results:
            return tuple(results)


    def add_revoked(self, revoked):
        """
        Add a revoked (by value not reference) to the CRL structure

        :param revoked: The new revoked.
        :type revoked: :class:`X509`

        :return: None
        """
        copy = _X509_REVOKED_dup(revoked._revoked)
        if copy == _api.NULL:
            1/0

        add_result = _api.X509_CRL_add0_revoked(self._crl, copy)
        # TODO what check on add_result?


    def export(self, cert, key, type=FILETYPE_PEM, days=100):
        """
        export a CRL as a string

        :param cert: Used to sign CRL.
        :type cert: :class:`X509`

        :param key: Used to sign CRL.
        :type key: :class:`PKey`

        :param type: The export format, either :py:data:`FILETYPE_PEM`, :py:data:`FILETYPE_ASN1`, or :py:data:`FILETYPE_TEXT`.

        :param days: The number of days until the next update of this CRL.
        :type days: :py:data:`int`

        :return: :py:data:`str`
        """
        if not isinstance(cert, X509):
            raise TypeError("cert must be an X509 instance")
        if not isinstance(key, PKey):
            raise TypeError("key must be a PKey instance")
        if not isinstance(type, int):
            raise TypeError("type must be an integer")

        bio = _api.BIO_new(_api.BIO_s_mem())
        if bio == _api.NULL:
            1/0

        # A scratch time object to give different values to different CRL fields
        sometime = _api.ASN1_TIME_new()
        if sometime == _api.NULL:
            1/0

        _api.X509_gmtime_adj(sometime, 0)
        _api.X509_CRL_set_lastUpdate(self._crl, sometime)

        _api.X509_gmtime_adj(sometime, days * 24 * 60 * 60)
        _api.X509_CRL_set_nextUpdate(self._crl, sometime)

        _api.X509_CRL_set_issuer_name(self._crl, _api.X509_get_subject_name(cert._x509))

        sign_result = _api.X509_CRL_sign(self._crl, key._pkey, _api.EVP_md5())
        if not sign_result:
            _raise_current_error()

        if type == FILETYPE_PEM:
            ret = _api.PEM_write_bio_X509_CRL(bio, self._crl)
        elif type == FILETYPE_ASN1:
            ret = _api.i2d_X509_CRL_bio(bio, self._crl)
        elif type == FILETYPE_TEXT:
            ret = _api.X509_CRL_print(bio, self._crl)
        else:
            raise ValueError(
                "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_TEXT")

        if not ret:
            1/0

        return _bio_to_string(bio)
CRLType = CRL



class PKCS12(object):
    def __init__(self):
        self._pkey = None
        self._cert = None
        self._cacerts = None
        self._friendlyname = None


    def get_certificate(self):
        """
        Return certificate portion of the PKCS12 structure

        :return: X509 object containing the certificate
        """
        return self._cert


    def set_certificate(self, cert):
        """
        Replace the certificate portion of the PKCS12 structure

        :param cert: The new certificate.
        :type cert: :py:class:`X509` or :py:data:`None`
        :return: None
        """
        if not isinstance(cert, X509):
            raise TypeError("cert must be an X509 instance")
        self._cert = cert


    def get_privatekey(self):
        """
        Return private key portion of the PKCS12 structure

        :returns: PKey object containing the private key
        """
        return self._pkey


    def set_privatekey(self, pkey):
        """
        Replace or set the certificate portion of the PKCS12 structure

        :param pkey: The new private key.
        :type pkey: :py:class:`PKey`
        :return: None
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")
        self._pkey = pkey


    def get_ca_certificates(self):
        """
        Return CA certificates within of the PKCS12 object

        :return: A newly created tuple containing the CA certificates in the chain,
                 if any are present, or None if no CA certificates are present.
        """
        if self._cacerts is not None:
            return tuple(self._cacerts)


    def set_ca_certificates(self, cacerts):
        """
        Replace or set the CA certificates withing the PKCS12 object.

        :param cacerts: The new CA certificates.
        :type cacerts: :py:data:`None` or an iterable of :py:class:`X509`
        :return: None
        """
        if cacerts is None:
            self._cacerts = None
        else:
            cacerts = list(cacerts)
            for cert in cacerts:
                if not isinstance(cert, X509):
                    raise TypeError("iterable must only contain X509 instances")
            self._cacerts = cacerts


    def set_friendlyname(self, name):
        """
        Replace or set the certificate portion of the PKCS12 structure

        :param name: The new friendly name.
        :type name: :py:class:`bytes`
        :return: None
        """
        if name is None:
            self._friendlyname = None
        elif not isinstance(name, bytes):
            raise TypeError("name must be a byte string or None (not %r)" % (name,))
        self._friendlyname = name


    def get_friendlyname(self):
        """
        Return friendly name portion of the PKCS12 structure

        :returns: String containing the friendlyname
        """
        return self._friendlyname


    def export(self, passphrase=None, iter=2048, maciter=1):
        """
        Dump a PKCS12 object as a string.  See also "man PKCS12_create".

        :param passphrase: used to encrypt the PKCS12
        :type passphrase: :py:data:`bytes`

        :param iter: How many times to repeat the encryption
        :type iter: :py:data:`int`

        :param maciter: How many times to repeat the MAC
        :type maciter: :py:data:`int`

        :return: The string containing the PKCS12
        """
        if self._cacerts is None:
            cacerts = _api.NULL
        else:
            cacerts = _api.sk_X509_new_null()
            for cert in self._cacerts:
                _api.sk_X509_push(cacerts, cert._x509)

        if passphrase is None:
            passphrase = _api.NULL

        friendlyname = self._friendlyname
        if friendlyname is None:
            friendlyname = _api.NULL

        if self._pkey is None:
            pkey = _api.NULL
        else:
            pkey = self._pkey._pkey

        if self._cert is None:
            cert = _api.NULL
        else:
            cert = self._cert._x509

        pkcs12 = _api.PKCS12_create(
            passphrase, friendlyname, pkey, cert, cacerts,
            _api.NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            _api.NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            iter, maciter, 0)
        if pkcs12 == _api.NULL:
            _raise_current_error()

        bio = _api.BIO_new(_api.BIO_s_mem())
        if bio == _api.NULL:
            1/0

        _api.i2d_PKCS12_bio(bio, pkcs12)
        return _bio_to_string(bio)
PKCS12Type = PKCS12



class NetscapeSPKI(object):
    def __init__(self):
        self._spki = _api.NETSCAPE_SPKI_new()


    def sign(self, pkey, digest):
        """
        Sign the certificate request using the supplied key and digest

        :param pkey: The key to sign with
        :param digest: The message digest to use
        :return: None
        """
        if pkey._only_public:
            raise ValueError("Key has only public part")

        if not pkey._initialized:
            raise ValueError("Key is uninitialized")

        digest_obj = _api.EVP_get_digestbyname(digest)
        if digest_obj == _api.NULL:
            raise ValueError("No such digest method")

        sign_result = _api.NETSCAPE_SPKI_sign(self._spki, pkey._pkey, digest_obj)
        if not sign_result:
            1/0


    def verify(self, key):
        """
        Verifies a certificate request using the supplied public key

        :param key: a public key
        :return: True if the signature is correct.
        :raise OpenSSL.crypto.Error: If the signature is invalid or there is a
            problem verifying the signature.
        """
        answer = _api.NETSCAPE_SPKI_verify(self._spki, key._pkey)
        if answer <= 0:
            _raise_current_error()
        return True


    def b64_encode(self):
        """
        Generate a base64 encoded string from an SPKI

        :return: The base64 encoded string
        """
        return _api.string(_api.NETSCAPE_SPKI_b64_encode(self._spki))


    def get_pubkey(self):
        """
        Get the public key of the certificate

        :return: The public key
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _api.NETSCAPE_SPKI_get_pubkey(self._spki)
        if pkey._pkey == _api.NULL:
            1/0
        pkey._only_public = True
        return pkey


    def set_pubkey(self, pkey):
        """
        Set the public key of the certificate

        :param pkey: The public key
        :return: None
        """
        set_result = _api.NETSCAPE_SPKI_set_pubkey(self._spki, pkey._pkey)
        if not set_result:
            1/0
NetscapeSPKIType = NetscapeSPKI


class _PassphraseHelper(object):
    def __init__(self, type, passphrase):
        if type != FILETYPE_PEM and passphrase is not None:
            raise ValueError("only FILETYPE_PEM key format supports encryption")
        self._passphrase = passphrase
        self._problems = []


    @property
    def callback(self):
        if self._passphrase is None:
            return _api.NULL
        elif isinstance(self._passphrase, bytes):
            return _api.NULL
        elif callable(self._passphrase):
            return _api.callback("pem_password_cb", self._read_passphrase)
        else:
            raise TypeError("Last argument must be string or callable")


    @property
    def callback_args(self):
        if self._passphrase is None:
            return _api.NULL
        elif isinstance(self._passphrase, bytes):
            return self._passphrase
        elif callable(self._passphrase):
            return _api.NULL
        else:
            raise TypeError("Last argument must be string or callable")


    def raise_if_problem(self):
        if self._problems:
            try:
                _raise_current_error()
            except Error:
                pass
            raise self._problems[0]


    def _read_passphrase(self, buf, size, rwflag, userdata):
        try:
            result = self._passphrase(rwflag)
            if not isinstance(result, bytes):
                raise ValueError("String expected")
            if len(result) > size:
                raise ValueError("passphrase returned by callback is too long")
            for i in range(len(result)):
                buf[i] = result[i]
            return len(result)
        except Exception as e:
            self._problems.append(e)
            return 0



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
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))
    if bio == _api.NULL:
        1/0

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        evp_pkey = _api.PEM_read_bio_PrivateKey(
            bio, _api.NULL, helper.callback, helper.callback_args)
        helper.raise_if_problem()
    elif type == FILETYPE_ASN1:
        evp_pkey = _api.d2i_PrivateKey_bio(bio, _api.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if evp_pkey == _api.NULL:
        _raise_current_error()

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
    bio = _api.BIO_new(_api.BIO_s_mem())
    if bio == _api.NULL:
        1/0

    if type == FILETYPE_PEM:
        result_code = _api.PEM_write_bio_X509_REQ(bio, req._req)
    elif type == FILETYPE_ASN1:
        result_code = _api.i2d_X509_REQ_bio(bio, req._req)
    elif type == FILETYPE_TEXT:
        result_code = _api.X509_REQ_print_ex(bio, req._req, 0, 0)
    else:
        raise ValueError("type argument must be FILETYPE_PEM, FILETYPE_ASN1, or FILETYPE_TEXT")

    if result_code == 0:
        1/0

    return _bio_to_string(bio)



def load_certificate_request(type, buffer):
    """
    Load a certificate request from a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the certificate request is stored in
    :return: The X509Req object
    """
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))
    if bio == _api.NULL:
        1/0

    if type == FILETYPE_PEM:
        req = _api.PEM_read_bio_X509_REQ(bio, _api.NULL, _api.NULL, _api.NULL)
    elif type == FILETYPE_ASN1:
        req = _api.d2i_X509_REQ_bio(bio, _api.NULL)
    else:
        1/0

    if req == _api.NULL:
        1/0

    x509req = X509Req.__new__(X509Req)
    x509req._req = req
    return x509req



def sign(pkey, data, digest):
    """
    Sign data with a digest

    :param pkey: Pkey to sign with
    :param data: data to be signed
    :param digest: message digest to use
    :return: signature
    """
    digest_obj = _api.EVP_get_digestbyname(digest)
    if digest_obj == _api.NULL:
        raise ValueError("No such digest method")

    md_ctx = _api.new("EVP_MD_CTX*")

    _api.EVP_SignInit(md_ctx, digest_obj)
    _api.EVP_SignUpdate(md_ctx, data, len(data))

    signature_buffer = _api.new("unsigned char[]", 512)
    signature_length = _api.new("unsigned int*")
    signature_length[0] = len(signature_buffer)
    final_result = _api.EVP_SignFinal(
        md_ctx, signature_buffer, signature_length, pkey._pkey)

    if final_result != 1:
        1/0

    return _api.buffer(signature_buffer, signature_length[0])[:]



def verify(cert, signature, data, digest):
    """
    Verify a signature

    :param cert: signing certificate (X509 object)
    :param signature: signature returned by sign function
    :param data: data to be verified
    :param digest: message digest to use
    :return: None if the signature is correct, raise exception otherwise
    """
    digest_obj = _api.EVP_get_digestbyname(digest)
    if digest_obj == _api.NULL:
        raise ValueError("No such digest method")

    pkey = _api.X509_get_pubkey(cert._x509)
    if pkey == _api.NULL:
        1/0

    md_ctx = _api.new("EVP_MD_CTX*")

    _api.EVP_VerifyInit(md_ctx, digest_obj)
    _api.EVP_VerifyUpdate(md_ctx, data, len(data))
    verify_result = _api.EVP_VerifyFinal(md_ctx, signature, len(signature), pkey)

    if verify_result != 1:
        _raise_current_error()



def load_crl(type, buffer):
    """
    Load a certificate revocation list from a buffer

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the CRL is stored in

    :return: The PKey object
    """
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))
    if bio == _api.NULL:
        1/0

    if type == FILETYPE_PEM:
        crl = _api.PEM_read_bio_X509_CRL(bio, _api.NULL, _api.NULL, _api.NULL)
    elif type == FILETYPE_ASN1:
        crl = _api.d2i_X509_CRL_bio(bio, _api.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if crl == _api.NULL:
        _raise_current_error()

    result = CRL.__new__(CRL)
    result._crl = crl
    return result



def load_pkcs12(buffer, passphrase):
    """
    Load a PKCS12 object from a buffer

    :param buffer: The buffer the certificate is stored in
    :param passphrase: (Optional) The password to decrypt the PKCS12 lump
    :returns: The PKCS12 object
    """
    bio = _api.BIO_new_mem_buf(buffer, len(buffer))
    if bio == _api.NULL:
        1/0

    p12 = _api.d2i_PKCS12_bio(bio, _api.NULL)
    if p12 == _api.NULL:
        _raise_current_error()

    pkey = _api.new("EVP_PKEY**")
    cert = _api.new("X509**")
    cacerts = _api.new("struct stack_st_X509**")

    parse_result = _api.PKCS12_parse(p12, passphrase, pkey, cert, cacerts)
    if not parse_result:
        _raise_current_error()

    # openssl 1.0.0 sometimes leaves an X509_check_private_key error in the
    # queue for no particular reason.  This error isn't interesting to anyone
    # outside this function.  It's not even interesting to us.  Get rid of it.
    try:
        _raise_current_error()
    except Error:
        pass

    if pkey[0] == _api.NULL:
        pykey = None
    else:
        pykey = PKey.__new__(PKey)
        pykey._pkey = pkey[0]

    if cert[0] == _api.NULL:
        pycert = None
        friendlyname = None
    else:
        pycert = X509.__new__(X509)
        pycert._x509 = cert[0]

        friendlyname_length = _api.new("int*")
        friendlyname_buffer = _api.X509_alias_get0(cert[0], friendlyname_length)
        friendlyname = _api.buffer(friendlyname_buffer, friendlyname_length[0])[:]
        if friendlyname_buffer == _api.NULL:
            friendlyname = None

    pycacerts = []
    for i in range(_api.sk_X509_num(cacerts[0])):
        pycacert = X509.__new__(X509)
        pycacert._x509 = _api.sk_X509_value(cacerts[0], i)
        pycacerts.append(pycacert)
    if not pycacerts:
        pycacerts = None

    pkcs12 = PKCS12.__new__(PKCS12)
    pkcs12._pkey = pykey
    pkcs12._cert = pycert
    pkcs12._cacerts = pycacerts
    pkcs12._friendlyname = friendlyname
    return pkcs12
