
from functools import wraps
from itertools import count

from OpenSSL.xSSL import *

from tls.c import api as _api

from OpenSSL.crypto import (
    FILETYPE_PEM, _PassphraseHelper, PKey, X509, _raise_current_error,
    _new_mem_buf)

_unspecified = object()

OPENSSL_VERSION_NUMBER = _api.OPENSSL_VERSION_NUMBER
SSLEAY_VERSION = _api.SSLEAY_VERSION
SSLEAY_CFLAGS = _api.SSLEAY_CFLAGS
SSLEAY_PLATFORM = _api.SSLEAY_PLATFORM
SSLEAY_DIR = _api.SSLEAY_DIR
SSLEAY_BUILT_ON = _api.SSLEAY_BUILT_ON

SENT_SHUTDOWN = _api.SSL_SENT_SHUTDOWN
RECEIVED_SHUTDOWN = _api.SSL_RECEIVED_SHUTDOWN

SSLv2_METHOD = 1
SSLv3_METHOD = 2
SSLv23_METHOD = 3
TLSv1_METHOD = 4

OP_NO_SSLv2 = _api.SSL_OP_NO_SSLv2
OP_NO_SSLv3 = _api.SSL_OP_NO_SSLv3

OP_SINGLE_DH_USE = _api.SSL_OP_SINGLE_DH_USE

VERIFY_PEER = _api.SSL_VERIFY_PEER
VERIFY_FAIL_IF_NO_PEER_CERT = _api.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
VERIFY_CLIENT_ONCE = _api.SSL_VERIFY_CLIENT_ONCE
VERIFY_NONE = _api.SSL_VERIFY_NONE

SESS_CACHE_OFF = _api.SSL_SESS_CACHE_OFF
SESS_CACHE_CLIENT = _api.SSL_SESS_CACHE_CLIENT
SESS_CACHE_SERVER = _api.SSL_SESS_CACHE_SERVER
SESS_CACHE_BOTH = _api.SSL_SESS_CACHE_BOTH
SESS_CACHE_NO_AUTO_CLEAR = _api.SSL_SESS_CACHE_NO_AUTO_CLEAR
SESS_CACHE_NO_INTERNAL_LOOKUP = _api.SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
SESS_CACHE_NO_INTERNAL_STORE = _api.SSL_SESS_CACHE_NO_INTERNAL_STORE
SESS_CACHE_NO_INTERNAL = _api.SSL_SESS_CACHE_NO_INTERNAL



class Error(Exception):
    pass



class WantReadError(Error):
    pass



def _asFileDescriptor(obj):
    fd = None

    if not isinstance(obj, int):
        meth = getattr(obj, "fileno", None)
        if meth is not None:
            obj = meth()

    if isinstance(obj, int):
        fd = obj

    if not isinstance(fd, int):
        raise TypeError("argument must be an int, or have a fileno() method.")
    elif fd < 0:
        raise ValueError(
            "file descriptor cannot be a negative integer (%i)" % (fd,))

    return fd



def SSLeay_version(type):
    """
    Return a string describing the version of OpenSSL in use.

    :param type: One of the SSLEAY_ constants defined in this module.
    """
    return _api.string(_api.SSLeay_version(type))



class Context(object):
    """
    :py:obj:`OpenSSL.SSL.Context` instances define the parameters for setting up
    new SSL connections.
    """
    _methods = {
        # TODO
        # SSLv2_METHOD: _api.SSLv2_method,
        SSLv3_METHOD: _api.SSLv3_method,
        TLSv1_METHOD: _api.TLSv1_method,
        SSLv23_METHOD: _api.SSLv23_method,
        }

    def __init__(self, method):
        """
        :param method: One of SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, or
            TLSv1_METHOD.
        """
        if not isinstance(method, int):
            raise TypeError("method must be an integer")

        try:
            method_func = self._methods[method]
        except KeyError:
            raise ValueError("No such protocol")

        method_obj = method_func()

        context = _api.SSL_CTX_new(method_obj)
        if context == _api.NULL:
            1/0

        self._context = context
        self._passphrase_callback = None
        self._verify_callback = None
        self._info_callback = None
        self._tlsext_servername_callback = None
        self._passphrase_userdata = None
        self._app_data = None

    # SSL_CTX_set_app_data(self->ctx, self);
    # SSL_CTX_set_mode(self->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
    #                             SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
    #                             SSL_MODE_AUTO_RETRY);


    def load_verify_locations(self, cafile, capath=None):
        """
        Let SSL know where we can find trusted certificates for the certificate
        chain

        :param cafile: In which file we can find the certificates
        :param capath: In which directory we can find the certificates
        :return: None
        """
        if cafile is None:
            cafile = _api.NULL
        elif not isinstance(cafile, bytes):
            raise TypeError("cafile must be None or a byte string")

        if capath is None:
            capath = _api.NULL
        elif not isinstance(capath, bytes):
            raise TypeError("capath must be None or a byte string")

        load_result = _api.SSL_CTX_load_verify_locations(self._context, cafile, capath)
        if not load_result:
            _raise_current_error(Error)


    def _wrap_callback(self, callback):
        @wraps(callback)
        def wrapper(size, verify, userdata):
            return callback(size, verify, self._passphrase_userdata)
        return _PassphraseHelper(
            FILETYPE_PEM, wrapper, more_args=True, truncate=True)


    def set_passwd_cb(self, callback, userdata=None):
        """
        Set the passphrase callback

        :param callback: The Python callback to use
        :param userdata: (optional) A Python object which will be given as
                         argument to the callback
        :return: None
        """
        if not callable(callback):
            raise TypeError("callback must be callable")

        self._passphrase_helper = self._wrap_callback(callback)
        self._passphrase_callback = self._passphrase_helper.callback
        _api.SSL_CTX_set_default_passwd_cb(
            self._context, self._passphrase_callback)
        self._passphrase_userdata = userdata


    def set_default_verify_paths(self):
        """
        Use the platform-specific CA certificate locations

        :return: None
        """
        set_result = _api.SSL_CTX_set_default_verify_paths(self._context)
        if not set_result:
            1/0
            _raise_current_error(Error)


    def use_certificate_chain_file(self, certfile):
        """
        Load a certificate chain from a file

        :param certfile: The name of the certificate chain file
        :return: None
        """
        if not isinstance(certfile, bytes):
            raise TypeError("certfile must be a byte string")

        result = _api.SSL_CTX_use_certificate_chain_file(self._context, certfile)
        if not result:
            _raise_current_error(Error)


    def use_certificate_file(self, certfile, filetype=_unspecified):
        """
        Load a certificate from a file

        :param certfile: The name of the certificate file
        :param filetype: (optional) The encoding of the file, default is PEM
        :return: None
        """

    def use_certificate(self, cert):
        """
        Load a certificate from a X509 object

        :param cert: The X509 object
        :return: None
        """
        if not isinstance(cert, X509):
            raise TypeError("cert must be an X509 instance")

        use_result = _api.SSL_CTX_use_certificate(self._context, cert._x509)
        if not use_result:
            1/0


    def add_extra_chain_cert(self, certobj):
        """
        Add certificate to chain

        :param certobj: The X509 certificate object to add to the chain
        :return: None
        """
        if not isinstance(certobj, X509):
            raise TypeError("certobj must be an X509 instance")

        copy = _api.X509_dup(certobj._x509)
        add_result = _api.SSL_CTX_add_extra_chain_cert(self._context, certobj._x509)
        if not add_result:
            # _api.X509_free(copy)
            # _raise_current_error(Error)
            1/0

    def use_privatekey_file(self, keyfile, filetype=_unspecified):
        """
        Load a private key from a file

        :param keyfile: The name of the key file
        :param filetype: (optional) The encoding of the file, default is PEM
        :return: None
        """
        if not isinstance(keyfile, bytes):
            raise TypeError("keyfile must be a byte string")

        if filetype is _unspecified:
            filetype = FILETYPE_PEM
        elif not isinstance(filetype, int):
            raise TypeError("filetype must be an integer")

        use_result = _api.SSL_CTX_use_PrivateKey_file(
            self._context, keyfile, filetype)
        if not use_result:
            exception = self._passphrase_helper.raise_if_problem(Error)
            if exception is not None:
                raise exception


    def use_privatekey(self, pkey):
        """
        Load a private key from a PKey object

        :param pkey: The PKey object
        :return: None
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")

        use_result = _api.SSL_CTX_use_PrivateKey(self._context, pkey._pkey)
        if not use_result:
            exception = self._passphrase_helper.raise_if_problem(Error)
            if exception is not None:
                raise exception


    def check_privatekey(self):
        """
        Check that the private key and certificate match up

        :return: None (raises an exception if something's wrong)
        """

    def load_client_ca(self, cafile):
        """
        Load the trusted certificates that will be sent to the client (basically
        telling the client "These are the guys I trust").  Does not actually
        imply any of the certificates are trusted; that must be configured
        separately.

        :param cafile: The name of the certificates file
        :return: None
        """

    def set_session_id(self, buf):
        """
        Set the session identifier.  This is needed if you want to do session
        resumption.

        :param buf: A Python object that can be safely converted to a string
        :returns: None
        """

    def set_session_cache_mode(self, mode):
        """
        Enable/disable session caching and specify the mode used.

        :param mode: One or more of the SESS_CACHE_* flags (combine using
            bitwise or)
        :returns: The previously set caching mode.
        """
        if not isinstance(mode, int):
            raise TypeError("mode must be an integer")

        return _api.SSL_CTX_set_session_cache_mode(self._context, mode)


    def get_session_cache_mode(self):
        """
        :returns: The currently used cache mode.
        """
        return _api.SSL_CTX_get_session_cache_mode(self._context)


    def set_verify(self, mode, callback):
        """
        Set the verify mode and verify callback

        :param mode: The verify mode, this is either VERIFY_NONE or
                     VERIFY_PEER combined with possible other flags
        :param callback: The Python callback to use
        :return: None

        See SSL_CTX_set_verify(3SSL) for further details.
        """
        if not isinstance(mode, int):
            raise TypeError("mode must be an integer")

        if not callable(callback):
            raise TypeError("callback must be callable")

        @wraps(callback)
        def wrapper(ok, store_ctx):
            cert = X509.__new__(X509)
            cert._x509 = _api.X509_STORE_CTX_get_current_cert(store_ctx)
            error_number = _api.X509_STORE_CTX_get_error(store_ctx)
            error_depth = _api.X509_STORE_CTX_get_error_depth(store_ctx)

            try:
                result = callback(self, cert, error_number, error_depth, ok)
            except Exception as e:
                # TODO
                pass
            else:
                if result:
                    _api.X509_STORE_CTX_set_error(store_ctx, _api.X509_V_OK)
                    return 1
                else:
                    return 0

        self._verify_callback = _api.ffi.callback("verify_callback", wrapper)
        _api.SSL_CTX_set_verify(self._context, mode, self._verify_callback)


    def set_verify_depth(self, depth):
        """
        Set the verify depth

        :param depth: An integer specifying the verify depth
        :return: None
        """
        if not isinstance(depth, int):
            raise TypeError("depth must be an integer")

        _api.SSL_CTX_set_verify_depth(self._context, depth)


    def get_verify_mode(self):
        """
        Get the verify mode

        :return: The verify mode
        """
        return _api.SSL_CTX_get_verify_mode(self._context)


    def get_verify_depth(self):
        """
        Get the verify depth

        :return: The verify depth
        """
        return _api.SSL_CTX_get_verify_depth(self._context)


    def load_tmp_dh(self, dhfile):
        """
        Load parameters for Ephemeral Diffie-Hellman

        :param dhfile: The file to load EDH parameters from
        :return: None
        """
        if not isinstance(dhfile, bytes):
            raise TypeError("dhfile must be a byte string")

        bio = _api.BIO_new_file(dhfile, "r")
        if bio == _api.NULL:
            _raise_current_error(Error)
        bio = _api.ffi.gc(bio, _api.BIO_free)

        dh = _api.PEM_read_bio_DHparams(bio, _api.NULL, _api.NULL, _api.NULL)
        dh = _api.ffi.gc(dh, _api.DH_free)
        _api.SSL_CTX_set_tmp_dh(self._context, dh)


    def set_cipher_list(self, cipher_list):
        """
        Change the cipher list

        :param cipher_list: A cipher list, see ciphers(1)
        :return: None
        """
        if not isinstance(cipher_list, bytes):
            raise TypeError("cipher_list must be a byte string")

        result = _api.SSL_CTX_set_cipher_list(self._context, cipher_list)
        if not result:
            _raise_current_error(Error)


    def set_client_ca_list(self, certificate_authorities):
        """
        Set the list of preferred client certificate signers for this server context.

        This list of certificate authorities will be sent to the client when the
        server requests a client certificate.

        :param certificate_authorities: a sequence of X509Names.
        :return: None
        """

    def add_client_ca(self, certificate_authority):
        """
        Add the CA certificate to the list of preferred signers for this context.

        The list of certificate authorities will be sent to the client when the
        server requests a client certificate.

        :param certificate_authority: certificate authority's X509 certificate.
        :return: None
        """

    def set_timeout(self, timeout):
        """
        Set session timeout

        :param timeout: The timeout in seconds
        :return: The previous session timeout
        """
        if not isinstance(timeout, int):
            raise TypeError("timeout must be an integer")

        return _api.SSL_CTX_set_timeout(self._context, timeout)


    def get_timeout(self):
        """
        Get the session timeout

        :return: The session timeout
        """
        return _api.SSL_CTX_get_timeout(self._context)


    def set_info_callback(self, callback):
        """
        Set the info callback

        :param callback: The Python callback to use
        :return: None
        """
        @wraps(callback)
        def wrapper(ssl, where, return_code):
            callback(self, where, return_code)
        self._info_callback = _api.callback('info_callback', wrapper)
        _api.SSL_CTX_set_info_callback(self._context, self._info_callback)


    def get_app_data(self):
        """
        Get the application data (supplied via set_app_data())

        :return: The application data
        """
        return self._app_data


    def set_app_data(self, data):
        """
        Set the application data (will be returned from get_app_data())

        :param data: Any Python object
        :return: None
        """
        self._app_data = data


    def get_cert_store(self):
        """
        Get the certificate store for the context

        :return: A X509Store object
        """

    def set_options(self, options):
        """
        Add options. Options set before are not cleared!

        :param options: The options to add.
        :return: The new option bitmask.
        """
        if not isinstance(options, options):
            raise TypeError("options must be an integer")

        return _api.SSL_CTX_set_options(self._context, options)


    def set_mode(self, mode):
        """
        Add modes via bitmask. Modes set before are not cleared!

        :param mode: The mode to add.
        :return: The new mode bitmask.
        """
        if not isinstance(mode, int):
            raise TypeError("mode must be an integer")

        return _api.SSL_CTX_set_mode(self._context, mode)


    def set_tlsext_servername_callback(self, callback):
        """
        Specify a callback function to be called when clients specify a server name.

        :param callback: The callback function.  It will be invoked with one
            argument, the Connection instance.
        """

ContextType = Context



class Connection(object):
    """
    """
    def __init__(self, context, socket=None):
        """
        Create a new Connection object, using the given OpenSSL.SSL.Context
        instance and socket.

        :param context: An SSL Context to use for this connection
        :param socket: The socket to use for transport layer
        """
        if not isinstance(context, Context):
            raise TypeError("context must be a Context instance")

        self._ssl = _api.SSL_new(context._context)

        if socket is None:
            self._socket = None
            self._into_ssl = _new_mem_buf()
            self._from_ssl = _new_mem_buf()

            if self._into_ssl == _api.NULL or self._from_ssl == _api.NULL:
                1/0

            _api.SSL_set_bio(self._ssl, self._into_ssl, self._from_ssl)
        else:
            self._socket = socket
            set_result = _api.SSL_set_fd(self._ssl, _asFileDescriptor(self._socket))
            if not set_result:
                1/0


    def __getattr__(self, name):
        """
        Look up attributes on the wrapped socket object if they are not found on
        the Connection object.
        """
        return getattr(self._socket, name)


    def _raise_ssl_error(self, error, result):
        if error == _api.SSL_ERROR_WANT_READ:
            raise WantReadError()
        else:
            _raise_current_error(Error)


    def get_context(self):
        """
        Get session context
        """


    def set_context(self):
        """
        Switch this connection to a new session context

        :param context: A :py:class:`Context` instance giving the new session context to use.
        """

    def get_servername(self):
        """
        Retrieve the servername extension value if provided in the client hello
        message, or None if there wasn't one.

        :return: A byte string giving the server name or :py:data:`None`.
        """

    def set_tlsext_host_name(self):
        """
        Set the value of the servername extension to send in the client hello.

        :param name: A byte string giving the name.
        """

    def pending(self):
        """
        Get the number of bytes that can be safely read from the connection

        :return: The number of bytes available in the receive buffer.
        """


    def _handle_SSL_result(self, ssl, result):
        error = _api.SSL_get_error(ssl, result)
        if error != _api.SSL_ERROR_NONE:
            self._raise_ssl_error(error, result)


    def send(self, data, flags=None):
        """
        Send data on the connection. NOTE: If you get one of the WantRead,
        WantWrite or WantX509Lookup exceptions on this, you have to call the
        method again with the SAME buffer.

        :param buf: The string to send
        :param flags: (optional) Included for compatibility with the socket
                      API, the value is ignored
        :return: The number of bytes written
        """
        result = _api.SSL_write(self._ssl, data, len(data))
        self._handle_SSL_result(self._ssl, result)
        return result
    write = send


    def sendall(self):
        """
        Send \"all\" data on the connection. This calls send() repeatedly until
        all data is sent. If an error occurs, it's impossible to tell how much data
        has been sent.

        :param buf: The string to send
        :param flags: (optional) Included for compatibility with the socket
                      API, the value is ignored
        :return: The number of bytes written
        """

    def recv(self, bufsiz, flags=None):
        """
        Receive data on the connection. NOTE: If you get one of the WantRead,
        WantWrite or WantX509Lookup exceptions on this, you have to call the
        method again with the SAME buffer.

        :param bufsiz: The maximum number of bytes to read
        :param flags: (optional) Included for compatibility with the socket
                      API, the value is ignored
        :return: The string read from the Connection
        """
        buf = _api.new("char[]", bufsiz)
        result = _api.SSL_read(self._ssl, buf, bufsiz)
        self._handle_SSL_result(self._ssl, result)
        return _api.buffer(buf, result)
    read = recv


    def bio_read(self):
        """
        When using non-socket connections this function reads
        the \"dirty\" data that would have traveled away on the network.

        :param bufsiz: The maximum number of bytes to read
        :return: The string read.
        """

    def bio_write(self):
        """
        When using non-socket connections this function sends
        \"dirty\" data that would have traveled in on the network.

        :param buf: The string to put into the memory BIO.
        :return: The number of bytes written
        """

    def renegotiate(self):
        """
        Renegotiate the session

        :return: True if the renegotiation can be started, false otherwise
        """

    def do_handshake(self):
        """
        Perform an SSL handshake (usually called after renegotiate() or one of
        set_*_state()). This can raise the same exceptions as send and recv.

        :return: None.
        """
        result = _api.SSL_do_handshake(self._ssl)
        self._handle_SSL_result(self._ssl, result)


    def renegotiate_pending(self):
        """
        Check if there's a renegotiation in progress, it will return false once
        a renegotiation is finished.

        :return: Whether there's a renegotiation in progress
        """

    def total_renegotiations(self):
        """
        Find out the total number of renegotiations.

        :return: The number of renegotiations.
        """

    def connect(self):
        """
        Connect to remote host and set up client-side SSL

        :param addr: A remote address
        :return: What the socket's connect method returns
        """

    def connect_ex(self):
        """
        Connect to remote host and set up client-side SSL. Note that if the socket's
        connect_ex method doesn't return 0, SSL won't be initialized.

        :param addr: A remove address
        :return: What the socket's connect_ex method returns
        """

    def accept(self):
        """
        Accept incoming connection and set up SSL on it

        :return: A (conn,addr) pair where conn is a Connection and addr is an
                 address
        """


    def bio_shutdown(self):
        """
        When using non-socket connections this function signals end of
        data on the input for this connection.

        :return: None
        """

    def shutdown(self):
        """
        Send closure alert

        :return: True if the shutdown completed successfully (i.e. both sides
                 have sent closure alerts), false otherwise (i.e. you have to
                 wait for a ZeroReturnError on a recv() method call
        """
        result = _api.SSL_shutdown(self._ssl)
        if result < 0:
            1/0
        elif result > 0:
            2/0
        else:
            return False


    def get_cipher_list(self):
        """
        Get the session cipher list

        :return: A list of cipher strings
        """
        ciphers = []
        for i in count():
            result = _api.SSL_get_cipher_list(self._ssl, i)
            if result == _api.NULL:
                break
            ciphers.append(_api.string(result))
        return ciphers


    def get_client_ca_list(self):
        """
        Get CAs whose certificates are suggested for client authentication.

        :return: If this is a server connection, a list of X509Names representing
            the acceptable CAs as set by :py:meth:`OpenSSL.SSL.Context.set_client_ca_list` or
            :py:meth:`OpenSSL.SSL.Context.add_client_ca`.  If this is a client connection,
            the list of such X509Names sent by the server, or an empty list if that
            has not yet happened.
        """

    def makefile(self):
        """
        The makefile() method is not implemented, since there is no dup semantics
        for SSL connections

        :raise NotImplementedError
        """


    def get_app_data(self):
        """
        Get application data

        :return: The application data
        """

    def set_app_data(self):
        """
        Set application data

        :param data - The application data
        :return: None
        """

    def get_shutdown(self):
        """
        Get shutdown state

        :return: The shutdown state, a bitvector of SENT_SHUTDOWN, RECEIVED_SHUTDOWN.
        """
        return _api.SSL_get_shutdown(self._ssl)


    def set_shutdown(self):
        """
        Set shutdown state

        :param state - bitvector of SENT_SHUTDOWN, RECEIVED_SHUTDOWN.
        :return: None
        """

    def state_string(self):
        """
        Get a verbose state description

        :return: A string representing the state
        """

    def server_random(self):
        """
        Get a copy of the server hello nonce.

        :return: A string representing the state
        """

    def client_random(self):
        """
        Get a copy of the client hello nonce.

        :return: A string representing the state
        """

    def master_key(self):
        """
        Get a copy of the master key.

        :return: A string representing the state
        """

    def sock_shutdown(self):
        """
        See shutdown(2)

        :return: What the socket's shutdown() method returns
        """

    def get_peer_certificate(self):
        """
        Retrieve the other side's certificate (if any)

        :return: The peer's certificate
        """
        cert = _api.SSL_get_peer_certificate(self._ssl)
        if cert != _api.NULL:
            pycert = X509.__new__(X509)
            pycert._x509 = _api.ffi.gc(cert, _api.X509_free)
            return pycert
        return None


    def get_peer_cert_chain(self):
        """
        Retrieve the other side's certificate (if any)

        :return: A list of X509 instances giving the peer's certificate chain,
                 or None if it does not have one.
        """

    def want_read(self):
        """
        Checks if more data has to be read from the transport layer to complete an
        operation.

        :return: True iff more data has to be read
        """

    def want_write(self):
        """
        Checks if there is data to write to the transport layer to complete an
        operation.

        :return: True iff there is data to write
        """

    def set_accept_state(self):
        """
        Set the connection to work in server mode. The handshake will be handled
        automatically by read/write.

        :return: None
        """
        _api.SSL_set_accept_state(self._ssl)


    def set_connect_state(self):
        """
        Set the connection to work in client mode. The handshake will be handled
        automatically by read/write.

        :return: None
        """
        _api.SSL_set_connect_state(self._ssl)


    def get_session(self):
        """
        Returns the Session currently used.

        @return: An instance of :py:class:`OpenSSL.SSL.Session` or :py:obj:`None` if
            no session exists.
        """

    def set_session(self):
        """
        Set the session to be used when the TLS/SSL connection is established.

        :param session: A Session instance representing the session to use.
        :returns: None
        """

ConnectionType = Connection
