.. _openssl-ssl:

:py:mod:`SSL` --- An interface to the SSL-specific parts of OpenSSL
===================================================================

.. py:module:: OpenSSL.SSL
    :synopsis: An interface to the SSL-specific parts of OpenSSL


This module handles things specific to SSL. There are two objects defined:
Context, Connection.

.. py:data:: SSLv2_METHOD
             SSLv3_METHOD
             SSLv23_METHOD
             TLSv1_METHOD
             TLSv1_1_METHOD
             TLSv1_2_METHOD

    These constants represent the different SSL methods to use when creating a
    context object.  If the underlying OpenSSL build is missing support for any
    of these protocols, constructing a :py:class:`Context` using the
    corresponding :py:const:`*_METHOD` will raise an exception.


.. py:data:: VERIFY_NONE
             VERIFY_PEER
             VERIFY_FAIL_IF_NO_PEER_CERT

    These constants represent the verification mode used by the Context
    object's :py:meth:`set_verify` method.


.. py:data:: FILETYPE_PEM
             FILETYPE_ASN1

    File type constants used with the :py:meth:`use_certificate_file` and
    :py:meth:`use_privatekey_file` methods of Context objects.


.. py:data:: OP_SINGLE_DH_USE
             OP_SINGLE_ECDH_USE

    Constants used with :py:meth:`set_options` of Context objects.

    When these options are used, a new key will always be created when using
    ephemeral (Elliptic curve) Diffie-Hellman.


.. py:data:: OP_EPHEMERAL_RSA

    Constant used with :py:meth:`set_options` of Context objects.

    When this option is used, ephemeral RSA keys will always be used when doing
    RSA operations.


.. py:data:: OP_NO_TICKET

    Constant used with :py:meth:`set_options` of Context objects.

    When this option is used, the session ticket extension will not be used.


.. py:data:: OP_NO_COMPRESSION

    Constant used with :py:meth:`set_options` of Context objects.

    When this option is used, compression will not be used.


.. py:data:: OP_NO_SSLv2
             OP_NO_SSLv3
             OP_NO_TLSv1
             OP_NO_TLSv1_1
             OP_NO_TLSv1_2
             OP_NO_TLSv1_3

    Constants used with :py:meth:`set_options` of Context objects.

    Each of these options disables one version of the SSL/TLS protocol.  This
    is interesting if you're using e.g. :py:const:`SSLv23_METHOD` to get an
    SSLv2-compatible handshake, but don't want to use SSLv2.  If the underlying
    OpenSSL build is missing support for any of these protocols, the
    :py:const:`OP_NO_*` constant may be undefined.


.. py:data:: SSLEAY_VERSION
             SSLEAY_CFLAGS
             SSLEAY_BUILT_ON
             SSLEAY_PLATFORM
             SSLEAY_DIR

    Constants used with :py:meth:`SSLeay_version` to specify what OpenSSL version
    information to retrieve.  See the man page for the :py:func:`SSLeay_version` C
    API for details.


.. py:data:: SESS_CACHE_OFF
             SESS_CACHE_CLIENT
             SESS_CACHE_SERVER
             SESS_CACHE_BOTH
             SESS_CACHE_NO_AUTO_CLEAR
             SESS_CACHE_NO_INTERNAL_LOOKUP
             SESS_CACHE_NO_INTERNAL_STORE
             SESS_CACHE_NO_INTERNAL

     Constants used with :py:meth:`Context.set_session_cache_mode` to specify
     the behavior of the session cache and potential session reuse.  See the man
     page for the :py:func:`SSL_CTX_set_session_cache_mode` C API for details.

     .. versionadded:: 0.14


.. py:data:: OPENSSL_VERSION_NUMBER

    An integer giving the version number of the OpenSSL library used to build this
    version of pyOpenSSL.  See the man page for the :py:func:`SSLeay_version` C API
    for details.


.. py:data:: NO_OVERLAPPING_PROTOCOLS

    A sentinel value that can be returned by the callback passed to
    :py:meth:`Context.set_alpn_select_callback` to indicate that
    the handshake can continue without a specific application protocol.

    .. versionadded:: 19.1


.. autofunction:: SSLeay_version


.. py:data:: ContextType

    See :py:class:`Context`.


.. autoclass:: Context

.. autoclass:: Session


.. py:data:: ConnectionType

    See :py:class:`Connection`.


.. py:class:: Connection(context, socket)

    A class representing SSL connections.

    *context* should be an instance of :py:class:`Context` and *socket*
    should be a socket [#connection-context-socket]_  object.  *socket* may be
    *None*; in this case, the Connection is created with a memory BIO: see
    the :py:meth:`bio_read`, :py:meth:`bio_write`, and :py:meth:`bio_shutdown`
    methods.

.. py:exception:: Error

    This exception is used as a base class for the other SSL-related
    exceptions, but may also be raised directly.

    Whenever this exception is raised directly, it has a list of error messages
    from the OpenSSL error queue, where each item is a tuple *(lib, function,
    reason)*. Here *lib*, *function* and *reason* are all strings, describing
    where and what the problem is. See :manpage:`err(3)` for more information.


.. py:exception:: ZeroReturnError

    This exception matches the error return code
    :py:data:`SSL_ERROR_ZERO_RETURN`, and is raised when the SSL Connection has
    been closed. In SSL 3.0 and TLS 1.0, this only occurs if a closure alert has
    occurred in the protocol, i.e.  the connection has been closed cleanly. Note
    that this does not necessarily mean that the transport layer (e.g. a socket)
    has been closed.

    It may seem a little strange that this is an exception, but it does match an
    :py:data:`SSL_ERROR` code, and is very convenient.


.. py:exception:: WantReadError

    The operation did not complete; the same I/O method should be called again
    later, with the same arguments. Any I/O method can lead to this since new
    handshakes can occur at any time.

    The wanted read is for **dirty** data sent over the network, not the
    **clean** data inside the tunnel.  For a socket based SSL connection,
    **read** means data coming at us over the network.  Until that read
    succeeds, the attempted :py:meth:`OpenSSL.SSL.Connection.recv`,
    :py:meth:`OpenSSL.SSL.Connection.send`, or
    :py:meth:`OpenSSL.SSL.Connection.do_handshake` is prevented or incomplete. You
    probably want to :py:meth:`select()` on the socket before trying again.


.. py:exception:: WantWriteError

    See :py:exc:`WantReadError`.  The socket send buffer may be too full to
    write more data.


.. py:exception:: WantX509LookupError

    The operation did not complete because an application callback has asked to be
    called again. The I/O method should be called again later, with the same
    arguments.

    .. note:: This won't occur in this version, as there are no such
        callbacks in this version.


.. py:exception:: SysCallError

    The :py:exc:`SysCallError` occurs when there's an I/O error and OpenSSL's
    error queue does not contain any information. This can mean two things: An
    error in the transport protocol, or an end of file that violates the protocol.
    The parameter to the exception is always a pair *(errnum,
    errstr)*.



.. _openssl-context:

Context objects
---------------

Context objects have the following methods:

.. autoclass:: OpenSSL.SSL.Context
               :members:

.. _openssl-session:

Session objects
---------------

Session objects have no methods.


.. _openssl-connection:

Connection objects
------------------

Connection objects have the following methods:

.. autoclass:: OpenSSL.SSL.Connection
               :members:


.. Rubric:: Footnotes

.. [#connection-context-socket] Actually, all that is required is an object that
    **behaves** like a socket, you could even use files, even though it'd be
    tricky to get the handshakes right!
