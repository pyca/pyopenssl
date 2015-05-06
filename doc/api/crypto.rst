.. _openssl-crypto:

:py:mod:`crypto` --- Generic cryptographic module
=================================================

.. py:module:: OpenSSL.crypto
   :synopsis: Generic cryptographic module

Elliptic curves
---------------

.. py:function:: get_elliptic_curves

    Return a set of objects representing the elliptic curves supported in the
    OpenSSL build in use.

    The curve objects have a :py:class:`unicode` ``name`` attribute by which
    they identify themselves.

    The curve objects are useful as values for the argument accepted by
    :py:meth:`Context.set_tmp_ecdh` to specify which elliptical curve should be
    used for ECDHE key exchange.


.. py:function:: get_elliptic_curve

    Return a single curve object selected by name.

    See :py:func:`get_elliptic_curves` for information about curve objects.

    If the named curve is not supported then :py:class:`ValueError` is raised.


Serialization and deserialization
---------------------------------

The following serialization functions take one of these constants to
determine the format:

.. py:data:: FILETYPE_PEM
             FILETYPE_ASN1

Certificates
~~~~~~~~~~~~

.. py:function:: dump_certificate(type, cert)

    Dump the certificate *cert* into a buffer string encoded with the type
    *type*.

.. py:function:: load_certificate(type, buffer)

    Load a certificate (X509) from the string *buffer* encoded with the
    type *type*.

Certificate signing requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:function:: dump_certificate_request(type, req)

    Dump the certificate request *req* into a buffer string encoded with the
    type *type*.

.. py:function:: load_certificate_request(type, buffer)

    Load a certificate request (X509Req) from the string *buffer* encoded with
    the type *type*.

Private keys
~~~~~~~~~~~~

.. py:function:: dump_privatekey(type, pkey[, cipher, passphrase])

    Dump the private key *pkey* into a buffer string encoded with the type
    *type*, optionally (if *type* is :py:const:`FILETYPE_PEM`) encrypting it
    using *cipher* and *passphrase*.

    *passphrase* must be either a string or a callback for providing the
    pass phrase.

.. py:function:: load_privatekey(type, buffer[, passphrase])

    Load a private key (PKey) from the string *buffer* encoded with the type
    *type* (must be one of :py:const:`FILETYPE_PEM` and
    :py:const:`FILETYPE_ASN1`).

    *passphrase* must be either a string or a callback for providing the pass
    phrase.

Certificate revocation lists
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:function:: load_crl(type, buffer)

    Load Certificate Revocation List (CRL) data from a string *buffer*.
    *buffer* encoded with the type *type*.  The type *type* must either
    :py:const:`FILETYPE_PEM` or :py:const:`FILETYPE_ASN1`).


.. py:function:: load_pkcs7_data(type, buffer)

    Load pkcs7 data from the string *buffer* encoded with the type
    *type*. The type *type* must either :py:const:`FILETYPE_PEM` or
    :py:const:`FILETYPE_ASN1`).


.. py:function:: load_pkcs12(buffer[, passphrase])

    Load pkcs12 data from the string *buffer*. If the pkcs12 structure is
    encrypted, a *passphrase* must be included.  The MAC is always
    checked and thus required.

    See also the man page for the C function :py:func:`PKCS12_parse`.

Signing and verifying signatures
--------------------------------

.. py:function:: sign(key, data, digest)

    Sign a data string using the given key and message digest.

    *key* is a :py:class:`PKey` instance.  *data* is a ``str`` instance.
    *digest* is a ``str`` naming a supported message digest type, for example
    :py:const:`sha1`.

    .. versionadded:: 0.11


.. py:function:: verify(certificate, signature, data, digest)

    Verify the signature for a data string.

    *certificate* is a :py:class:`X509` instance corresponding to the private
    key which generated the signature.  *signature* is a *str* instance giving
    the signature itself.  *data* is a *str* instance giving the data to which
    the signature applies.  *digest* is a *str* instance naming the message
    digest type of the signature, for example :py:const:`sha1`.

    .. versionadded:: 0.11


.. _openssl-x509:

X509 objects
------------

.. autoclass:: X509
               :members:

.. _openssl-x509name:

X509Name objects
----------------

.. autoclass:: X509Name
               :members:
               :special-members:
               :exclude-members: __repr__, __getattr__, __weakref__

.. _openssl-x509req:

X509Req objects
---------------

.. autoclass:: X509Req
               :members:
               :special-members:
               :exclude-members: __weakref__

.. _openssl-x509store:

X509Store objects
-----------------

.. autoclass:: X509Store
               :members:

X509StoreContextError objects
-----------------------------

The X509StoreContextError is an exception raised from
`X509StoreContext.verify_certificate` in circumstances where a certificate
cannot be verified in a provided context.

The certificate for which the verification error was detected is given by the
``certificate`` attribute of the exception instance as a :class:`X509`
instance.

Details about the verification error are given in the exception's
``args`` attribute.

X509StoreContext objects
------------------------

The X509StoreContext object is used for verifying a certificate against a set
of trusted certificates.


.. py:method:: X509StoreContext.verify_certificate()

    Verify a certificate in the context of this initialized `X509StoreContext`.
    On error, raises `X509StoreContextError`, otherwise does nothing.

    .. versionadded:: 0.15


.. _openssl-pkey:

PKey objects
------------

.. autoclass:: PKey
               :members:

.. _openssl-pkcs7:

.. py:data:: TYPE_RSA
             TYPE_DSA

    Key type constants.

PKCS7 objects
-------------

PKCS7 objects have the following methods:

.. py:method:: PKCS7.type_is_signed()

    FIXME

.. py:method:: PKCS7.type_is_enveloped()

    FIXME

.. py:method:: PKCS7.type_is_signedAndEnveloped()

    FIXME

.. py:method:: PKCS7.type_is_data()

    FIXME

.. py:method:: PKCS7.get_type_name()

    Get the type name of the PKCS7.

.. _openssl-pkcs12:

PKCS12 objects
--------------

.. autoclass:: PKCS12
               :members:

.. _openssl-509ext:

X509Extension objects
---------------------

.. autoclass:: X509Extension
               :members:
               :special-members:
               :exclude-members: __weakref__

.. _openssl-netscape-spki:

NetscapeSPKI objects
--------------------

.. autoclass:: NetscapeSPKI
               :members:
               :special-members:
               :exclude-members: __weakref__

.. _crl:

CRL objects
-----------

.. autoclass:: CRL
               :members:
               :special-members:
               :exclude-members: __weakref__

.. _revoked:

Revoked objects
---------------

.. autoclass:: Revoked
               :members:

Exceptions
----------

.. py:exception:: Error

    Generic exception used in the :py:mod:`.crypto` module.

Digest names
------------

Several of the functions and methods in this module take a digest
name. These must be strings describing a digest algorithm supported by
OpenSSL (by ``EVP_get_digestbyname``, specifically). For example,
:py:const:`b"md5"` or :py:const:`b"sha1"`.

More information and a list of these digest names can be found in the
``EVP_DigestInit(3)`` man page of your OpenSSL installation. This page
can be found online for the latest version of OpenSSL:
https://www.openssl.org/docs/crypto/EVP_DigestInit.html

Backwards compatible type names
-------------------------------

When PyOpenSSL was originally written, the most current version of
Python was 2.1. It made a distinction between classes and types. None
of the versions of Python currently supported by PyOpenSSL still
enforce that distinction: the type of an instance of an
:py:class:`X509` object is now simply :py:class:`X509`. Originally,
the type would have been :py:class:`X509Type`. These days,
:py:class:`X509Type` and :py:class:`X509` are literally the same
object. PyOpenSSL maintains these old names for backwards
compatibility.

Here's a table of these backwards-compatible names:

=========================  =============================
Type name                  Backwards-compatible name
=========================  =============================
:py:class:`X509`           :py:class:`X509Type`
:py:class:`X509Name`       :py:class:`X509NameType`
:py:class:`X509Req`        :py:class:`X509ReqType`
:py:class:`X509Store`      :py:class:`X509StoreType`
:py:class:`X509Extension`  :py:class:`X509ExtensionType`
:py:class:`PKey`           :py:class:`PKeyType`
:py:class:`PKCS7`          :py:class:`PKCS7Type`
:py:class:`PKCS12`         :py:class:`PKCS12Type`
:py:class:`NetscapeSPKI`   :py:class:`NetscapeSPKIType`
:py:class:`CRL`            :py:class:`CRLType`
=========================  =============================

Some objects, such as :py:class`Revoked`, don't have ``Type``
equivalents, because they were added after the restriction had been
lifted.
