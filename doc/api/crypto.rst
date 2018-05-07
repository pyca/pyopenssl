.. _openssl-crypto:

:py:mod:`crypto` --- Generic cryptographic module
=================================================

.. py:module:: OpenSSL.crypto
   :synopsis: Generic cryptographic module

.. note::

    `pyca/cryptography`_ is likely a better choice than using this module.
    It contains a complete set of cryptographic primitives as well as a significantly better and more powerful X509 API.
    If necessary you can convert to and from cryptography objects using the ``to_cryptography`` and ``from_cryptography`` methods on ``X509``, ``X509Req``, ``CRL``, and ``PKey``.


Elliptic curves
---------------

.. autofunction:: get_elliptic_curves

.. autofunction:: get_elliptic_curve

Serialization and deserialization
---------------------------------

The following serialization functions take one of these constants to determine the format.

.. py:data:: FILETYPE_PEM

:data:`FILETYPE_PEM` serializes data to a Base64-encoded encoded representation of the underlying ASN.1 data structure. This representation includes delimiters that define what data structure is contained within the Base64-encoded block: for example, for a certificate, the delimiters are ``-----BEGIN CERTIFICATE-----`` and ``-----END CERTIFICATE-----``.

.. py:data:: FILETYPE_ASN1

:data:`FILETYPE_ASN1` serializes data to the underlying ASN.1 data structure. The format used by :data:`FILETYPE_ASN1` is also sometimes referred to as DER.

Certificates
~~~~~~~~~~~~

.. autofunction:: dump_certificate

.. autofunction:: load_certificate

Certificate signing requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: dump_certificate_request

.. autofunction:: load_certificate_request

Private keys
~~~~~~~~~~~~

.. autofunction:: dump_privatekey

.. autofunction:: load_privatekey

Public keys
~~~~~~~~~~~

.. autofunction:: dump_publickey

.. autofunction:: load_publickey

Certificate revocation lists
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autofunction:: dump_crl

.. autofunction:: load_crl

.. autofunction:: load_pkcs7_data

.. autofunction:: load_pkcs12

Signing and verifying signatures
--------------------------------

.. autofunction:: sign

.. autofunction:: verify


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

.. _openssl-x509storecontexterror:

X509StoreContextError objects
-----------------------------

.. autoclass:: X509StoreContextError
               :members:

.. _openssl-x509storecontext:

X509StoreContext objects
------------------------

.. autoclass:: X509StoreContext
               :members:

.. _openssl-pkey:

X509StoreFlags constants
------------------------

.. autoclass:: X509StoreFlags

    .. data:: CRL_CHECK
    .. data:: CRL_CHECK_ALL
    .. data:: IGNORE_CRITICAL
    .. data:: X509_STRICT
    .. data:: ALLOW_PROXY_CERTS
    .. data:: POLICY_CHECK
    .. data:: EXPLICIT_POLICY
    .. data:: INHIBIT_MAP
    .. data:: NOTIFY_POLICY
    .. data:: CHECK_SS_SIGNATURE
    .. data:: CB_ISSUER_CHECK

.. _openssl-x509storeflags:

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

.. autoclass:: PKCS7
               :members:

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

Several of the functions and methods in this module take a digest name.
These must be strings describing a digest algorithm supported by OpenSSL (by ``EVP_get_digestbyname``, specifically).
For example, :const:`b"sha256"` or :const:`b"sha384"`.

More information and a list of these digest names can be found in the ``EVP_DigestInit(3)`` man page of your OpenSSL installation.
This page can be found online for the latest version of OpenSSL:
https://www.openssl.org/docs/manmaster/man3/EVP_DigestInit.html

.. _`pyca/cryptography`:  https://cryptography.io
