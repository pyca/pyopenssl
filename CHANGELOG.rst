Changelog
=========

Versions are year-based with a strict backward-compatibility policy.
The third digit is only for regressions.

16.2.0 (2016-10-15)
-------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

*none*


Changes:
^^^^^^^^

- Fixed compatibility errors with OpenSSL 1.1.0.
- Fixed an issue that caused failures with subinterpreters and embedded Pythons.
  `#552 <https://github.com/pyca/pyopenssl/pull/552>`_


----


16.1.0 (2016-08-26)
-------------------

Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*none*


Deprecations:
^^^^^^^^^^^^^

- Dropped support for OpenSSL 0.9.8.


Changes:
^^^^^^^^

- Fix memory leak in ``OpenSSL.crypto.dump_privatekey()`` with ``FILETYPE_TEXT``.
  `#496 <https://github.com/pyca/pyopenssl/pull/496>`_
- Enable use of CRL (and more) in verify context.
  `#483 <https://github.com/pyca/pyopenssl/pull/483>`_
- ``OpenSSL.crypto.PKey`` can now be constructed from ``cryptography`` objects and also exported as such.
  `#439 <https://github.com/pyca/pyopenssl/pull/439>`_
- Support newer versions of ``cryptography`` which use opaque structs for OpenSSL 1.1.0 compatibility.


----


16.0.0 (2016-03-19)
-------------------

This is the first release under full stewardship of PyCA.
We have made *many* changes to make local development more pleasing.
The test suite now passes both on Linux and OS X with OpenSSL 0.9.8, 1.0.1, and 1.0.2.
It has been moved to `pytest <https://pytest.org/>`_, all CI test runs are part of `tox <https://testrun.org/tox/>`_ and the source code has been made fully `flake8 <https://flake8.readthedocs.io/>`_ compliant.

We hope to have lowered the barrier for contributions significantly but are open to hear about any remaining frustrations.


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Python 3.2 support has been dropped.
  It never had significant real world usage and has been dropped by our main dependency ``cryptography``.
  Affected users should upgrade to Python 3.3 or later.


Deprecations:
^^^^^^^^^^^^^

- The support for EGD has been removed.
  The only affected function ``OpenSSL.rand.egd()`` now uses ``os.urandom()`` to seed the internal PRNG instead.
  Please see `pyca/cryptography#1636 <https://github.com/pyca/cryptography/pull/1636>`_ for more background information on this decision.
  In accordance with our backward compatibility policy ``OpenSSL.rand.egd()`` will be *removed* no sooner than a year from the release of 16.0.0.

  Please note that you should `use urandom <https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/>`_ for all your secure random number needs.
- Python 2.6 support has been deprecated.
  Our main dependency ``cryptography`` deprecated 2.6 in version 0.9 (2015-05-14) with no time table for actually dropping it.
  pyOpenSSL will drop Python 2.6 support once ``cryptography`` does.


Changes:
^^^^^^^^

- Fixed ``OpenSSL.SSL.Context.set_session_id``, ``OpenSSL.SSL.Connection.renegotiate``, ``OpenSSL.SSL.Connection.renegotiate_pending``, and ``OpenSSL.SSL.Context.load_client_ca``.
  They were lacking an implementation since 0.14.
  `#422 <https://github.com/pyca/pyopenssl/pull/422>`_
- Fixed segmentation fault when using keys larger than 4096-bit to sign data.
  `#428 <https://github.com/pyca/pyopenssl/pull/428>`_
- Fixed ``AttributeError`` when ``OpenSSL.SSL.Connection.get_app_data()`` was called before setting any app data.
  `#304 <https://github.com/pyca/pyopenssl/pull/304>`_
- Added ``OpenSSL.crypto.dump_publickey()`` to dump ``OpenSSL.crypto.PKey`` objects that represent public keys, and ``OpenSSL.crypto.load_publickey()`` to load such objects from serialized representations.
  `#382 <https://github.com/pyca/pyopenssl/pull/382>`_
- Added ``OpenSSL.crypto.dump_crl()`` to dump a certificate revocation list out to a string buffer.
  `#368 <https://github.com/pyca/pyopenssl/pull/368>`_
- Added ``OpenSSL.SSL.Connection.get_state_string()`` using the OpenSSL binding ``state_string_long``.
  `#358 <https://github.com/pyca/pyopenssl/pull/358>`_
- Added support for the ``socket.MSG_PEEK`` flag to ``OpenSSL.SSL.Connection.recv()`` and ``OpenSSL.SSL.Connection.recv_into()``.
  `#294 <https://github.com/pyca/pyopenssl/pull/294>`_
- Added ``OpenSSL.SSL.Connection.get_protocol_version()`` and ``OpenSSL.SSL.Connection.get_protocol_version_name()``.
  `#244 <https://github.com/pyca/pyopenssl/pull/244>`_
- Switched to ``utf8string`` mask by default.
  OpenSSL formerly defaulted to a ``T61String`` if there were UTF-8 characters present.
  This was changed to default to ``UTF8String`` in the config around 2005, but the actual code didn't change it until late last year.
  This will default us to the setting that actually works.
  To revert this you can call ``OpenSSL.crypto._lib.ASN1_STRING_set_default_mask_asc(b"default")``.
  `#234 <https://github.com/pyca/pyopenssl/pull/234>`_


----


Older Changelog Entries
-----------------------

The changes from before release 16.0.0 are preserved in the `repository <https://github.com/pyca/pyopenssl/blob/master/doc/ChangeLog_old.txt>`_.
