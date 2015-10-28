Changelog
=========

Versions are year-based with a strict :doc:`backward-compatibility` policy.
The third digit is only for regressions.


15.2.0 (UNRELEASED)
-------------------

This is the first release under full stewardship of PyCA.
We have made *many* changes to make local development more pleasing.
The test suite now passes both on Linux and OS X with OpenSSL 0.9.8, 1.0.1, and 1.0.2.
It has been moved to `py.test <http://pytest.org/latest/>`_, all CI test runs are part of `tox <https://testrun.org/tox/>`_ and the source code has been made fully `flake8 <https://flake8.readthedocs.org/en/>`_ compliant.

We hope to have lowered the barrier for contributions significantly but are open to hear about any remaining frustrations.


Backward-incompatible changes:
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Python 3.2 support has been dropped.
  It never had significant real world usage and has been dropped by our main dependency ``cryptography``.
  Affected users should upgrade to Python 3.3 or later.


Deprecations:
^^^^^^^^^^^^^

- The support for EGD has been removed.
  The only affected function :func:`OpenSSL.rand.egd` now uses :func:`os.urandom` to seed the internal PRNG instead.
  Please see `pyca/cryptography#1636 <https://github.com/pyca/cryptography/pull/1636>`_ for more background information on this decision.

  Please note that you should `use urandom <http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/>`_ for all your secure random number needs.


In accordance with our backward compatibility policy :func:`OpenSSL.rand.egd` will be *removed* no sooner than a year from the release of 15.2.0


Changes:
^^^^^^^^

- Added :func:`OpenSSL.crypto.dump_crl` to dump a certificate revocation list out to a string buffer.
  [`#368 <https://github.com/pyca/pyopenssl/pull/368>`_]
- Added :meth:`OpenSSL.SSL.Connection.state_string` using the OpenSSL binding ``state_string_long``.
  [`#358 <https://github.com/pyca/pyopenssl/pull/358>`_]
- Added support for the ``socket.MSG_PEEK`` flag to :meth:`OpenSSL.SSL.Connection.recv` and :meth:`OpenSSL.SSL.Connection.recv_into`.
  [`#294 <https://github.com/pyca/pyopenssl/pull/294>`_]
- Added :meth:`OpenSSL.SSL.Connection.get_protocol_version` and :meth:`OpenSSL.SSL.Connection.get_protocol_version_name`.
  [`#244 <https://github.com/pyca/pyopenssl/pull/244>`_]
- Switched to utf8string mask by default.
  OpenSSL formerly defaulted to a T61String if there were UTF-8 characters present.
  This was changed to default to UTF8String in the config around 2005, but the actual code didn't change it until late last year.
  This will default us to the setting that actually works.
  To revert this you can call ``OpenSSL.crypto._lib.ASN1_STRING_set_default_mask_asc(b"default")``.
  [`#234 <https://github.com/pyca/pyopenssl/pull/234>`_]
- Added :func:`OpenSSL.crypto.dump_publickey` to dump :class:`OpenSSL.crypto.PKey` objects that represent public keys.
  [`#382 <https://github.com/pyca/pyopenssl/pull/382>`_]
- Added :func:`OpenSSL.crypto.load_publickey` to load :class:`OpenSSL.crypto.PKey` objects that represent public keys from serialized representations.
  [`#382 <https://github.com/pyca/pyopenssl/pull/382>`_]



Older Changelog Entries
-----------------------

The changes from before release 15.2.0 are preserved in the `repository <https://github.com/pyca/pyopenssl/blob/master/doc/ChangeLog_old.txt>`_.
