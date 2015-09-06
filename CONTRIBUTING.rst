Contributing
============

First of all, thank you for your interest in contributing to pyOpenSSL!
This project has no company backing its development therefore we're dependent on help by the community.


Filing bug reports
------------------

Bug reports are very welcome.
Please file them on the `GitHub issue tracker`_.
Good bug reports come with extensive descriptions of the error and how to reproduce it.
Reporters are strongly encouraged to include an `short, self contained, correct example <http://www.sscce.org/>`_.


Security
--------

If you feel that you found a security-relevant bug that you would prefer to discuss in private, please send us a GPG_-encrypted e-mail.

The maintainer can be reached at hs@ox.cx and his GPG key ID is ``0xAE2536227F69F181`` (Fingerprint: ``C2A0 4F86 ACE2 8ADC F817  DBB7 AE25 3622 7F69 F181``).
Feel free to cross-check this information with Keybase_.


Patches
-------

All patches to pyOpenSSL should be submitted in the form of pull requests to the main pyOpenSSL repository, `pyca/pyopenssl`_.
These pull requests should satisfy the following properties:

- The pull request should focus on one particular improvement to pyOpenSSL.
  Create different pull requests for unrelated features or bugfixes.
- Code should follow `PEP 8`_, especially in the "do what code around you does" sense.
  Follow OpenSSL naming for callables whenever possible is preferred.
- New tests should use `py.test-style assertions`_ instead of the old `self.assertXYZ`-style.
- Pull requests that introduce code must test all new behavior they introduce as well as for previously untested or poorly tested behavior that they touch.
- Pull requests are not allowed to break existing tests.
  We usually don't comment on pull requests that are breaking the CI because we consider them work in progress.
  Please note that not having 100% code coverage for the code you wrote/touched also causes our CI to fail.
- Pull requests that introduce features or fix bugs should note those changes in the ``ChangeLog`` text file in the root of the repository.
  They should also document the changes, both in docstrings and in the documentation in the ``doc/`` directory.

Finally, pull requests must be reviewed before merging.
This process mirrors the `cryptography code review process`_.
Everyone can perform reviews; this is a very valuable way to contribute, and is highly encouraged.

Pull requests are merged by `members of PyCA`_.
They should, of course, keep all the requirements detailed in this document as well as the ``pyca/cryptography`` merge requirements in mind.

The final responsibility for the reviewing of merged code lies with the person merging it.
Since pyOpenSSL is a sensitive project from a security perspective, reviewers are strongly encouraged to take this review and merge process very seriously.


Finding Help
------------

If you need any help with the contribution process, you'll find us hanging out at ``#cryptography-dev`` on Freenode_ IRC.
You can also ask questions on our `mailing list`_.

Wherever we interact, we strive to follow the `Python Community Code of Conduct`_.


.. _GitHub issue tracker: https://github.com/pyca/pyopenssl/issues
.. _GPG: http://en.wikipedia.org/wiki/GNU_Privacy_Guard
.. _Keybase: https://keybase.io/hynek
.. _pyca/pyopenssl: https://github.com/pyca/pyopenssl
.. _PEP 8: https://www.python.org/dev/peps/pep-0008/
.. _py.test-style assertions: https://pytest.org/latest/assert.html
.. _cryptography code review process: https://cryptography.io/en/latest/development/reviewing-patches/
.. _freenode: https://freenode.net
.. _mailing list: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _Python Community Code of Conduct: https://www.python.org/psf/codeofconduct/
.. _members of PyCA: https://github.com/orgs/pyca/people
