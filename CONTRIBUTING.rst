Contributing
============

First of all, thank you for your interest in contributing to pyOpenSSL!

Filing bug reports
------------------

Bug reports are very welcome.
Please file them on the Github issue tracker.
Good bug reports come with extensive descriptions of the error and how to reproduce it.
Reporters are strongly encouraged to include an `SSCCE <http://www.sscce.org/>`_.

Patches
-------

All patches to pyOpenSSL should be submitted in the form of pull requests to the main pyOpenSSL repository, ``pyca/pyopenssl``.
These pull requests should satisfy the following properties:

- Code should follow `PEP 8`_, especially in the "do what code around you does" sense.
  One notable way pyOpenSSL code differs, for example, is that there should be three empty lines between   module-level elements, and two empty lines between class-level elements.
  Methods and functions are named in ``snake_case``.
  Follow OpenSSL naming for callables whenever possible is preferred.
- Pull requests that introduce code must test all new behavior they introduce, as well as previously untested or poorly tested behavior that they touch.
- Pull requests are not allowed to break existing tests.
- Pull requests that introduce features or fix bugs should note those changes in the ``ChangeLog`` text file in the root of the repository.
  They should also document the changes, both in docstrings and in the documentation in the ``doc/`` directory.

Finally, pull requests must be reviewed before merging.
This process mirrors the `cryptography code review process`_.
Everyone can perform reviews; this is a very valuable way to contribute, and is highly encouraged.

All members of the pyca Github organization can merge pull requests, of course keeping in mind all the requirements detailed in this document as well as the pyca/cryptography merge requirements.

The final responsibility for the reviewing of merged code lies with the person merging it; since pyOpenSSL is obviously a sensitive project from a security perspective, so reviewers are strongly encouraged to take this review and merge process very seriously.

.. _PEP 8: http://legacy.python.org/dev/peps/pep-0008/
.. _cryptography code review process: https://cryptography.io/en/latest/development/reviewing-patches/
