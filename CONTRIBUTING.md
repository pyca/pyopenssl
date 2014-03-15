# Contributing

First of all, thank you for your interest in contributing to
pyOpenSSL!

## Filing bug reports

Bug reports are very welcome. Please file them on the Github issue
tracker. Good bug reports come with extensive descriptions of the
error and how to reproduce it. Reporters are strongly encouraged to
include an [SSCCE](http://www.sscce.org/).

## Patches

All patches to pyOpenSSL should be submitted in the form of pull
requests to the main pyOpenSSL repository, `pyca/pyopenssl`. These
pull requests should satisfy the following properties:

- Pull requests that involve code must follow the
  [Twisted Coding Standard][tcs]. For example, `methodNamesLikeThis`,
  three empty lines between module-level elements, and two empty lines
  between class-level elements.
- Pull requests that introduce code must test all new behavior they
  introduce, as well as previously untested or poorly tested behavior
  that they touch.
- Pull requests are not allowed to break existing tests.
- Pull requests that include major changes should note those changes
  in the `ChangeLog` text file in the root of the repository.

Finally, pull requests must be reviewed before merging. This process
is based on [the one from cryptography][cryptography-review]. Everyone
can perform reviews; this is a very valuable way to contribute, and is
highly encouraged.

All members of the pyca Github organization can merge pull requests,
of course keeping in mind all the requirements detailed in this
document as well as the pyca/cryptography merge requirements.

The final responsibility for the reviewing of merged code lies with
the person merging it; since pyOpenSSL is obviously a sensitive
project from a security perspective, so reviewers are strongly
encouraged to take this review and merge process very seriously.

[tcs]: https://twistedmatrix.com/documents/current/core/development/policy/coding-standard.html
"Twisted Coding Standard"
[cryptography-review]: https://cryptography.io/en/latest/development/reviewing-patches/
