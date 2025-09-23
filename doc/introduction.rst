.. _intro:

============
Introduction
============


History
=======

pyOpenSSL was originally created by Martin Sjögren because the SSL support in the standard library in Python 2.1 (the contemporary version of Python when the pyOpenSSL project was begun) was severely limited.
Other OpenSSL wrappers for Python at the time were also limited, though in different ways.

Later it was maintained by `Jean-Paul Calderone`_ who among other things managed to make pyOpenSSL a pure Python project which the current maintainers are *very* grateful for.

Over the time the standard library's ``ssl`` module improved, never reaching the completeness of pyOpenSSL's API coverage.
pyOpenSSL remains the only choice for full-featured TLS code in Python versions 3.8+ and PyPy_.


Development
===========

pyOpenSSL is collaboratively developed by the Python Cryptography Authority (PyCA_) that also maintains the low-level bindings called cryptography_.


.. include:: ../CONTRIBUTING.rst


.. _Jean-Paul Calderone: https://github.com/exarkun
.. _PyPy: http://pypy.org
.. _PyCA: https://github.com/pyca
.. _cryptography: https://github.com/pyca/cryptography
