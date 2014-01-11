# Copyright (C) AB Strakt
# See LICENSE for details.

"""
pyOpenSSL - A simple wrapper around the OpenSSL library
"""

from OpenSSL import rand, crypto, SSL
from OpenSSL.version import __version__

__all__ = [
    'rand', 'crypto', 'SSL', 'tsafe', '__version__']


# ERR_load_crypto_strings, SSL_library_init, ERR_load_SSL_strings
