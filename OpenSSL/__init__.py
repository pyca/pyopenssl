#
# __init__.py
#
# Copyright (C) AB Strakt 2001, All rights reserved
#
# $Id: __init__.py,v 1.4 2004/07/22 12:01:25 martin Exp $
#
"""
pyOpenSSL - A simple wrapper around the OpenSSL library
"""

import sys
try:
    orig = sys.getdlopenflags()
except AttributeError:
    pass
else:
    sys.setdlopenflags(2 | 256)
    from OpenSSL import crypto
    sys.setdlopenflags(orig)
del sys, orig

from OpenSSL import rand, crypto, SSL
from OpenSSL.version import __version__

__all__ = [
    'rand', 'crypto', 'SSL', 'tsafe', '__version__']
