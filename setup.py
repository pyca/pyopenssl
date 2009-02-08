#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) AB Strakt 2001, All rights reserved
# Copyright (C) Jean-Paul Calderone 2008, All rights reserved
#
# @(#) $Id: setup.py,v 1.28 2004/08/10 10:59:01 martin Exp $
#

"""
Installation script for the OpenSSL module
"""

import sys, os
from distutils.core import Extension, setup

from glob import glob

from version import __version__

crypto_src = ['src/crypto/crypto.c', 'src/crypto/x509.c',
              'src/crypto/x509name.c', 'src/crypto/pkey.c',
              'src/crypto/x509store.c', 'src/crypto/x509req.c',
              'src/crypto/x509ext.c', 'src/crypto/pkcs7.c',
              'src/crypto/pkcs12.c', 'src/crypto/netscape_spki.c',
              'src/util.c']
crypto_dep = ['src/crypto/crypto.h', 'src/crypto/x509.h',
              'src/crypto/x509name.h', 'src/crypto/pkey.h',
              'src/crypto/x509store.h', 'src/crypto/x509req.h',
              'src/crypto/x509ext.h', 'src/crypto/pkcs7.h',
              'src/crypto/pkcs12.h', 'src/crypto/netscape_spki.h',
              'src/util.h']
rand_src = ['src/rand/rand.c', 'src/util.c']
rand_dep = ['src/util.h']
ssl_src = ['src/ssl/connection.c', 'src/ssl/context.c', 'src/ssl/ssl.c',
           'src/util.c']
ssl_dep = ['src/ssl/connection.h', 'src/ssl/context.h', 'src/ssl/ssl.h',
           'src/util.h']

IncludeDirs = None
LibraryDirs = None

# Add more platforms here when needed
if os.name == 'nt' or sys.platform == 'win32':
    Libraries = ['eay32', 'Ws2_32']
    # Try to find it...
    for path in ["C:/Python25/libs/", "C:/Python26/libs/", "C:/OpenSSL/lib/MinGW/"]:
        if os.path.exists(os.path.join(path, "ssleay32.a")):
            ExtraObjects = [os.path.join(path, "ssleay32.a")]
            break
    else:
        raise SystemExit("Cannot find ssleay32.a, aborting")
else:
    Libraries = ['ssl', 'crypto']
    ExtraObjects = []

if sys.platform == 'darwin':
    IncludeDirs = ['/sw/include']
    LibraryDirs = ['/sw/lib']

# Use the SSL_LIB and SSL_INC environment variables to extend
# the library and header directories we pass to the extensions.
ssl_lib = os.environ.get('SSL_LIB', [])
if ssl_lib:
    if LibraryDirs:
        LibraryDirs += [ssl_lib]
    else:
        LibraryDirs = [ssl_lib]
ssl_inc = os.environ.get('SSL_INC', [])
if ssl_inc:
    if IncludeDirs:
        IncludeDirs += [ssl_inc]
    else:
        IncludeDirs = [ssl_inc]

# On Windows, make sure the necessary .dll's get added to the egg.
data_files = []
if sys.platform == 'win32':
    data_files = [("OpenSSL", ExtraObjects)]


def mkExtension(name):
    modname = 'OpenSSL.' + name
    src = globals()[name.lower() + '_src']
    dep = globals()[name.lower() + '_dep']
    return Extension(modname, src, libraries=Libraries, depends=dep,
                     include_dirs=IncludeDirs, library_dirs=LibraryDirs,
                     extra_objects=ExtraObjects)

setup(name='pyOpenSSL', version=__version__,
      package_dir = {'OpenSSL': '.'},
      ext_modules = [mkExtension('crypto'), mkExtension('rand'),
                     mkExtension('SSL')],
      py_modules  = ['OpenSSL.__init__', 'OpenSSL.tsafe',
                     'OpenSSL.version', 'OpenSSL.test.__init__',
                     'OpenSSL.test.test_crypto',
                     'OpenSSL.test.test_ssl'],
      data_files = data_files,
      description = 'Python wrapper module around the OpenSSL library',
      author = 'Martin Sjögren, AB Strakt',
      author_email = 'msjogren@gmail.com',
      maintainer = 'Jean-Paul Calderone',
      maintainer_email = 'exarkun@twistedmatrix.com',
      url = 'http://pyopenssl.sourceforge.net/',
      license = 'LGPL',
      long_description = """\
High-level wrapper around a subset of the OpenSSL library, includes
 * SSL.Connection objects, wrapping the methods of Python's portable
   sockets
 * Callbacks written in Python
 * Extensive error-handling mechanism, mirroring OpenSSL's error codes
...  and much more ;)"""
     )
