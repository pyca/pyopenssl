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

    Libraries = ['Ws2_32']
    def makeTellMeIf(original, what):
        class tellMeIf(original):
            def __init__(*a, **kw):
                Libraries.extend(what)
                return original.__init__(*a, **kw)
        return tellMeIf

    from distutils import cygwinccompiler
    cygwinccompiler.Mingw32CCompiler = makeTellMeIf(cygwinccompiler.Mingw32CCompiler, ['eay32', 'ssl32'])
    from distutils import msvccompiler
    msvccompiler.MSVCCompiler = makeTellMeIf(msvccompiler.MSVCCompiler, ['libeay32', 'ssleay32'])

    import shutil
    shutil.copy("C:\\OpenSSL\\ssleay32.dll", os.path.split(os.path.abspath(__file__))[0])
    shutil.copy("C:\\OpenSSL\\libeay32.dll", os.path.split(os.path.abspath(__file__))[0])
    package_data = {'': ['ssleay32.dll', 'libeay32.dll']}
else:
    Libraries = ['ssl', 'crypto']
    package_data = {}


def mkExtension(name):
    modname = 'OpenSSL.' + name
    src = globals()[name.lower() + '_src']
    dep = globals()[name.lower() + '_dep']
    return Extension(modname, src, libraries=Libraries, depends=dep,
                     include_dirs=IncludeDirs, library_dirs=LibraryDirs)


setup(name='pyOpenSSL', version=__version__,
      packages = ['OpenSSL'],
      package_dir = {'OpenSSL': '.'},
      ext_modules = [mkExtension('crypto'), mkExtension('rand'),
                     mkExtension('SSL')],
      py_modules  = ['OpenSSL.__init__', 'OpenSSL.tsafe',
                     'OpenSSL.version', 'OpenSSL.test.__init__',
                     'OpenSSL.test.util',
                     'OpenSSL.test.test_crypto',
                     'OpenSSL.test.test_rand',
                     'OpenSSL.test.test_ssl'],
      zip_safe = False,
      package_data = package_data,
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
