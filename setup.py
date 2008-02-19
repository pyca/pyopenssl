# vim:fileencoding=UTF-8
#
# setup.py
#
# Copyright (C) AB Strakt 2001, All rights reserved
#
# @(#) $Id: setup.py,v 1.28 2004/08/10 10:59:01 martin Exp $
#
"""
Installation script for the OpenSSL module
"""

from distutils.core import setup, Extension
import os, sys

from version import __version__

# A hack to determine if Extension objects support the depends keyword arg.
try:
    init_func = Extension.__init__.func_code
    has_dep = 'depends' in init_func.co_varnames
except:
    has_dep = 0
if not has_dep:
    # If it doesn't, create a local replacement that removes depends
    # from the kwargs before calling the regular constructor.
    _Extension = Extension
    class Extension(_Extension):
        def __init__(self, name, sources, **kwargs):
            if kwargs.has_key('depends'):
                del kwargs['depends']
            apply(_Extension.__init__, (self, name, sources), kwargs)


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
    Libraries = ['libeay32', 'ssleay32', 'Ws2_32']
else:
    Libraries = ['ssl', 'crypto']

if sys.platform == 'darwin':
    IncludeDirs = ['/sw/include']
    LibraryDirs = ['/sw/lib']

def mkExtension(name):
    import string
    modname = 'OpenSSL.%s' % name
    src = globals()['%s_src' % string.lower(name)]
    dep = globals()['%s_dep' % string.lower(name)]
    return Extension(modname, src, libraries=Libraries, depends=dep,
                     include_dirs=IncludeDirs, library_dirs=LibraryDirs)

setup(name='pyOpenSSL', version=__version__,
      package_dir = { 'OpenSSL': '.' },
      ext_modules = [mkExtension('crypto'), mkExtension('rand'), mkExtension('SSL')],
      py_modules  = ['OpenSSL.__init__', 'OpenSSL.tsafe', 'OpenSSL.version'],
      description = 'Python wrapper module around the OpenSSL library',
      author = 'Martin Sjögren, AB Strakt', author_email = 'msjogren@gmail.com',
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
