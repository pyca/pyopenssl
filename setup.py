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

import distutils.log
distutils.log.set_verbosity(3)

import sys, os
from distutils.core import Extension, setup
from distutils.errors import DistutilsFileError
from distutils.command.build_ext import build_ext

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



    class BuildExtension(build_ext):
        """
        A custom command that semiautomatically finds dependencies required by
        PyOpenSSL.
        """

        user_options = (build_ext.user_options +
                        [("with-openssl=", None,
                          "directory where OpenSSL is installed")])
        with_openssl = None
        openssl_dlls = ()
        openssl_mingw = False


        def finalize_options(self):
            """
            Update build options with details about OpenSSL.
            """
            build_ext.finalize_options(self)
            if self.with_openssl is None:
                self.find_openssl()
            self.find_openssl_dlls()
            self.add_openssl_compile_info()


        def find_openssl(self):
            """
            Find OpenSSL's install directory.
            """
            potentials = []
            dirs = os.environ.get("PATH").split(os.pathsep)
            for d in dirs:
                if os.path.exists(os.path.join(d, "openssl.exe")):
                    ssldir, bin = os.path.split(d)
                    if not bin:
                        ssldir, bin = os.path.split(ssldir)
                    potentials.append(ssldir)
                    childdirs = os.listdir(ssldir)
                    if "lib" in childdirs and "include" in childdirs:
                        self.with_openssl = ssldir
                        return
            if potentials:
                raise DistutilsFileError(
                    "Only found improper OpenSSL directories: %r" % (
                        potentials,))
            else:
                raise DistutilsFileError("Could not find 'openssl.exe'")


        def find_openssl_dlls(self):
            """
            Find OpenSSL's shared libraries.
            """
            self.openssl_dlls = []
            self.find_openssl_dll("libssl32.dll", False)
            if self.openssl_dlls:
                self.openssl_mingw = True
            else:
                self.find_openssl_dll("ssleay32.dll", True)
            self.find_openssl_dll("libeay32.dll", True)
            # add zlib to the mix if it looks like OpenSSL
            # was linked with a private copy of it
            self.find_openssl_dll("zlib1.dll", False)


        def find_openssl_dll(self, name, required):
            """
            Find OpenSSL's shared library and its path after installation.
            """
            dllpath = os.path.join(self.with_openssl, "bin", name)
            if not os.path.exists(dllpath):
                if required:
                    raise DistutilsFileError("could not find '%s'" % name)
                else:
                    return
            newpath = os.path.join(self.build_lib, "OpenSSL", name)
            self.openssl_dlls.append((dllpath, newpath))


        def add_openssl_compile_info(self):
            """
            Set up various compile and link parameters.
            """
            if self.compiler == "mingw32":
                if self.openssl_mingw:
                    # Library path and library names are sane when OpenSSL is
                    # built with MinGW .
                    libdir = "lib"
                    libs = ["eay32", "ssl32"]
                else:
                    libdir = ""
                    libs = []
                    # Unlike when using the binary installer, which creates
                    # an atypical shared library name 'ssleay32', so we have
                    # to use this workaround.
                    if self.link_objects is None:
                        self.link_objects = []
                    for dllpath, _ in self.openssl_dlls:
                        dllname = os.path.basename(dllpath)
                        libname = os.path.splitext(dllname)[0] + ".a"
                        libpath = os.path.join(self.with_openssl,
                                               "lib", "MinGW", libname)
                        self.link_objects.append(libpath)
            else:
                libdir = "lib"
                libs = ["libeay32", "ssleay32"]
            self.include_dirs.append(os.path.join(self.with_openssl, "include"))
            self.library_dirs.append(os.path.join(self.with_openssl, libdir))
            self.libraries.extend(libs)


        def run(self):
            """
            Build extension modules and copy shared libraries.
            """
            build_ext.run(self)
            for dllpath, newpath in self.openssl_dlls:
                self.copy_file(dllpath, newpath)


        def get_outputs(self):
            """
            Return a list of file paths built by this comand.
            """
            output = [pathpair[1] for pathpair in self.openssl_dlls]
            output.extend(build_ext.get_outputs(self))
            return output



else:
    Libraries = ['ssl', 'crypto']
    BuildExtension = build_ext



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
      cmdclass = {"build_ext": BuildExtension},
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
