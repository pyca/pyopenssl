#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) Jean-Paul Calderone 2008-2015, All rights reserved
#

"""
Installation script for the OpenSSL module.
"""

import codecs
import os
import re
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand


HERE = os.path.abspath(os.path.dirname(__file__))
META_PATH = os.path.join("OpenSSL", "version.py")


def read_file(*parts):
    """
    Build an absolute path from *parts* and and return the contents of the
    resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "ascii") as f:
        return f.read()


META_FILE = read_file(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta),
        META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


<<<<<<< HEAD
class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args or [] +
                            ["OpenSSL"])
        sys.exit(errno)


setup(
    name=find_meta("title"),
    version=find_meta("version"),
    description=find_meta("summary"),
    long_description=read_file("README.rst"),
    author=find_meta("author"),
    author_email=find_meta("email"),
    maintainer="Hynek Schlawack",
    maintainer_email="hs@ox.cx",
    url=find_meta("uri"),
    license=find_meta("license"),
    classifiers=[
=======
# XXX Deduplicate this
__version__ = '0.14'

setup(name='pyOpenSSL', version=__version__,
      packages = ['OpenSSL'],
      package_dir = {'OpenSSL': 'OpenSSL'},
      py_modules  = ['OpenSSL.__init__',
                     'OpenSSL.tsafe',
                     'OpenSSL.rand',
                     'OpenSSL.crypto',
                     'OpenSSL.SSL',
                     'OpenSSL.version',
                     'OpenSSL.test.__init__',
                     'OpenSSL.test.util',
                     'OpenSSL.test.test_crypto',
                     'OpenSSL.test.test_rand',
                     'OpenSSL.test.test_ssl'],
      description = 'Python wrapper module around the OpenSSL library',
      author = 'Jean-Paul Calderone',
      author_email = 'exarkun@twistedmatrix.com',
      maintainer = 'Jean-Paul Calderone',
      maintainer_email = 'exarkun@twistedmatrix.com',
      url = 'https://github.com/pyca/pyopenssl',
      license = 'APL2',
      install_requires=["cryptography>=0.7.2", "six>=1.5.2"],
      long_description = """\
High-level wrapper around a subset of the OpenSSL library, includes
 * SSL.Connection objects, wrapping the methods of Python's portable
   sockets
 * Callbacks written in Python
 * Extensive error-handling mechanism, mirroring OpenSSL's error codes
...  and much more ;)""",
      classifiers = [
>>>>>>> Add support for querying the negotiated TLS version.
        'Development Status :: 6 - Mature',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',

        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
    ],

    packages=['OpenSSL'],
    package_dir={'OpenSSL': 'OpenSSL'},
    py_modules=['OpenSSL.__init__',
                'OpenSSL.tsafe',
                'OpenSSL.rand',
                'OpenSSL.crypto',
                'OpenSSL.SSL',
                'OpenSSL.version',
                'OpenSSL.test.__init__',
                'OpenSSL.test.util',
                'OpenSSL.test.test_crypto',
                'OpenSSL.test.test_rand',
                'OpenSSL.test.test_ssl',
                'OpenSSL.test.test_tsafe',
                'OpenSSL.test.test_util',],
    install_requires=[
        "cryptography>=0.7",
        "six>=1.5.2"
    ],
    test_suite="OpenSSL",
    tests_require=[
        "pytest",
    ],
    cmdclass={
        "test": PyTest,
    }
)
