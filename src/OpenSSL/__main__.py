from __future__ import print_function

import sys

import OpenSSL.SSL
import cryptography

from . import version


if __name__ != "__main__":
    raise ImportError("This module can't be imported.")

wot = """\
pyOpenSSL: {pyopenssl}
cryptography: {cryptography}
OpenSSL: {openssl}
Python: {python}
Python version: {python_version}
Platform: {platform}
sys.path: {sys_path}""".format(
    pyopenssl=version.__version__,
    openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
    cryptography=cryptography.__version__,
    python=sys.executable,
    python_version=sys.version,
    platform=sys.platform,
    sys_path=sys.path,
)

print(wot)
