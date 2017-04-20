from __future__ import print_function

import OpenSSL.SSL
import cryptography

from . import version


if __name__ != "__main__":
    raise ImportError("This module can't be imported.")

print(
    "pyOpenSSL: {pyopenssl}\n"
    "OpenSSL: {openssl}\n"
    "cryptography: {cryptography}"
    .format(
        pyopenssl=version.__version__,
        openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
        cryptography=cryptography.__version__
    )
)
