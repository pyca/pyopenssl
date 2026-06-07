import ssl
import sys

import cryptography

import OpenSSL.SSL

from . import version

_env_info = """\
pyOpenSSL: {pyopenssl}
cryptography: {cryptography}
pyOpenSSL's linked OpenSSL: {openssl_link}
Python's OpenSSL: {python_openssl}
Python executable: {python}
Python version: {python_version}
Platform: {platform}
sys.path: {sys_path}""".format(
    pyopenssl=version.__version__,
    openssl_link=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION).decode(
        "ascii"
    ),
    python_openssl=getattr(ssl, "OPENSSL_VERSION", "n/a"),
    cryptography=cryptography.__version__,
    python=sys.executable,
    python_version=sys.version,
    platform=sys.platform,
    sys_path=sys.path,
)


if __name__ == "__main__":
    print(_env_info)
