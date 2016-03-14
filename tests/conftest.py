# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.


def pytest_report_header(config):
    import OpenSSL.SSL
    import cryptography

    return "OpenSSL: {openssl}\ncryptography: {cryptography}".format(
        openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
        cryptography=cryptography.__version__
    )
