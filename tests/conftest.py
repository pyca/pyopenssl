# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

from OpenSSL.SSL import (
    Context,
    SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD,
    TLSv1_1_METHOD, TLSv1_2_METHOD)
from tempfile import mktemp

import pytest


def pytest_report_header(config):
    import OpenSSL.SSL
    import cryptography

    return "OpenSSL: {openssl}\ncryptography: {cryptography}".format(
        openssl=OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION),
        cryptography=cryptography.__version__
    )


@pytest.fixture
def tmpfile(tmpdir):
    """
    Return UTF-8-encoded bytes of a path to a tmp file.

    The file will be cleaned up after the test run.
    """
    return mktemp(dir=tmpdir.dirname).encode("utf-8")

def _get_tls_versions():
    versions = [TLSv1_METHOD, SSLv23_METHOD]
    ids = ["TLSv1_METHOD", "SSLv23_METHOD"]
    for (tls_version, name) in [ (SSLv2_METHOD, "SSLv2_METHOD"), 
                                 (SSLv3_METHOD, "SSLv3_METHOD"),
                                 (TLSv1_1_METHOD, "TLSv1_1_METHOD"),
                                 (TLSv1_2_METHOD, "TLSv1_2_METHOD")
                                ]:
        try:
            Context(tls_version)
            versions.append(tls_version)
            ids.append(name)
        except Exception:
            # Some versions of OpenSSL have SSLv2 / TLSv1.1 / TLSv1.2, some
            # don't.  Difficult to say in advance.
            pass
    return versions, ids

def pytest_generate_tests(metafunc):
    if 'tls_version' in metafunc.fixturenames:
        versions, ids = _get_tls_versions()
        metafunc.parametrize("tls_version", versions, ids=ids)
