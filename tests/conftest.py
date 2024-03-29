# Copyright (c) The pyOpenSSL developers
# See LICENSE for details.

from tempfile import mktemp

import pytest


def pytest_report_header(config):
    import cryptography

    import OpenSSL.SSL

    return (
        f"OpenSSL: {OpenSSL.SSL.SSLeay_version(OpenSSL.SSL.SSLEAY_VERSION)}\n"
        f"cryptography: {cryptography.__version__}"
    )


@pytest.fixture
def tmpfile(tmpdir):
    """
    Return UTF-8-encoded bytes of a path to a tmp file.

    The file will be cleaned up after the test run.
    """
    return mktemp(dir=tmpdir.dirname).encode("utf-8")
