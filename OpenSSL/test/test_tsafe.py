
"""
Unit tests for :py:obj:`OpenSSL.tsafe`.
"""

from OpenSSL import tsafe
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD
from OpenSSL.SSL import Context
from OpenSSL.test.util import TestCase, bytes, b
from OpenSSL.test.test_ssl import _create_certificate_chain


class ConnectionTest(TestCase):
    """
    Unit tests for :py:obj:`OpenSSL.tsafe.Connection`.
    """

    def test_instantiating_works_under_all_supported_Python_versions(self):
        """
        At least one library (namely `Werkzeug`_) is instantiating
        :py:obj:`Connection` directly which previously did not work under
        Python 3 (Bug #1211834: Python 3 Code Uses "apply" function).

        .. _Werkzeug: http://werkzeug.pocoo.org
        """
        chain = _create_certificate_chain()
        [(_, _), (ikey, icert), (skey, scert)] = chain

        # Create the server context
        ctx = Context(TLSv1_METHOD)
        ctx.use_privatekey(skey)
        ctx.use_certificate(scert)

        # The following line should not throw an error
        socket = tsafe.Connection(ctx, None)
