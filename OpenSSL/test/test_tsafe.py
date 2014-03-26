# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Unit tests for :py:obj:`OpenSSL.tsafe`.
"""

from OpenSSL.SSL import TLSv1_METHOD, Context
from OpenSSL.tsafe import Connection
from OpenSSL.test.util import TestCase
from OpenSSL.test.test_ssl import _create_certificate_chain


class ConnectionTest(TestCase):
    """
    Tests for :py:obj:`OpenSSL.tsafe.Connection`.
    """
    def test_instantiation(self):
        """
        :py:obj:`OpenSSL.tsafe.Connection` can be instantiated.
        """
        chain = _create_certificate_chain()
        [(_, _), (ikey, icert), (skey, scert)] = chain

        # Create the server context
        ctx = Context(TLSv1_METHOD)
        ctx.use_privatekey(skey)
        ctx.use_certificate(scert)

        # The following line should not throw an error.  This isn't an ideal
        # test.  It would be great to refactor the other Connection tests so
        # they could automatically be applied to this class too.
        Connection(ctx, None)
