# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.SSL}.
"""

from unittest import TestCase
from tempfile import mktemp
from socket import socket
from os import makedirs, symlink
from os.path import join

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, PKey, dump_privatekey, load_certificate, load_privatekey
from OpenSSL.SSL import WantReadError, Context, Connection, Error
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD
from OpenSSL.SSL import VERIFY_PEER
from OpenSSL.test.test_crypto import _Python23TestCaseHelper, cleartextCertificatePEM, cleartextPrivateKeyPEM
try:
    from OpenSSL.SSL import OP_NO_QUERY_MTU
except ImportError:
    OP_NO_QUERY_MTU = None
try:
    from OpenSSL.SSL import OP_COOKIE_EXCHANGE
except ImportError:
    OP_COOKIE_EXCHANGE = None
try:
    from OpenSSL.SSL import OP_NO_TICKET
except ImportError:
    OP_NO_TICKET = None


class ContextTests(TestCase, _Python23TestCaseHelper):
    """
    Unit tests for L{OpenSSL.SSL.Context}.
    """
    def mktemp(self):
        """
        Pathetic substitute for twisted.trial.unittest.TestCase.mktemp.
        """
        return mktemp(dir=".")


    def test_method(self):
        """
        L{Context} can be instantiated with one of L{SSLv2_METHOD},
        L{SSLv3_METHOD}, L{SSLv23_METHOD}, or L{TLSv1_METHOD}.
        """
        for meth in [SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD]:
            Context(meth)
        self.assertRaises(TypeError, Context, "")
        self.assertRaises(ValueError, Context, 10)


    def test_use_privatekey(self):
        """
        L{Context.use_privatekey} takes an L{OpenSSL.crypto.PKey} instance.
        """
        key = PKey()
        key.generate_key(TYPE_RSA, 128)
        ctx = Context(TLSv1_METHOD)
        ctx.use_privatekey(key)
        self.assertRaises(TypeError, ctx.use_privatekey, "")


    def test_set_passwd_cb(self):
        """
        L{Context.set_passwd_cb} accepts a callable which will be invoked when
        a private key is loaded from an encrypted PEM.
        """
        key = PKey()
        key.generate_key(TYPE_RSA, 128)
        pemFile = self.mktemp()
        fObj = file(pemFile, 'w')
        passphrase = "foobar"
        fObj.write(dump_privatekey(FILETYPE_PEM, key, "blowfish", passphrase))
        fObj.close()

        calledWith = []
        def passphraseCallback(maxlen, verify, extra):
            calledWith.append((maxlen, verify, extra))
            return passphrase
        context = Context(TLSv1_METHOD)
        context.set_passwd_cb(passphraseCallback)
        context.use_privatekey_file(pemFile)
        self.assertTrue(len(calledWith), 1)
        self.assertTrue(isinstance(calledWith[0][0], int))
        self.assertTrue(isinstance(calledWith[0][1], int))
        self.assertEqual(calledWith[0][2], None)


    def test_set_info_callback(self):
        """
        L{Context.set_info_callback} accepts a callable which will be invoked
        when certain information about an SSL connection is available.
        """
        port = socket()
        port.bind(('', 0))
        port.listen(1)

        client = socket()
        client.setblocking(False)
        client.connect_ex(port.getsockname())

        clientSSL = Connection(Context(TLSv1_METHOD), client)
        clientSSL.set_connect_state()

        called = []
        def info(conn, where, ret):
            called.append((conn, where, ret))
        context = Context(TLSv1_METHOD)
        context.set_info_callback(info)
        context.use_certificate(
            load_certificate(FILETYPE_PEM, cleartextCertificatePEM))
        context.use_privatekey(
            load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM))

        server, ignored = port.accept()
        server.setblocking(False)

        serverSSL = Connection(context, server)
        serverSSL.set_accept_state()

        while not called:
            for ssl in clientSSL, serverSSL:
                try:
                    ssl.do_handshake()
                except WantReadError:
                    pass

        # Kind of lame.  Just make sure it got called somehow.
        self.assertTrue(called)


    def _load_verify_locations_test(self, *args):
        port = socket()
        port.bind(('', 0))
        port.listen(1)

        client = socket()
        client.setblocking(False)
        client.connect_ex(port.getsockname())

        clientContext = Context(TLSv1_METHOD)
        clientContext.load_verify_locations(*args)
        # Require that the server certificate verify properly or the
        # connection will fail.
        clientContext.set_verify(
            VERIFY_PEER,
            lambda conn, cert, errno, depth, preverify_ok: preverify_ok)

        clientSSL = Connection(clientContext, client)
        clientSSL.set_connect_state()

        server, _ = port.accept()
        server.setblocking(False)

        serverContext = Context(TLSv1_METHOD)
        serverContext.use_certificate(
            load_certificate(FILETYPE_PEM, cleartextCertificatePEM))
        serverContext.use_privatekey(
            load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM))

        serverSSL = Connection(serverContext, server)
        serverSSL.set_accept_state()

        for i in range(3):
            for ssl in clientSSL, serverSSL:
                try:
                    # Without load_verify_locations above, the handshake
                    # will fail:
                    # Error: [('SSL routines', 'SSL3_GET_SERVER_CERTIFICATE',
                    #          'certificate verify failed')]
                    ssl.do_handshake()
                except WantReadError:
                    pass

        cert = clientSSL.get_peer_certificate()
        self.assertEqual(cert.get_subject().CN, 'pyopenssl.sf.net')

    def test_load_verify_file(self):
        """
        L{Context.load_verify_locations} accepts a file name and uses the
        certificates within for verification purposes.
        """
        cafile = self.mktemp()
        fObj = file(cafile, 'w')
        fObj.write(cleartextCertificatePEM)
        fObj.close()

        self._load_verify_locations_test(cafile)


    def test_load_verify_invalid_file(self):
        """
        L{Context.load_verify_locations} raises L{Error} when passed a
        non-existent cafile.
        """
        clientContext = Context(TLSv1_METHOD)
        self.assertRaises(
            Error, clientContext.load_verify_locations, self.mktemp())


    def test_load_verify_directory(self):
        """
        L{Context.load_verify_locations} accepts a directory name and uses
        the certificates within for verification purposes.
        """
        capath = self.mktemp()
        makedirs(capath)
        cafile = join(capath, 'cert.pem')
        fObj = file(cafile, 'w')
        fObj.write(cleartextCertificatePEM)
        fObj.close()

        # Hash value computed manually with c_rehash to avoid depending on
        # c_rehash in the test suite.
        symlink('cert.pem', join(capath, '07497d9e.0'))

        self._load_verify_locations_test(None, capath)


    def test_set_default_verify_paths(self):
        """
        L{Context.set_default_verify_paths} causes the platform-specific CA
        certificate locations to be used for verification purposes.
        """
        # Testing this requires a server with a certificate signed by one of
        # the CAs in the platform CA location.  Getting one of those costs
        # money.  Fortunately (or unfortunately, depending on your
        # perspective), it's easy to think of a public server on the
        # internet which has such a certificate.  Connecting to the network
        # in a unit test is bad, but it's the only way I can think of to
        # really test this. -exarkun

        # Arg, verisign.com doesn't speak TLSv1
        context = Context(SSLv3_METHOD)
        context.set_default_verify_paths()
        context.set_verify(
            VERIFY_PEER, 
            lambda conn, cert, errno, depth, preverify_ok: preverify_ok)

        client = socket()
        client.connect(('verisign.com', 443))
        clientSSL = Connection(context, client)
        clientSSL.set_connect_state()
        clientSSL.do_handshake()
        clientSSL.send('GET / HTTP/1.0\r\n\r\n')
        self.assertTrue(clientSSL.recv(1024))


    def test_set_default_verify_paths_signature(self):
        """
        L{Context.set_default_verify_paths} takes no arguments and raises
        L{TypeError} if given any.
        """
        context = Context(TLSv1_METHOD)
        self.assertRaises(TypeError, context.set_default_verify_paths, None)
        self.assertRaises(TypeError, context.set_default_verify_paths, 1)
        self.assertRaises(TypeError, context.set_default_verify_paths, "")



class ConstantsTests(TestCase):
    """
    Tests for the values of constants exposed in L{OpenSSL.SSL}.

    These are values defined by OpenSSL intended only to be used as flags to
    OpenSSL APIs.  The only assertions it seems can be made about them is
    their values.
    """
    def test_op_no_query_mtu(self):
        """
        The value of L{OpenSSL.SSL.OP_NO_QUERY_MTU} is 0x1000, the value of
        I{SSL_OP_NO_QUERY_MTU} defined by I{openssl/ssl.h}.
        """
        self.assertEqual(OP_NO_QUERY_MTU, 0x1000)
    if OP_NO_QUERY_MTU is None:
        test_op_no_query_mtu.skip = "OP_NO_QUERY_MTU unavailable - OpenSSL version may be too old"


    def test_op_cookie_exchange(self):
        """
        The value of L{OpenSSL.SSL.OP_COOKIE_EXCHANGE} is 0x2000, the value
        of I{SSL_OP_COOKIE_EXCHANGE} defined by I{openssl/ssl.h}.
        """
        self.assertEqual(OP_COOKIE_EXCHANGE, 0x2000)
    if OP_COOKIE_EXCHANGE is None:
        test_op_cookie_exchange.skip = "OP_COOKIE_EXCHANGE unavailable - OpenSSL version may be too old"


    def test_op_no_ticket(self):
        """
        The value of L{OpenSSL.SSL.OP_NO_TICKET} is 0x4000, the value of
        I{SSL_OP_NO_TICKET} defined by I{openssl/ssl.h}.
        """
        self.assertEqual(OP_NO_TICKET, 0x4000)
    if OP_NO_TICKET is None:
        test_op_no_ticket.skip = "OP_NO_TICKET unavailable - OpenSSL version may be too old"
