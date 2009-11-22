# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.SSL}.
"""

from sys import platform
from socket import socket
from os import makedirs
from os.path import join
from unittest import main

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, PKey, dump_privatekey, load_certificate, load_privatekey
from OpenSSL.SSL import WantReadError, Context, ContextType, Connection, ConnectionType, Error
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD
from OpenSSL.SSL import OP_NO_SSLv2, OP_NO_SSLv3, OP_SINGLE_DH_USE
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT, VERIFY_CLIENT_ONCE
from OpenSSL.test.util import TestCase
from OpenSSL.test.test_crypto import cleartextCertificatePEM, cleartextPrivateKeyPEM
from OpenSSL.test.test_crypto import client_cert_pem, client_key_pem, server_cert_pem, server_key_pem, root_cert_pem
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


def socket_pair():
    """
    Establish and return a pair of network sockets connected to each other.
    """
    # Connect a pair of sockets
    port = socket()
    port.bind(('', 0))
    port.listen(1)
    client = socket()
    client.setblocking(False)
    client.connect_ex(("127.0.0.1", port.getsockname()[1]))
    client.setblocking(True)
    server = port.accept()[0]

    # Let's pass some unencrypted data to make sure our socket connection is
    # fine.  Just one byte, so we don't have to worry about buffers getting
    # filled up or fragmentation.
    server.send("x")
    assert client.recv(1024) == "x"
    client.send("y")
    assert server.recv(1024) == "y"

    # All our callers want non-blocking sockets, make it easy for them.
    server.setblocking(False)
    client.setblocking(False)

    return (server, client)



class ContextTests(TestCase):
    """
    Unit tests for L{OpenSSL.SSL.Context}.
    """
    def test_method(self):
        """
        L{Context} can be instantiated with one of L{SSLv2_METHOD},
        L{SSLv3_METHOD}, L{SSLv23_METHOD}, or L{TLSv1_METHOD}.
        """
        for meth in [SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD]:
            Context(meth)
        self.assertRaises(TypeError, Context, "")
        self.assertRaises(ValueError, Context, 10)


    def test_type(self):
        """
        L{Context} and L{ContextType} refer to the same type object and can be
        used to create instances of that type.
        """
        self.assertIdentical(Context, ContextType)
        self.assertConsistentType(Context, 'Context', TLSv1_METHOD)


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
        (server, client) = socket_pair()

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
        (server, client) = socket_pair()

        clientContext = Context(TLSv1_METHOD)
        clientContext.load_verify_locations(*args)
        # Require that the server certificate verify properly or the
        # connection will fail.
        clientContext.set_verify(
            VERIFY_PEER,
            lambda conn, cert, errno, depth, preverify_ok: preverify_ok)

        clientSSL = Connection(clientContext, client)
        clientSSL.set_connect_state()

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
        self.assertEqual(cert.get_subject().CN, 'Testing Root CA')


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
        # Hash value computed manually with c_rehash to avoid depending on
        # c_rehash in the test suite.
        cafile = join(capath, 'c7adac82.0')
        fObj = file(cafile, 'w')
        fObj.write(cleartextCertificatePEM)
        fObj.close()

        self._load_verify_locations_test(None, capath)


    if platform in ("darwin", "win32"):
        "set_default_verify_paths appears not to work on OS X or Windows"
        "See LP#404343 and LP#404344."
    else:
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

    def test_add_extra_chain_cert_invalid_cert(self):
        """
        L{Context.add_extra_chain_cert} raises L{TypeError} if called with
        other than one argument or if called with an object which is not an
        instance of L{X509}.
        """
        context = Context(TLSv1_METHOD)
        self.assertRaises(TypeError, context.add_extra_chain_cert)
        self.assertRaises(TypeError, context.add_extra_chain_cert, object())
        self.assertRaises(TypeError, context.add_extra_chain_cert, object(), object())


    def test_add_extra_chain_cert(self):
        """
        L{Context.add_extra_chain_cert} accepts an L{X509} instance to add to
        the certificate chain.
        """
        context = Context(TLSv1_METHOD)
        context.add_extra_chain_cert(load_certificate(FILETYPE_PEM, cleartextCertificatePEM))
        # XXX Oh no, actually asserting something about its behavior would be really hard.
        # See #477521.



class ConnectionTests(TestCase):
    """
    Unit tests for L{OpenSSL.SSL.Connection}.
    """
    def test_type(self):
        """
        L{Connection} and L{ConnectionType} refer to the same type object and
        can be used to create instances of that type.
        """
        self.assertIdentical(Connection, ConnectionType)
        ctx = Context(TLSv1_METHOD)
        self.assertConsistentType(Connection, 'Connection', ctx, None)


    def test_get_context(self):
        """
        L{Connection.get_context} returns the L{Context} instance used to
        construct the L{Connection} instance.
        """
        context = Context(TLSv1_METHOD)
        connection = Connection(context, None)
        self.assertIdentical(connection.get_context(), context)


    def test_get_context_wrong_args(self):
        """
        L{Connection.get_context} raises L{TypeError} if called with any
        arguments.
        """
        connection = Connection(Context(TLSv1_METHOD), None)
        self.assertRaises(TypeError, connection.get_context, None)



class ErrorTests(TestCase):
    """
    Unit tests for L{OpenSSL.SSL.Error}.
    """
    def test_type(self):
        """
        L{Error} is an exception type.
        """
        self.assertTrue(issubclass(Error, Exception))
        self.assertEqual(Error.__name__, 'Error')



class ConstantsTests(TestCase):
    """
    Tests for the values of constants exposed in L{OpenSSL.SSL}.

    These are values defined by OpenSSL intended only to be used as flags to
    OpenSSL APIs.  The only assertions it seems can be made about them is
    their values.
    """
    # unittest.TestCase has no skip mechanism
    if OP_NO_QUERY_MTU is not None:
        def test_op_no_query_mtu(self):
            """
            The value of L{OpenSSL.SSL.OP_NO_QUERY_MTU} is 0x1000, the value of
            I{SSL_OP_NO_QUERY_MTU} defined by I{openssl/ssl.h}.
            """
            self.assertEqual(OP_NO_QUERY_MTU, 0x1000)
    else:
        "OP_NO_QUERY_MTU unavailable - OpenSSL version may be too old"


    if OP_COOKIE_EXCHANGE is not None:
        def test_op_cookie_exchange(self):
            """
            The value of L{OpenSSL.SSL.OP_COOKIE_EXCHANGE} is 0x2000, the value
            of I{SSL_OP_COOKIE_EXCHANGE} defined by I{openssl/ssl.h}.
            """
            self.assertEqual(OP_COOKIE_EXCHANGE, 0x2000)
    else:
        "OP_COOKIE_EXCHANGE unavailable - OpenSSL version may be too old"


    if OP_NO_TICKET is not None:
        def test_op_no_ticket(self):
            """
            The value of L{OpenSSL.SSL.OP_NO_TICKET} is 0x4000, the value of
            I{SSL_OP_NO_TICKET} defined by I{openssl/ssl.h}.
            """
            self.assertEqual(OP_NO_TICKET, 0x4000)
    else:
        "OP_NO_TICKET unavailable - OpenSSL version may be too old"



def verify_cb(conn, cert, errnum, depth, ok):
    return ok

class MemoryBIOTests(TestCase):
    """
    Tests for L{OpenSSL.SSL.Connection} using a memory BIO.
    """
    def _server(self, sock):
        """
        Create a new server-side SSL L{Connection} object wrapped around
        C{sock}.
        """
        # Create the server side Connection.  This is mostly setup boilerplate
        # - use TLSv1, use a particular certificate, etc.
        server_ctx = Context(TLSv1_METHOD)
        server_ctx.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_SINGLE_DH_USE )
        server_ctx.set_verify(VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT|VERIFY_CLIENT_ONCE, verify_cb)
        server_store = server_ctx.get_cert_store()
        server_ctx.use_privatekey(load_privatekey(FILETYPE_PEM, server_key_pem))
        server_ctx.use_certificate(load_certificate(FILETYPE_PEM, server_cert_pem))
        server_ctx.check_privatekey()
        server_store.add_cert(load_certificate(FILETYPE_PEM, root_cert_pem))
        # Here the Connection is actually created.  If None is passed as the 2nd
        # parameter, it indicates a memory BIO should be created.
        server_conn = Connection(server_ctx, sock)
        server_conn.set_accept_state()
        return server_conn


    def _client(self, sock):
        """
        Create a new client-side SSL L{Connection} object wrapped around
        C{sock}.
        """
        # Now create the client side Connection.  Similar boilerplate to the
        # above.
        client_ctx = Context(TLSv1_METHOD)
        client_ctx.set_options(OP_NO_SSLv2 | OP_NO_SSLv3 | OP_SINGLE_DH_USE )
        client_ctx.set_verify(VERIFY_PEER|VERIFY_FAIL_IF_NO_PEER_CERT|VERIFY_CLIENT_ONCE, verify_cb)
        client_store = client_ctx.get_cert_store()
        client_ctx.use_privatekey(load_privatekey(FILETYPE_PEM, client_key_pem))
        client_ctx.use_certificate(load_certificate(FILETYPE_PEM, client_cert_pem))
        client_ctx.check_privatekey()
        client_store.add_cert(load_certificate(FILETYPE_PEM, root_cert_pem))
        client_conn = Connection(client_ctx, sock)
        client_conn.set_connect_state()
        return client_conn


    def _loopback(self, client_conn, server_conn):
        """
        Try to read application bytes from each of the two L{Connection}
        objects.  Copy bytes back and forth between their send/receive buffers
        for as long as there is anything to copy.  When there is nothing more
        to copy, return C{None}.  If one of them actually manages to deliver
        some application bytes, return a two-tuple of the connection from which
        the bytes were read and the bytes themselves.
        """
        wrote = True
        while wrote:
            # Loop until neither side has anything to say
            wrote = False

            # Copy stuff from each side's send buffer to the other side's
            # receive buffer.
            for (read, write) in [(client_conn, server_conn),
                                  (server_conn, client_conn)]:

                # Give the side a chance to generate some more bytes, or
                # succeed.
                try:
                    bytes = read.recv(2 ** 16)
                except WantReadError:
                    # It didn't succeed, so we'll hope it generated some
                    # output.
                    pass
                else:
                    # It did succeed, so we'll stop now and let the caller deal
                    # with it.
                    return (read, bytes)

                while True:
                    # Keep copying as long as there's more stuff there.
                    try:
                        dirty = read.bio_read(4096)
                    except WantReadError:
                        # Okay, nothing more waiting to be sent.  Stop
                        # processing this send buffer.
                        break
                    else:
                        # Keep track of the fact that someone generated some
                        # output.
                        wrote = True
                        write.bio_write(dirty)


    def test_memoryConnect(self):
        """
        Two L{Connection}s which use memory BIOs can be manually connected by
        reading from the output of each and writing those bytes to the input of
        the other and in this way establish a connection and exchange
        application-level bytes with each other.
        """
        server_conn = self._server(None)
        client_conn = self._client(None)

        # There should be no key or nonces yet.
        self.assertIdentical(server_conn.master_key(), None)
        self.assertIdentical(server_conn.client_random(), None)
        self.assertIdentical(server_conn.server_random(), None)

        # First, the handshake needs to happen.  We'll deliver bytes back and
        # forth between the client and server until neither of them feels like
        # speaking any more.
        self.assertIdentical(self._loopback(client_conn, server_conn), None)

        # Now that the handshake is done, there should be a key and nonces.
        self.assertNotIdentical(server_conn.master_key(), None)
        self.assertNotIdentical(server_conn.client_random(), None)
        self.assertNotIdentical(server_conn.server_random(), None)
        self.assertEquals(server_conn.client_random(), client_conn.client_random())
        self.assertEquals(server_conn.server_random(), client_conn.server_random())
        self.assertNotEquals(server_conn.client_random(), server_conn.server_random())
        self.assertNotEquals(client_conn.client_random(), client_conn.server_random())

        # Here are the bytes we'll try to send.
        important_message = 'One if by land, two if by sea.'

        server_conn.write(important_message)
        self.assertEquals(
            self._loopback(client_conn, server_conn),
            (client_conn, important_message))

        client_conn.write(important_message[::-1])
        self.assertEquals(
            self._loopback(client_conn, server_conn),
            (server_conn, important_message[::-1]))


    def test_socketConnect(self):
        """
        Just like L{test_memoryConnect} but with an actual socket.

        This is primarily to rule out the memory BIO code as the source of
        any problems encountered while passing data over a L{Connection} (if
        this test fails, there must be a problem outside the memory BIO
        code, as no memory BIO is involved here).  Even though this isn't a
        memory BIO test, it's convenient to have it here.
        """
        (server, client) = socket_pair()

        # Let the encryption begin...
        client_conn = self._client(client)
        server_conn = self._server(server)

        # Establish the connection
        established = False
        while not established:
            established = True  # assume the best
            for ssl in client_conn, server_conn:
                try:
                    # Generally a recv() or send() could also work instead
                    # of do_handshake(), and we would stop on the first
                    # non-exception.
                    ssl.do_handshake()
                except WantReadError:
                    established = False

        important_message = "Help me Obi Wan Kenobi, you're my only hope."
        client_conn.send(important_message)
        msg = server_conn.recv(1024)
        self.assertEqual(msg, important_message)

        # Again in the other direction, just for fun.
        important_message = important_message[::-1]
        server_conn.send(important_message)
        msg = client_conn.recv(1024)
        self.assertEqual(msg, important_message)


    def test_socketOverridesMemory(self):
        """
        Test that L{OpenSSL.SSL.bio_read} and L{OpenSSL.SSL.bio_write} don't
        work on L{OpenSSL.SSL.Connection}() that use sockets.
        """
        context = Context(SSLv3_METHOD)
        client = socket()
        clientSSL = Connection(context, client)
        self.assertRaises( TypeError, clientSSL.bio_read, 100)
        self.assertRaises( TypeError, clientSSL.bio_write, "foo")
        self.assertRaises( TypeError, clientSSL.bio_shutdown )


    def test_outgoingOverflow(self):
        """
        If more bytes than can be written to the memory BIO are passed to
        L{Connection.send} at once, the number of bytes which were written is
        returned and that many bytes from the beginning of the input can be
        read from the other end of the connection.
        """
        server = self._server(None)
        client = self._client(None)

        self._loopback(client, server)

        size = 2 ** 15
        sent = client.send("x" * size)
        # Sanity check.  We're trying to test what happens when the entire
        # input can't be sent.  If the entire input was sent, this test is
        # meaningless.
        self.assertTrue(sent < size)

        receiver, received = self._loopback(client, server)
        self.assertIdentical(receiver, server)

        # We can rely on all of these bytes being received at once because
        # _loopback passes 2 ** 16 to recv - more than 2 ** 15.
        self.assertEquals(len(received), sent)


    def test_shutdown(self):
        """
        L{Connection.bio_shutdown} signals the end of the data stream from
        which the L{Connection} reads.
        """
        server = self._server(None)
        server.bio_shutdown()
        e = self.assertRaises(Error, server.recv, 1024)
        # We don't want WantReadError or ZeroReturnError or anything - it's a
        # handshake failure.
        self.assertEquals(e.__class__, Error)


    def _check_client_ca_list(self, func):
        """
        Verify the return value of the C{get_client_ca_list} method for server and client connections.

        @param func: A function which will be called with the server context
            before the client and server are connected to each other.  This
            function should specify a list of CAs for the server to send to the
            client and return that same list.  The list will be used to verify
            that C{get_client_ca_list} returns the proper value at various
            times.
        """
        server = self._server(None)
        client = self._client(None)
        self.assertEqual(client.get_client_ca_list(), [])
        self.assertEqual(server.get_client_ca_list(), [])
        ctx = server.get_context()
        expected = func(ctx)
        self.assertEqual(client.get_client_ca_list(), [])
        self.assertEqual(server.get_client_ca_list(), expected)
        self._loopback(client, server)
        self.assertEqual(client.get_client_ca_list(), expected)
        self.assertEqual(server.get_client_ca_list(), expected)


    def test_set_client_ca_list_errors(self):
        """
        L{Context.set_client_ca_list} raises a L{TypeError} if called with a
        non-list or a list that contains objects other than X509Names.
        """
        ctx = Context(TLSv1_METHOD)
        self.assertRaises(TypeError, ctx.set_client_ca_list, "spam")
        self.assertRaises(TypeError, ctx.set_client_ca_list, ["spam"])
        self.assertIdentical(ctx.set_client_ca_list([]), None)


    def test_set_empty_ca_list(self):
        """
        If passed an empty list, L{Context.set_client_ca_list} configures the
        context to send no CA names to the client and, on both the server and
        client sides, L{Connection.get_client_ca_list} returns an empty list
        after the connection is set up.
        """
        def no_ca(ctx):
            ctx.set_client_ca_list([])
            return []
        self._check_client_ca_list(no_ca)


    def test_set_one_ca_list(self):
        """
        If passed a list containing a single X509Name,
        L{Context.set_client_ca_list} configures the context to send that CA
        name to the client and, on both the server and client sides,
        L{Connection.get_client_ca_list} returns a list containing that
        X509Name after the connection is set up.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        cadesc = cacert.get_subject()
        def single_ca(ctx):
            ctx.set_client_ca_list([cadesc])
            return [cadesc]
        self._check_client_ca_list(single_ca)


    def test_set_multiple_ca_list(self):
        """
        If passed a list containing multiple X509Name objects,
        L{Context.set_client_ca_list} configures the context to send those CA
        names to the client and, on both the server and client sides,
        L{Connection.get_client_ca_list} returns a list containing those
        X509Names after the connection is set up.
        """
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)
        clcert = load_certificate(FILETYPE_PEM, server_cert_pem)

        sedesc = secert.get_subject()
        cldesc = clcert.get_subject()

        def multiple_ca(ctx):
            L = [sedesc, cldesc]
            ctx.set_client_ca_list(L)
            return L
        self._check_client_ca_list(multiple_ca)


    def test_reset_ca_list(self):
        """
        If called multiple times, only the X509Names passed to the final call
        of L{Context.set_client_ca_list} are used to configure the CA names
        sent to the client.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)
        clcert = load_certificate(FILETYPE_PEM, server_cert_pem)

        cadesc = cacert.get_subject()
        sedesc = secert.get_subject()
        cldesc = clcert.get_subject()

        def changed_ca(ctx):
            ctx.set_client_ca_list([sedesc, cldesc])
            ctx.set_client_ca_list([cadesc])
            return [cadesc]
        self._check_client_ca_list(changed_ca)


    def test_mutated_ca_list(self):
        """
        If the list passed to L{Context.set_client_ca_list} is mutated
        afterwards, this does not affect the list of CA names sent to the
        client.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)

        cadesc = cacert.get_subject()
        sedesc = secert.get_subject()

        def mutated_ca(ctx):
            L = [cadesc]
            ctx.set_client_ca_list([cadesc])
            L.append(sedesc)
            return [cadesc]
        self._check_client_ca_list(mutated_ca)


    def test_add_client_ca_errors(self):
        """
        L{Context.add_client_ca} raises L{TypeError} if called with a non-X509
        object or with a number of arguments other than one.
        """
        ctx = Context(TLSv1_METHOD)
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        self.assertRaises(TypeError, ctx.add_client_ca)
        self.assertRaises(TypeError, ctx.add_client_ca, "spam")
        self.assertRaises(TypeError, ctx.add_client_ca, cacert, cacert)


    def test_one_add_client_ca(self):
        """
        A certificate's subject can be added as a CA to be sent to the client
        with L{Context.add_client_ca}.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        cadesc = cacert.get_subject()
        def single_ca(ctx):
            ctx.add_client_ca(cacert)
            return [cadesc]
        self._check_client_ca_list(single_ca)


    def test_multiple_add_client_ca(self):
        """
        Multiple CA names can be sent to the client by calling
        L{Context.add_client_ca} with multiple X509 objects.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)

        cadesc = cacert.get_subject()
        sedesc = secert.get_subject()

        def multiple_ca(ctx):
            ctx.add_client_ca(cacert)
            ctx.add_client_ca(secert)
            return [cadesc, sedesc]
        self._check_client_ca_list(multiple_ca)


    def test_set_and_add_client_ca(self):
        """
        A call to L{Context.set_client_ca_list} followed by a call to
        L{Context.add_client_ca} results in using the CA names from the first
        call and the CA name from the second call.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)
        clcert = load_certificate(FILETYPE_PEM, server_cert_pem)

        cadesc = cacert.get_subject()
        sedesc = secert.get_subject()
        cldesc = clcert.get_subject()

        def mixed_set_add_ca(ctx):
            ctx.set_client_ca_list([cadesc, sedesc])
            ctx.add_client_ca(clcert)
            return [cadesc, sedesc, cldesc]
        self._check_client_ca_list(mixed_set_add_ca)


    def test_set_after_add_client_ca(self):
        """
        A call to L{Context.set_client_ca_list} after a call to
        L{Context.add_client_ca} replaces the CA name specified by the former
        call with the names specified by the latter cal.
        """
        cacert = load_certificate(FILETYPE_PEM, root_cert_pem)
        secert = load_certificate(FILETYPE_PEM, server_cert_pem)
        clcert = load_certificate(FILETYPE_PEM, server_cert_pem)

        cadesc = cacert.get_subject()
        sedesc = secert.get_subject()
        cldesc = clcert.get_subject()

        def set_replaces_add_ca(ctx):
            ctx.add_client_ca(clcert)
            ctx.set_client_ca_list([cadesc])
            ctx.add_client_ca(secert)
            return [cadesc, sedesc]
        self._check_client_ca_list(set_replaces_add_ca)



if __name__ == '__main__':
    main()
