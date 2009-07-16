# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.SSL}.
"""

from sys import platform
from socket import socket
from os import makedirs, symlink
from os.path import join
from unittest import main

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, PKey, dump_privatekey, load_certificate, load_privatekey
from OpenSSL.SSL import WantReadError, Context, Connection, Error
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD
from OpenSSL.SSL import OP_NO_SSLv2, OP_NO_SSLv3, OP_SINGLE_DH_USE 
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT, VERIFY_CLIENT_ONCE
from OpenSSL.test.util import TestCase
from OpenSSL.test.test_crypto import cleartextCertificatePEM, cleartextPrivateKeyPEM
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
    Establish and return a pair of network sockets connected 
    to each other.
    """
    # Connect a pair of sockets
    port = socket()
    port.bind(('', 0))
    port.listen(1)
    client = socket()
    client.setblocking(False)
    client.connect_ex(port.getsockname())
    server = port.accept()[0]
    server.setblocking(False)

    # Let's pass some unencrypted data to make sure our socket connection is
    # fine.  Just one byte, so we don't have to worry about buffers getting
    # filled up or fragmentation.
    server.send("x")
    assert client.recv(1024) == "x"
    client.send("y")
    assert server.recv(1024) == "y"

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
        cafile = join(capath, 'cert.pem')
        fObj = file(cafile, 'w')
        fObj.write(cleartextCertificatePEM)
        fObj.close()

        # Hash value computed manually with c_rehash to avoid depending on
        # c_rehash in the test suite.
        symlink('cert.pem', join(capath, 'c7adac82.0'))

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
    if platform == "darwin":
        test_set_default_verify_paths.todo = (
            "set_default_verify_paths appears not to work on OS X - a "
            "problem with the supplied OpenSSL, perhaps?")


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



root_cert_pem = """-----BEGIN CERTIFICATE-----
MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
-----END CERTIFICATE-----
"""

root_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD5mkLpi7q6ROdu7khB3S9aanA0Zls7vvfGOmB80/yeylhGpsjA
jWen0VtSQke/NlEPGtO38tsV7CsuFnSmschvAnGrcJl76b0UOOHUgDTIoRxC6QDU
3claegwsrBA+sJEBbqx5RdXbIRGicPG/8qQ4Zm1SKOgotcbwiaor2yxZ2wIDAQAB
AoGBAPCgMpmLxzwDaUmcFbTJUvlLW1hoxNNYSu2jIZm1k/hRAcE60JYwvBkgz3UB
yMEh0AtLxYe0bFk6EHah11tMUPgscbCq73snJ++8koUw+csk22G65hOs51bVb7Aa
6JBe67oLzdtvgCUFAA2qfrKzWRZzAdhUirQUZgySZk+Xq1pBAkEA/kZG0A6roTSM
BVnx7LnPfsycKUsTumorpXiylZJjTi9XtmzxhrYN6wgZlDOOwOLgSQhszGpxVoMD
u3gByT1b2QJBAPtL3mSKdvwRu/+40zaZLwvSJRxaj0mcE4BJOS6Oqs/hS1xRlrNk
PpQ7WJ4yM6ZOLnXzm2mKyxm50Mv64109FtMCQQDOqS2KkjHaLowTGVxwC0DijMfr
I9Lf8sSQk32J5VWCySWf5gGTfEnpmUa41gKTMJIbqZZLucNuDcOtzUaeWZlZAkA8
ttXigLnCqR486JDPTi9ZscoZkZ+w7y6e/hH8t6d5Vjt48JVyfjPIaJY+km58LcN3
6AWSeGAdtRFHVzR7oHjVAkB4hutvxiOeiIVQNBhM6RSI9aBPMI21DoX2JRoxvNW2
cbvAhow217X9V0dVerEOKxnNYspXRrh36h7k4mQA+sDq
-----END RSA PRIVATE KEY-----
"""

server_cert_pem = """-----BEGIN CERTIFICATE-----
MIICKDCCAZGgAwIBAgIJAJn/HpR21r/8MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMH
VGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBMCIYDzIwMDkwMzI1MTIz
NzUzWhgPMjAxNzA2MTExMjM3NTNaMBgxFjAUBgNVBAMTDWxvdmVseSBzZXJ2ZXIw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL6m+G653V0tpBC/OKl22VxOi2Cv
lK4TYu9LHSDP9uDVTe7V5D5Tl6qzFoRRx5pfmnkqT5B+W9byp2NU3FC5hLm5zSAr
b45meUhjEJ/ifkZgbNUjHdBIGP9MAQUHZa5WKdkGIJvGAvs8UzUqlr4TBWQIB24+
lJ+Ukk/CRgasrYwdAgMBAAGjNjA0MB0GA1UdDgQWBBS4kC7Ij0W1TZXZqXQFAM2e
gKEG2DATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQUFAAOBgQBh30Li
dJ+NlxIOx5343WqIBka3UbsOb2kxWrbkVCrvRapCMLCASO4FqiKWM+L0VDBprqIp
2mgpFQ6FHpoIENGvJhdEKpptQ5i7KaGhnDNTfdy3x1+h852G99f1iyj0RmbuFcM8
uzujnS8YXWvM7DM1Ilozk4MzPug8jzFp5uhKCQ==
-----END CERTIFICATE-----
"""

server_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC+pvhuud1dLaQQvzipdtlcTotgr5SuE2LvSx0gz/bg1U3u1eQ+
U5eqsxaEUceaX5p5Kk+QflvW8qdjVNxQuYS5uc0gK2+OZnlIYxCf4n5GYGzVIx3Q
SBj/TAEFB2WuVinZBiCbxgL7PFM1Kpa+EwVkCAduPpSflJJPwkYGrK2MHQIDAQAB
AoGAbwuZ0AR6JveahBaczjfnSpiFHf+mve2UxoQdpyr6ROJ4zg/PLW5K/KXrC48G
j6f3tXMrfKHcpEoZrQWUfYBRCUsGD5DCazEhD8zlxEHahIsqpwA0WWssJA2VOLEN
j6DuV2pCFbw67rfTBkTSo32ahfXxEKev5KswZk0JIzH3ooECQQDgzS9AI89h0gs8
Dt+1m11Rzqo3vZML7ZIyGApUzVan+a7hbc33nbGRkAXjHaUBJO31it/H6dTO+uwX
msWwNG5ZAkEA2RyFKs5xR5USTFaKLWCgpH/ydV96KPOpBND7TKQx62snDenFNNbn
FwwOhpahld+vqhYk+pfuWWUpQciE+Bu7ZQJASjfT4sQv4qbbKK/scePicnDdx9th
4e1EeB9xwb+tXXXUo/6Bor/AcUNwfiQ6Zt9PZOK9sR3lMZSsP7rMi7kzuQJABie6
1sXXjFH7nNJvRG4S39cIxq8YRYTy68II/dlB2QzGpKxV/POCxbJ/zu0CU79tuYK7
NaeNCFfH3aeTrX0LyQJAMBWjWmeKM2G2sCExheeQK0ROnaBC8itCECD4Jsve4nqf
r50+LF74iLXFwqysVCebPKMOpDWp/qQ1BbJQIPs7/A==
-----END RSA PRIVATE KEY-----
"""

client_cert_pem = """-----BEGIN CERTIFICATE-----
MIICJjCCAY+gAwIBAgIJAKxpFI5lODkjMA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMH
VGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBMCIYDzIwMDkwMzI1MTIz
ODA1WhgPMjAxNzA2MTExMjM4MDVaMBYxFDASBgNVBAMTC3VnbHkgY2xpZW50MIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAZh/SRtNm5ntMT4qb6YzEpTroMlq2
rn+GrRHRiZ+xkCw/CGNhbtPir7/QxaUj26BSmQrHw1bGKEbPsWiW7bdXSespl+xK
iku4G/KvnnmWdeJHqsiXeUZtqurMELcPQAw9xPHEuhqqUJvvEoMTsnCEqGM+7Dtb
oCRajYyHfluARQIDAQABozYwNDAdBgNVHQ4EFgQUNQB+qkaOaEVecf1J3TTUtAff
0fAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADgYEAyv/Jh7gM
Q3OHvmsFEEvRI+hsW8y66zK4K5de239Y44iZrFYkt7Q5nBPMEWDj4F2hLYWL/qtI
9Zdr0U4UDCU9SmmGYh4o7R4TZ5pGFvBYvjhHbkSFYFQXZxKUi+WUxplP6I0wr2KJ
PSTJCjJOn3xo2NTKRgV1gaoTf2EhL+RG8TQ=
-----END CERTIFICATE-----
"""

client_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDAZh/SRtNm5ntMT4qb6YzEpTroMlq2rn+GrRHRiZ+xkCw/CGNh
btPir7/QxaUj26BSmQrHw1bGKEbPsWiW7bdXSespl+xKiku4G/KvnnmWdeJHqsiX
eUZtqurMELcPQAw9xPHEuhqqUJvvEoMTsnCEqGM+7DtboCRajYyHfluARQIDAQAB
AoGATkZ+NceY5Glqyl4mD06SdcKfV65814vg2EL7V9t8+/mi9rYL8KztSXGlQWPX
zuHgtRoMl78yQ4ZJYOBVo+nsx8KZNRCEBlE19bamSbQLCeQMenWnpeYyQUZ908gF
h6L9qsFVJepgA9RDgAjyDoS5CaWCdCCPCH2lDkdcqC54SVUCQQDseuduc4wi8h4t
V8AahUn9fn9gYfhoNuM0gdguTA0nPLVWz4hy1yJiWYQe0H7NLNNTmCKiLQaJpAbb
TC6vE8C7AkEA0Ee8CMJUc20BnGEmxwgWcVuqFWaKCo8jTH1X38FlATUsyR3krjW2
dL3yDD9NwHxsYP7nTKp/U8MV7U9IBn4y/wJBAJl7H0/BcLeRmuJk7IqJ7b635iYB
D/9beFUw3MUXmQXZUfyYz39xf6CDZsu1GEdEC5haykeln3Of4M9d/4Kj+FcCQQCY
si6xwT7GzMDkk/ko684AV3KPc/h6G0yGtFIrMg7J3uExpR/VdH2KgwMkZXisSMvw
JJEQjOMCVsEJlRk54WWjAkEAzoZNH6UhDdBK5F38rVt/y4SEHgbSfJHIAmPS32Kq
f6GGcfNpip0Uk7q7udTKuX7Q/buZi/C4YW7u3VKAquv9NA==
-----END RSA PRIVATE KEY-----
"""

def verify_cb(conn, cert, errnum, depth, ok):
    return ok

class MemoryBIOTests(TestCase):
    """
    Tests for L{OpenSSL.SSL.Connection} using a memory BIO.
    """
    def _server(self, sock=None):
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


    def _client(self, sock=None):
        # Now create the client side Connection.  Similar boilerplate to the above.
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


    def test_connect(self):
        """
        Two L{Connection}s which use memory BIOs can be manually connected by
        reading from the output of each and writing those bytes to the input of
        the other and in this way establish a connection and exchange
        application-level bytes with each other.
        """
        server_conn = self._server()
        client_conn = self._client()

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


    def test_socket_connect(self):
        """
        Just like test_connect() but with an actual socket.
        """
        (server, client) = socket_pair()

        # Let the encryption begin...
        client_conn = self._client(client)
        client_conn.set_connect_state()
        server_conn = self._server(server)
        server_conn.set_accept_state()
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
        server = self._server()
        client = self._client()

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
        server = self._server()
        server.bio_shutdown()
        e = self.assertRaises(Error, server.recv, 1024)
        # We don't want WantReadError or ZeroReturnError or anything - it's a
        # handshake failure.
        self.assertEquals(e.__class__, Error)



if __name__ == '__main__':
    main()
