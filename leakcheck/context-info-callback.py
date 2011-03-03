# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.
#
# Stress tester for thread-related bugs in global_info_callback in
# src/ssl/context.c.  In 0.7 and earlier, this will somewhat reliably
# segfault or abort after a few dozen to a few thousand iterations on an SMP
# machine (generally not on a UP machine) due to uses of Python/C API
# without holding the GIL.

from itertools import count
from threading import Thread
from socket import socket

from OpenSSL.SSL import Context, TLSv1_METHOD, Connection, WantReadError
from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey

cleartextPrivateKeyPEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQDaemNe1syksAbFFpF3aoOrZ18vB/IQNZrAjFqXPv9iieJm7+Tc\n"
    "g+lA/v0qmoEKrpT2xfwxXmvZwBNM4ZhyRC3DPIFEyJV7/3IA1p5iuMY/GJI1VIgn\n"
    "aikQCnrsyxtaRpsMBeZRniaVzcUJ+XnEdFGEjlo+k0xlwfVclDEMwgpXAQIDAQAB\n"
    "AoGBALi0a7pMQqqgnriVAdpBVJveQtxSDVWi2/gZMKVZfzNheuSnv4amhtaKPKJ+\n"
    "CMZtHkcazsE2IFvxRN/kgato9H3gJqq8nq2CkdpdLNVKBoxiCtkLfutdY4SQLtoY\n"
    "USN7exk131pchsAJXYlR6mCW+ZP+E523cNwpPgsyKxVbmXSBAkEA9470fy2W0jFM\n"
    "taZFslpntKSzbvn6JmdtjtvWrM1bBaeeqFiGBuQFYg46VaCUaeRWYw02jmYAsDYh\n"
    "ZQavmXThaQJBAOHtlAQ0IJJEiMZr6vtVPH32fmbthSv1AUSYPzKqdlQrUnOXPQXu\n"
    "z70cFoLG1TvPF5rBxbOkbQ/s8/ka5ZjPfdkCQCeC7YsO36+UpsWnUCBzRXITh4AC\n"
    "7eYLQ/U1KUJTVF/GrQ/5cQrQgftwgecAxi9Qfmk4xqhbp2h4e0QAmS5I9WECQH02\n"
    "0QwrX8nxFeTytr8pFGezj4a4KVCdb2B3CL+p3f70K7RIo9d/7b6frJI6ZL/LHQf2\n"
    "UP4pKRDkgKsVDx7MELECQGm072/Z7vmb03h/uE95IYJOgY4nfmYs0QKA9Is18wUz\n"
    "DpjfE33p0Ha6GO1VZRIQoqE24F8o5oimy3BEjryFuw4=\n"
    "-----END RSA PRIVATE KEY-----\n")


cleartextCertificatePEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICfTCCAeYCAQEwDQYJKoZIhvcNAQEEBQAwgYYxCzAJBgNVBAYTAlVTMRkwFwYD\n"
    "VQQDExBweW9wZW5zc2wuc2YubmV0MREwDwYDVQQHEwhOZXcgWW9yazESMBAGA1UE\n"
    "ChMJUHlPcGVuU1NMMREwDwYDVQQIEwhOZXcgWW9yazEQMA4GCSqGSIb3DQEJARYB\n"
    "IDEQMA4GA1UECxMHVGVzdGluZzAeFw0wODAzMjUxOTA0MTNaFw0wOTAzMjUxOTA0\n"
    "MTNaMIGGMQswCQYDVQQGEwJVUzEZMBcGA1UEAxMQcHlvcGVuc3NsLnNmLm5ldDER\n"
    "MA8GA1UEBxMITmV3IFlvcmsxEjAQBgNVBAoTCVB5T3BlblNTTDERMA8GA1UECBMI\n"
    "TmV3IFlvcmsxEDAOBgkqhkiG9w0BCQEWASAxEDAOBgNVBAsTB1Rlc3RpbmcwgZ8w\n"
    "DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANp6Y17WzKSwBsUWkXdqg6tnXy8H8hA1\n"
    "msCMWpc+/2KJ4mbv5NyD6UD+/SqagQqulPbF/DFea9nAE0zhmHJELcM8gUTIlXv/\n"
    "cgDWnmK4xj8YkjVUiCdqKRAKeuzLG1pGmwwF5lGeJpXNxQn5ecR0UYSOWj6TTGXB\n"
    "9VyUMQzCClcBAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAmm0Vzvv1O91WLl2LnF2P\n"
    "q55LJdOnJbCCXIgxLdoVmvYAz1ZJq1eGKgKWI5QLgxiSzJLEU7KK//aVfiZzoCd5\n"
    "RipBiEEMEV4eAY317bHPwPP+4Bj9t0l8AsDLseC5vLRHgxrLEu3bn08DYx6imB5Q\n"
    "UBj849/xpszEM7BhwKE0GiQ=\n"
    "-----END CERTIFICATE-----\n")

count = count()
def go():
    port = socket()
    port.bind(('', 0))
    port.listen(1)

    called = []
    def info(conn, where, ret):
        print count.next()
        called.append(None)
    context = Context(TLSv1_METHOD)
    context.set_info_callback(info)
    context.use_certificate(
        load_certificate(FILETYPE_PEM, cleartextCertificatePEM))
    context.use_privatekey(
        load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM))

    while 1:
        client = socket()
        client.setblocking(False)
        client.connect_ex(port.getsockname())

        clientSSL = Connection(Context(TLSv1_METHOD), client)
        clientSSL.set_connect_state()

        server, ignored = port.accept()
        server.setblocking(False)

        serverSSL = Connection(context, server)
        serverSSL.set_accept_state()

        del called[:]
        while not called:
            for ssl in clientSSL, serverSSL:
                try:
                    ssl.do_handshake()
                except WantReadError:
                    pass


threads = [Thread(target=go, args=()) for i in xrange(2)]
for th in threads:
    th.start()
for th in threads:
    th.join()
