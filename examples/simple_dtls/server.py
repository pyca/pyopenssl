# -*- coding: latin-1 -*-

"""
Simple DTLS echo server, using blocking I/O
"""

import os
import socket
import sys

from OpenSSL import SSL, crypto


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    sys.stdout.flush()
    return ok


if len(sys.argv) < 2:
    print('Usage: python server.py PORT')
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir

port = int(sys.argv[1])

# Initialize context
ctx = SSL.Context(SSL.DTLS_METHOD)
ctx.set_options(SSL.OP_NO_DTLSv1)
ctx.set_verify(
    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
)  # Demand a certificate
ctx.use_privatekey_file(os.path.join(dir, 'server.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

while True:

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(('', port))

    cli = None
    while cli is None:
        # wait until a client is available
        _, cli = server.recvfrom(1024)

    cli_conn = SSL.Connection(ctx, server)

    print('Connected', cli)
    sys.stdout.flush()

    cli_conn.connect(cli)

    cli_conn.set_accept_state()

    cli_conn.do_handshake()

    while True:
        try:
            ret = cli_conn.recv(1024).decode('utf-8')
        except SSL.ZeroReturnError:
            break
        try:
            cli_conn.send(ret)
        except SSL.ZeroReturnError:
            break

    cli_conn.shutdown()
    cli_conn.close()
    print('Disconnected', cli)
    sys.stdout.flush()


server.shutdown()
server.close()
