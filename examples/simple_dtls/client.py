# -*- coding: latin-1 -*-

"""
Simple DTLS client, using blocking I/O
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


if len(sys.argv) < 3:
    print('Usage: python client.py HOST PORT')
    sys.exit(1)


dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Initialize context
ctx = SSL.Context(SSL.DTLS_METHOD)
# ctx = SSL.Context(SSL.DTLSv1_METHOD)
ctx.set_options(SSL.OP_NO_DTLSv1)
ctx.set_verify(
    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
)  # Demand a certificate
ctx.use_privatekey_file(os.path.join(dir, 'client.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'client.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

# Set up client
sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
sock.connect((sys.argv[1], int(sys.argv[2])))


print sock._socket.getsockname()
sys.stdout.flush()

# do handshake on connect
# sock.do_handshake()

while 1:
    line = sys.stdin.readline()
    if line == '' or line == '\n':
        break
    try:
        sock.send(line)
        sys.stdout.write(sock.recv(1024).decode('utf-8'))
        sys.stdout.flush()
    except SSL.Error:
        print('Connection died unexpectedly')
        break


sock.shutdown()
sock.close()
