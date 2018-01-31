# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Simple SSL client, using blocking I/O
"""

import os
import socket
import sys

from OpenSSL import SSL, crypto


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    return ok


def psk_client_cb(conn, identity_hint):
    print(identity_hint)
    return ('pre_shared_key_identity', 'pre_shared_key')


if len(sys.argv) < 3:
    print('Usage: python client.py HOST PORT')
    sys.exit(1)


dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir


# Initialize context
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_options(SSL.OP_NO_SSLv2)
ctx.set_options(SSL.OP_NO_SSLv3)
ctx.set_psk_client_callback(psk_client_cb)
ctx.set_cipher_list('PSK')

# Set up client
sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect((sys.argv[1], int(sys.argv[2])))

while 1:
    line = sys.stdin.readline()
    if line == '':
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
