# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

"""
Simple echo server, using nonblocking I/O
"""

from __future__ import print_function

import os
import select
import socket
import sys

from OpenSSL import SSL, crypto


PSK_MAP = {
    'pre_shared_key_identity': 'pre_shared_key',
}


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    return ok


def psk_server_cb(conn, client_identity):
    print(client_identity)
    try:
        # PSK identity max length is 128 bytes
        # PSK max length is 256 bytes
        psk = PSK_MAP[client_identity]
    except KeyError:
        # return empty string if client identity is invalid
        # will cause a handshake error
        psk = ''
    return psk


if len(sys.argv) < 2:
    print('Usage: python server.py PORT')
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir

# Initialize context
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.set_options(SSL.OP_NO_SSLv2)
ctx.set_options(SSL.OP_NO_SSLv3)
ctx.use_psk_identity_hint('pre_shared_key_identity_hint')
ctx.set_psk_server_callback(psk_server_cb)
ctx.set_cipher_list('PSK')

# Set up server
server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
server.bind(('', int(sys.argv[1])))
server.listen(3)
server.setblocking(0)

clients = {}
writers = {}


def dropClient(cli, errors=None):
    if errors:
        print('Client %s left unexpectedly:' % (clients[cli],))
        print('  ', errors)
    else:
        print('Client %s left politely' % (clients[cli],))
    del clients[cli]
    if cli in writers:
        del writers[cli]
    if not errors:
        cli.shutdown()
    cli.close()


while 1:
    try:
        r, w, _ = select.select(
            [server] + list(clients.keys()), list(writers.keys()), []
        )
    except Exception:
        break

    for cli in r:
        if cli == server:
            cli, addr = server.accept()
            print('Connection from %s' % (addr,))
            clients[cli] = addr

        else:
            try:
                ret = cli.recv(1024).decode('utf-8')
            except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError):
                pass
            except SSL.ZeroReturnError:
                dropClient(cli)
            except SSL.Error as errors:
                dropClient(cli, errors)
            else:
                if cli not in writers:
                    writers[cli] = ''
                writers[cli] = writers[cli] + ret

    for cli in w:
        try:
            ret = cli.send(writers[cli])
        except (SSL.WantReadError,
                SSL.WantWriteError,
                SSL.WantX509LookupError):
            pass
        except SSL.ZeroReturnError:
            dropClient(cli)
        except SSL.Error as errors:
            dropClient(cli, errors)
        else:
            writers[cli] = writers[cli][ret:]
            if writers[cli] == '':
                del writers[cli]

for cli in clients.keys():
    cli.close()
server.close()
