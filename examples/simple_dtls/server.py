# -*- coding: latin-1 -*-

"""
Simple DTLS echo server, using nonblocking I/O
"""

from __future__ import print_function

import os
import select
import socket
import sys

from OpenSSL import SSL, crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac


SERVER_COOKIE_SECRET = os.urandom(16)


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    sys.stdout.flush()
    return ok


def generate_cookie_cb(conn):
    h = hmac.HMAC(
        SERVER_COOKIE_SECRET,
        hashes.SHA256(),
        backend=default_backend()
    )
    # TODO: fix this, actually use peer info as a digest
    h.update(str(conn))
    return h.finalize()


def verify_cookie_cb(conn, client_cookie):
    return client_cookie == generate_cookie_cb(conn)


if len(sys.argv) < 2:
    print('Usage: python server.py PORT')
    sys.exit(1)

dir = os.path.dirname(sys.argv[0])
if dir == '':
    dir = os.curdir

# Initialize context
ctx = SSL.Context(SSL.DTLS_METHOD)
# ctx = SSL.Context(SSL.DTLSv1_METHOD)
ctx.set_options(SSL.OP_NO_DTLSv1)
ctx.set_options(SSL.OP_COOKIE_EXCHANGE)
ctx.set_cookie_generate_cb(generate_cookie_cb)
ctx.set_cookie_verify_cb(verify_cookie_cb)
ctx.set_verify(
    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb
)  # Demand a certificate
ctx.use_privatekey_file(os.path.join(dir, 'server.pkey'))
ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))

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
    sys.stdout.flush()


PORT = int(sys.argv[1])


while 1:

    # Set up server listen socket
    listenfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listenfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listenfd.setblocking(0)
    listenfd.bind(('', PORT))

    try:
        r, w, _ = select.select(
            [listenfd] + list(clients.keys()), list(writers.keys()), []
        )
    except Exception:
        break

    for cli in r:
        if cli == listenfd:

            # use message peek so the client doesn't have to retransmit another ClientHello
            try:
                _, cli_addr = listenfd.recvfrom(1024, socket.MSG_PEEK)
            except socket.error as err:
                # if err.errno == 10054:
                #     continue
                raise

            print(cli_addr)
            sys.stdout.flush()

            server = SSL.Connection(ctx, listenfd)

            server.connect(cli_addr)

            server.set_accept_state()

            handshake = None
            while handshake is None:
                try:
                    server.do_handshake()
                except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError):
                    # todo check for timeouts here and continue if up, we don't want server
                    # to get stuck in this loop
                    continue
                except (SSL.ZeroReturnError, SSL.Error) as errors:
                    # handshake error
                    handshake = errors
                else:
                    handshake = True
            print('Connection from {}'.format(cli_addr))
            sys.stdout.flush()
            clients[server] = cli_addr
            if isinstance(handshake, Exception):
                dropClient(server, handshake)

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
