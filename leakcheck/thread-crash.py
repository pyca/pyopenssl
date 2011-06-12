# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.
#
# Stress tester for thread-related bugs in ssl_Connection_send and
# ssl_Connection_recv in src/ssl/connection.c for usage of a single
# Connection object simultaneously in multiple threads.  In 0.7 and earlier,
# this will somewhat reliably cause Python to abort with a "tstate mix-up"
# almost immediately, due to the incorrect sharing between threads of the
# `tstate` field of the connection object.


from socket import socket
from threading import Thread

from OpenSSL.SSL import Connection, Context, TLSv1_METHOD

def send(conn):
    while 1:
        for i in xrange(1024 * 32):
            conn.send('x')
        print 'Sent 32KB on', hex(id(conn))


def recv(conn):
    while 1:
        for i in xrange(1024 * 64):
            conn.recv(1)
        print 'Received 64KB on', hex(id(conn))


def main():
    port = socket()
    port.bind(('', 0))
    port.listen(5)

    client = socket()
    client.setblocking(False)
    client.connect_ex(port.getsockname())
    client.setblocking(True)

    server = port.accept()[0]

    clientCtx = Context(TLSv1_METHOD)
    clientCtx.set_cipher_list('ALL:ADH')
    clientCtx.load_tmp_dh('dhparam.pem')

    sslClient = Connection(clientCtx, client)
    sslClient.set_connect_state()

    serverCtx = Context(TLSv1_METHOD)
    serverCtx.set_cipher_list('ALL:ADH')
    serverCtx.load_tmp_dh('dhparam.pem')

    sslServer = Connection(serverCtx, server)
    sslServer.set_accept_state()

    t1 = Thread(target=send, args=(sslClient,))
    t2 = Thread(target=send, args=(sslServer,))
    t3 = Thread(target=recv, args=(sslClient,))
    t4 = Thread(target=recv, args=(sslServer,))

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t1.join()
    t2.join()
    t3.join()
    t4.join()

main()
