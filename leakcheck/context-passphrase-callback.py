# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.
#
# Stress tester for thread-related bugs in global_passphrase_callback in
# src/ssl/context.c.  In 0.7 and earlier, this will somewhat reliably
# segfault or abort after a few dozen to a few thousand iterations on an SMP
# machine (generally not on a UP machine) due to uses of Python/C API
# without holding the GIL.

from itertools import count
from threading import Thread

from OpenSSL.SSL import Context, TLSv1_METHOD
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, PKey, dump_privatekey

k = PKey()
k.generate_key(TYPE_RSA, 128)
file('pkey.pem', 'w').write(dump_privatekey(FILETYPE_PEM, k, "blowfish", "foobar"))

count = count()
def go():
    def cb(a, b, c):
        print count.next()
        return "foobar"
    c = Context(TLSv1_METHOD)
    c.set_passwd_cb(cb)
    while 1:
        c.use_privatekey_file('pkey.pem')

threads = [Thread(target=go, args=()) for i in xrange(2)]
for th in threads:
    th.start()
for th in threads:
    th.join()
