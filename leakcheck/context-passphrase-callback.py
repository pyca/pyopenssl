# -*- coding: utf-8 -*-

# Copyright 2001 Martin Sjögren and pyOpenSSL contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Stress tester for thread-related bugs in global_passphrase_callback in
src/ssl/context.c.  In 0.7 and earlier, this will somewhat reliably segfault or
abort after a few dozen to a few thousand iterations on an SMP machine
(generally not on a UP machine) due to uses of Python/C API without holding the
GIL.
"""

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
