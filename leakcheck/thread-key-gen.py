# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.
#
# Stress tester for thread-related bugs in RSA and DSA key generation.  0.12 and
# older held the GIL during these operations.  Subsequent versions release it
# during them.

from threading import Thread

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, PKey

def generate_rsa():
    keys = []
    for i in range(100):
        key = PKey()
        key.generate_key(TYPE_RSA, 1024)
        keys.append(key)

def generate_dsa():
    keys = []
    for i in range(100):
        key = PKey()
        key.generate_key(TYPE_DSA, 512)
        keys.append(key)


def main():
    threads = []
    for i in range(3):
        t = Thread(target=generate_rsa, args=())
        threads.append(t)
        t = Thread(target=generate_dsa, args=())
        threads.append(t)

    for t in threads:
        t.start()

main()
