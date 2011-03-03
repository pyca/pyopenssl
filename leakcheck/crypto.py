# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

import sys

from OpenSSL.crypto import TYPE_DSA, Error, PKey, X509

class Checker_X509_get_pubkey(object):
    """
    Leak checks for L{X509.get_pubkey}.
    """
    def __init__(self, iterations):
        self.iterations = iterations


    def check_exception(self):
        """
        Call the method repeatedly such that it will raise an exception.
        """
        for i in xrange(self.iterations):
            cert = X509()
            try:
                cert.get_pubkey()
            except Error:
                pass


    def check_success(self):
        """
        Call the method repeatedly such that it will return a PKey object.
        """
        small = xrange(3)
        for i in xrange(self.iterations):
            key = PKey()
            key.generate_key(TYPE_DSA, 256)
            for i in small:
                cert = X509()
                cert.set_pubkey(key)
                for i in small:
                    cert.get_pubkey()


def vmsize():
    return [x for x in file('/proc/self/status').readlines() if 'VmSize' in x]


def main(iterations='1000'):
    iterations = int(iterations)
    for klass in globals():
        if klass.startswith('Checker_'):
            klass = globals()[klass]
            print klass
            checker = klass(iterations)
            for meth in dir(checker):
                if meth.startswith('check_'):
                    print '\t', meth, vmsize(), '...',
                    getattr(checker, meth)()
                    print vmsize()


if __name__ == '__main__':
    main(*sys.argv[1:])
