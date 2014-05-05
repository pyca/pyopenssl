# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

import sys

from OpenSSL.crypto import (
    FILETYPE_PEM, TYPE_DSA, Error, PKey, X509, load_privatekey, CRL, Revoked,
    get_elliptic_curves, _X509_REVOKED_dup)

from OpenSSL._util import lib as _lib



class BaseChecker(object):
    def __init__(self, iterations):
        self.iterations = iterations



class Checker_X509_get_pubkey(BaseChecker):
    """
    Leak checks for L{X509.get_pubkey}.
    """
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



class Checker_load_privatekey(BaseChecker):
    """
    Leak checks for :py:obj:`load_privatekey`.
    """
    ENCRYPTED_PEM = """\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: BF-CBC,3763C340F9B5A1D0

a/DO10mLjHLCAOG8/Hc5Lbuh3pfjvcTZiCexShP+tupkp0VxW2YbZjML8uoXrpA6
fSPUo7cEC+r96GjV03ZIVhjmsxxesdWMpfkzXRpG8rUbWEW2KcCJWdSX8bEkuNW3
uvAXdXZwiOrm56ANDo/48gj27GcLwnlA8ld39+ylAzkUJ1tcMVzzTjfcyd6BMFpR
Yjg23ikseug6iWEsZQormdl0ITdYzmFpM+YYsG7kmmmi4UjCEYfb9zFaqJn+WZT2
qXxmo2ZPFzmEVkuB46mf5GCqMwLRN2QTbIZX2+Dljj1Hfo5erf5jROewE/yzcTwO
FCB5K3c2kkTv2KjcCAimjxkE+SBKfHg35W0wB0AWkXpVFO5W/TbHg4tqtkpt/KMn
/MPnSxvYr/vEqYMfW4Y83c45iqK0Cyr2pwY60lcn8Kk=
-----END RSA PRIVATE KEY-----
"""
    def check_load_privatekey_callback(self):
        """
        Call the function with an encrypted PEM and a passphrase callback.
        """
        for i in xrange(self.iterations * 10):
            load_privatekey(
                FILETYPE_PEM, self.ENCRYPTED_PEM, lambda *args: "hello, secret")


    def check_load_privatekey_callback_incorrect(self):
        """
        Call the function with an encrypted PEM and a passphrase callback which
        returns the wrong passphrase.
        """
        for i in xrange(self.iterations * 10):
            try:
                load_privatekey(
                    FILETYPE_PEM, self.ENCRYPTED_PEM,
                    lambda *args: "hello, public")
            except Error:
                pass


    def check_load_privatekey_callback_wrong_type(self):
        """
        Call the function with an encrypted PEM and a passphrase callback which
        returns a non-string.
        """
        for i in xrange(self.iterations * 10):
            try:
                load_privatekey(
                    FILETYPE_PEM, self.ENCRYPTED_PEM,
                    lambda *args: {})
            except ValueError:
                pass



class Checker_CRL(BaseChecker):
    """
    Leak checks for L{CRL.add_revoked} and L{CRL.get_revoked}.
    """
    def check_add_revoked(self):
        """
        Call the add_revoked method repeatedly on an empty CRL.
        """
        for i in xrange(self.iterations * 200):
            CRL().add_revoked(Revoked())


    def check_get_revoked(self):
        """
        Create a CRL object with 100 Revoked objects, then call the
        get_revoked method repeatedly.
        """
        crl = CRL()
        for i in xrange(100):
            crl.add_revoked(Revoked())
        for i in xrange(self.iterations):
            crl.get_revoked()



class Checker_X509_REVOKED_dup(BaseChecker):
    """
    Leak checks for :py:obj:`_X509_REVOKED_dup`.
    """
    def check_X509_REVOKED_dup(self):
        """
        Copy an empty Revoked object repeatedly. The copy is not garbage
        collected, therefore it needs to be manually freed.
        """
        for i in xrange(self.iterations * 100):
            revoked_copy = _X509_REVOKED_dup(Revoked()._revoked)
            _lib.X509_REVOKED_free(revoked_copy)



class Checker_EllipticCurve(BaseChecker):
    """
    Leak checks for :py:obj:`_EllipticCurve`.
    """
    def check_to_EC_KEY(self):
        """
        Repeatedly create an EC_KEY* from an :py:obj:`_EllipticCurve`.  The
        structure should be automatically garbage collected.
        """
        curves = get_elliptic_curves()
        if curves:
            curve = next(iter(curves))
            for i in xrange(self.iterations * 1000):
                curve._to_EC_KEY()


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
