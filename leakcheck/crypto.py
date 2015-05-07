# Copyright (C) Jean-Paul Calderone
# See LICENSE for details.

import sys

from OpenSSL.crypto import (
    FILETYPE_PEM, TYPE_DSA, Error, PKey, X509, load_privatekey, CRL, Revoked,
    get_elliptic_curves, _X509_REVOKED_dup, load_certificate)

from OpenSSL._util import lib as _lib



class BaseChecker(object):
    def __init__(self, iterations):
        self.iterations = iterations

class Checker_AltSubjectNameExt(BaseChecker):
    """
    Leak check for X509Extention. member function _subjectAltNameString()
    """
    ALTSUBJ_X509 = \
"""-----BEGIN CERTIFICATE-----
MIIISzCCBzOgAwIBAgIQCiuGDMoB9F/X7mNgGxw+gzANBgkqhkiG9w0BAQsFADB1
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE0MDMyMDAwMDAwMFoXDTE2MDYxMjEy
MDAwMFowggELMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysG
AQQBgjc8AgEDEwJVUzEVMBMGCysGAQQBgjc8AgECEwRVdGFoMRUwEwYDVQQFEww1
Mjk5NTM3LTAxNDIxEjAQBgNVBAkTCVN1aXRlIDUwMDEkMCIGA1UECRMbMjYwMCBX
ZXN0IEV4ZWN1dGl2ZSBQYXJrd2F5MQ4wDAYDVQQREwU4NDA0MzELMAkGA1UEBhMC
VVMxDTALBgNVBAgTBFV0YWgxDTALBgNVBAcTBExlaGkxFzAVBgNVBAoTDkRpZ2lD
ZXJ0LCBJbmMuMRkwFwYDVQQDExB3d3cuZGlnaWNlcnQuY29tMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAqImzO5GUV4dyCVtfyyxCKp7twv0geyxjf90H
v/tJXO0conB5dcI0zOsS8ECIOrnqKaIRj1PhAuGHBPZYuYa2f4VeClhHw73nayEH
ndvvV4sWzjjx4+LkWhC4ObsKrcrFEIU6oW9nyRjDW7JMpgG2w1C+fsh5yjxTXgJ4
rpZfViGzpDw//knFF3Olbqlgqr0WBFb6VNLLJcDpn4nJ7hCHAfLHky3DL57QnEIk
nQkk9oDE6DSZWi4mw3MoUiasCTSOxXDh9fuTuDQtRPRQH4YKm2RFJgXURcpyA90e
gBqcUwZ7yDYxA9pfVcQNKcBSnCOVjalVlcQRAlujG+55sm5Kak1KRD45nosN7DiT
XlyzT1OPTip4sVJUS/tqlDVhAwZ56AacjoFbazbfwP5DztUWGfaClOiAAOGEFB0o
c4vpurZV56YXjK5wFb4E78gIJ9nfOn5njAYNUZQFlS8n5MHUpF7KlhOJ0gWLQ2j8
MYeptvLDR+Pf2RkTT7kFqYqYA8rFkinjc+dL6AraG5zbaFBmlSvc6DkbFPpB0/za
5o0ELIHREkfGJ53XVL1P7kIgllKmg59ZBWsrGEF6WruJG0WCim57lHjgTgnrHKja
2bRW1KB9CNXylIEuobQKFFYhJsPEJ0g8UNVxRTVLNyJ7aSZs27hO8vGi+Gv7Gq7m
61seFdUCAwEAAaOCAz0wggM5MB8GA1UdIwQYMBaAFD3TUKXWoK3u80pgCmXTIdT4
+NYPMB0GA1UdDgQWBBT4o6dhq9l3SxlmkMef45/msEQhBjBsBgNVHREEZTBjghB3
d3cuZGlnaWNlcnQuY29tghRjb250ZW50LmRpZ2ljZXJ0LmNvbYIMZGlnaWNlcnQu
Y29tghd3d3cub3JpZ2luLmRpZ2ljZXJ0LmNvbYISbG9naW4uZGlnaWNlcnQuY29t
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
dQYDVR0fBG4wbDA0oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTIt
ZXYtc2VydmVyLWcxLmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29t
L3NoYTItZXYtc2VydmVyLWcxLmNybDBCBgNVHSAEOzA5MDcGCWCGSAGG/WwCATAq
MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGIBggr
BgEFBQcBAQR8MHowJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
bTBSBggrBgEFBQcwAoZGaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
ZXJ0U0hBMkV4dGVuZGVkVmFsaWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMBAf8E
AjAAMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYApLkJkLQYWBSHuxOizGdwCjw1
mAT5G9+443fNDsgN3BAAAAFGAfj4EQAABAMARzBFAiBCsenxdlQ3dZBcfRMYphsr
6HrdAPxcfKp5U9BB8pU55gIhAI/rMx1PyNPn55YZxVp4zKgn9LAd2fAzCHvrfAeE
k4NrAHYAaPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8QAAAFGAfj4DQAA
BAMARzBFAiEAg8qcGjwzNf44Xz/TX4sj8HvgVHi66rY+p7tuGLXECS8CIAdmUF8C
CHveoNoZf5Gb1peHsT8Egl7sN2AL2WvbF+OYMA0GCSqGSIb3DQEBCwUAA4IBAQAt
nIIupEenVPHngDTSHo+3jvC0jtCatrc2HxciDQ6Rf7+d6m96qRjNjGCKTcnqswuN
vXcwlz716XIAMzPNO9YTFKOnTfzdwZcs5fYaJJc9eRIBm8icbialjb2dqLG9EFYR
BdY7VtwMQs2M3IEwWsl5hAsDEZkGDjL3uTONWfzl5CWj9olBfzI4RFY+4rHa/kML
WlwZqlMPruOGLN7HThOJ6KeTUkVxBjUusO1Nl3Ye7FCE9hXOhgSrq+CT/o7P9VPT
Q9FXgnA36oSFOPyD64yfMF8xT1fC5ogluE7smQcjkPFRLcoPq5pYMxIsYr3Z18rw
DcxdKIGW/9KPNNapvbom
-----END CERTIFICATE-----"""

    x509 = load_certificate(FILETYPE_PEM, ALTSUBJ_X509)
    ext = x509.get_extension(2)


    def check_alt_name_ext(self):
        for i in xrange(0, int(self.iterations) * 100):
            x = str(Checker_AltSubjectNameExt.ext)


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
