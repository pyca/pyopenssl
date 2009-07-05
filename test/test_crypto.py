# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.crypto}.
"""

from unittest import main

from os import popen2

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, Error, PKey, PKeyType
from OpenSSL.crypto import X509, X509Type, X509Name, X509NameType
from OpenSSL.crypto import X509Req, X509ReqType
from OpenSSL.crypto import X509Extension, X509ExtensionType
from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
from OpenSSL.crypto import dump_certificate, load_certificate_request
from OpenSSL.crypto import dump_certificate_request, dump_privatekey
from OpenSSL.crypto import PKCS7Type, load_pkcs7_data
from OpenSSL.crypto import PKCS12Type, load_pkcs12
from OpenSSL.crypto import NetscapeSPKI, NetscapeSPKIType
from OpenSSL.test.util import TestCase


cleartextCertificatePEM = """-----BEGIN CERTIFICATE-----
MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
-----END CERTIFICATE-----
"""

cleartextPrivateKeyPEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD5mkLpi7q6ROdu7khB3S9aanA0Zls7vvfGOmB80/yeylhGpsjA
jWen0VtSQke/NlEPGtO38tsV7CsuFnSmschvAnGrcJl76b0UOOHUgDTIoRxC6QDU
3claegwsrBA+sJEBbqx5RdXbIRGicPG/8qQ4Zm1SKOgotcbwiaor2yxZ2wIDAQAB
AoGBAPCgMpmLxzwDaUmcFbTJUvlLW1hoxNNYSu2jIZm1k/hRAcE60JYwvBkgz3UB
yMEh0AtLxYe0bFk6EHah11tMUPgscbCq73snJ++8koUw+csk22G65hOs51bVb7Aa
6JBe67oLzdtvgCUFAA2qfrKzWRZzAdhUirQUZgySZk+Xq1pBAkEA/kZG0A6roTSM
BVnx7LnPfsycKUsTumorpXiylZJjTi9XtmzxhrYN6wgZlDOOwOLgSQhszGpxVoMD
u3gByT1b2QJBAPtL3mSKdvwRu/+40zaZLwvSJRxaj0mcE4BJOS6Oqs/hS1xRlrNk
PpQ7WJ4yM6ZOLnXzm2mKyxm50Mv64109FtMCQQDOqS2KkjHaLowTGVxwC0DijMfr
I9Lf8sSQk32J5VWCySWf5gGTfEnpmUa41gKTMJIbqZZLucNuDcOtzUaeWZlZAkA8
ttXigLnCqR486JDPTi9ZscoZkZ+w7y6e/hH8t6d5Vjt48JVyfjPIaJY+km58LcN3
6AWSeGAdtRFHVzR7oHjVAkB4hutvxiOeiIVQNBhM6RSI9aBPMI21DoX2JRoxvNW2
cbvAhow217X9V0dVerEOKxnNYspXRrh36h7k4mQA+sDq
-----END RSA PRIVATE KEY-----
"""

cleartextCertificateRequestPEM = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIBnjCCAQcCAQAwXjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQH\n"
    "EwdDaGljYWdvMRcwFQYDVQQKEw5NeSBDb21wYW55IEx0ZDEXMBUGA1UEAxMORnJl\n"
    "ZGVyaWNrIERlYW4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANp6Y17WzKSw\n"
    "BsUWkXdqg6tnXy8H8hA1msCMWpc+/2KJ4mbv5NyD6UD+/SqagQqulPbF/DFea9nA\n"
    "E0zhmHJELcM8gUTIlXv/cgDWnmK4xj8YkjVUiCdqKRAKeuzLG1pGmwwF5lGeJpXN\n"
    "xQn5ecR0UYSOWj6TTGXB9VyUMQzCClcBAgMBAAGgADANBgkqhkiG9w0BAQUFAAOB\n"
    "gQAAJGuF/R/GGbeC7FbFW+aJgr9ee0Xbl6nlhu7pTe67k+iiKT2dsl2ti68MVTnu\n"
    "Vrb3HUNqOkiwsJf6kCtq5oPn3QVYzTa76Dt2y3Rtzv6boRSlmlfrgS92GNma8JfR\n"
    "oICQk3nAudi6zl1Dix3BCv1pUp5KMtGn3MeDEi6QFGy2rA==\n"
    "-----END CERTIFICATE REQUEST-----\n")

encryptedPrivateKeyPEM = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9573604A18579E9E

SHOho56WxDkT0ht10UTeKc0F5u8cqIa01kzFAmETw0MAs8ezYtK15NPdCXUm3X/2
a17G7LSF5bkxOgZ7vpXyMzun/owrj7CzvLxyncyEFZWvtvzaAhPhvTJtTIB3kf8B
8+qRcpTGK7NgXEgYBW5bj1y4qZkD4zCL9o9NQzsKI3Ie8i0239jsDOWR38AxjXBH
mGwAQ4Z6ZN5dnmM4fhMIWsmFf19sNyAML4gHenQCHhmXbjXeVq47aC2ProInJbrm
+00TcisbAQ40V9aehVbcDKtS4ZbMVDwncAjpXpcncC54G76N6j7F7wL7L/FuXa3A
fvSVy9n2VfF/pJ3kYSflLHH2G/DFxjF7dl0GxhKPxJjp3IJi9VtuvmN9R2jZWLQF
tfC8dXgy/P9CfFQhlinqBTEwgH0oZ/d4k4NVFDSdEMaSdmBAjlHpc+Vfdty3HVnV
rKXj//wslsFNm9kIwJGIgKUa/n2jsOiydrsk1mgH7SmNCb3YHgZhbbnq0qLat/HC
gHDt3FHpNQ31QzzL3yrenFB2L9osIsnRsDTPFNi4RX4SpDgNroxOQmyzCCV6H+d4
o1mcnNiZSdxLZxVKccq0AfRpHqpPAFnJcQHP6xyT9MZp6fBa0XkxDnt9kNU8H3Qw
7SJWZ69VXjBUzMlQViLuaWMgTnL+ZVyFZf9hTF7U/ef4HMLMAVNdiaGG+G+AjCV/
MbzjS007Oe4qqBnCWaFPSnJX6uLApeTbqAxAeyCql56ULW5x6vDMNC3dwjvS/CEh
11n8RkgFIQA0AhuKSIg3CbuartRsJnWOLwgLTzsrKYL4yRog1RJrtw==
-----END RSA PRIVATE KEY-----
"""
encryptedPrivateKeyPEMPassphrase = "foobar"

# Some PKCS12 data, base64 encoded.  The data itself was constructed using the
# openssl command line:
#
#    openssl pkcs12 -export -in s.pem -out o.p12 -inkey s.pem -certfile s.pem
#
# With s.pem containing a private key and certificate.  The contents of the
# generated file, o.p12, were then base64 encoded to produce this value.
pkcs12Data = """\
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
""".decode('base64')

# Some PKCS#7 stuff.  Generated with the openssl command line:
#
#    openssl crl2pkcs7 -inform pem -outform pem -certfile s.pem -nocrl
#
# with a certificate and key (but the key should be irrelevant) in s.pem
pkcs7Data = """\
-----BEGIN PKCS7-----
MIIDNwYJKoZIhvcNAQcCoIIDKDCCAyQCAQExADALBgkqhkiG9w0BBwGgggMKMIID
BjCCAm+gAwIBAgIBATANBgkqhkiG9w0BAQQFADB7MQswCQYDVQQGEwJTRzERMA8G
A1UEChMITTJDcnlwdG8xFDASBgNVBAsTC00yQ3J5cHRvIENBMSQwIgYDVQQDExtN
MkNyeXB0byBDZXJ0aWZpY2F0ZSBNYXN0ZXIxHTAbBgkqhkiG9w0BCQEWDm5ncHNA
cG9zdDEuY29tMB4XDTAwMDkxMDA5NTEzMFoXDTAyMDkxMDA5NTEzMFowUzELMAkG
A1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIwEAYDVQQDEwlsb2NhbGhvc3Qx
HTAbBgkqhkiG9w0BCQEWDm5ncHNAcG9zdDEuY29tMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAKy+e3dulvXzV7zoTZWc5TzgApr8DmeQHTYC8ydfzH7EECe4R1Xh5kwI
zOuuFfn178FBiS84gngaNcrFi0Z5fAkCAwEAAaOCAQQwggEAMAkGA1UdEwQCMAAw
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G
A1UdDgQWBBTPhIKSvnsmYsBVNWjj0m3M2z0qVTCBpQYDVR0jBIGdMIGagBT7hyNp
65w6kxXlxb8pUU/+7Sg4AaF/pH0wezELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0y
Q3J5cHRvMRQwEgYDVQQLEwtNMkNyeXB0byBDQTEkMCIGA1UEAxMbTTJDcnlwdG8g
Q2VydGlmaWNhdGUgTWFzdGVyMR0wGwYJKoZIhvcNAQkBFg5uZ3BzQHBvc3QxLmNv
bYIBADANBgkqhkiG9w0BAQQFAAOBgQA7/CqT6PoHycTdhEStWNZde7M/2Yc6BoJu
VwnW8YxGO8Sn6UJ4FeffZNcYZddSDKosw8LtPOeWoK3JINjAk5jiPQ2cww++7QGG
/g5NDjxFZNDJP1dGiLAxPW6JXwov4v0FmdzfLOZ01jDcgQQZqEpYlgpuI5JEWUQ9
Ho4EzbYCOaEAMQA=
-----END PKCS7-----
"""


class _Python23TestCaseHelper:
    # Python 2.3 compatibility.
    def assertTrue(self, *a, **kw):
        return self.failUnless(*a, **kw)


    def assertFalse(self, *a, **kw):
        return self.failIf(*a, **kw)



class X509ExtTests(TestCase, _Python23TestCaseHelper):
    def test_construction(self):
        """
        L{X509Extension} accepts an extension type name, a critical flag,
        and an extension value and returns an L{X509ExtensionType} instance.
        """
        basic = X509Extension('basicConstraints', True, 'CA:true')
        self.assertTrue(
            isinstance(basic, X509ExtensionType),
            "%r is of type %r, should be %r" % (
                basic, type(basic), X509ExtensionType))

        comment = X509Extension('nsComment', False, 'pyOpenSSL unit test')
        self.assertTrue(
            isinstance(comment, X509ExtensionType),
            "%r is of type %r, should be %r" % (
                comment, type(comment), X509ExtensionType))


    def test_invalid_extension(self):
        """
        L{X509Extension} raises something if it is passed a bad extension
        name or value.
        """
        self.assertRaises(
            Error, X509Extension, 'thisIsMadeUp', False, 'hi')
        self.assertRaises(
            Error, X509Extension, 'basicConstraints', False, 'blah blah')

        # Exercise a weird one (an extension which uses the r2i method).  This
        # exercises the codepath that requires a non-NULL ctx to be passed to
        # X509V3_EXT_nconf.  It can't work now because we provide no
        # configuration database.  It might be made to work in the future.
        self.assertRaises(
            Error, X509Extension, 'proxyCertInfo', True,
            'language:id-ppl-anyLanguage,pathlen:1,policy:text:AB')


    def test_get_critical(self):
        """
        L{X509ExtensionType.get_critical} returns the value of the
        extension's critical flag.
        """
        ext = X509Extension('basicConstraints', True, 'CA:true')
        self.assertTrue(ext.get_critical())
        ext = X509Extension('basicConstraints', False, 'CA:true')
        self.assertFalse(ext.get_critical())


    def test_get_short_name(self):
        """
        L{X509ExtensionType.get_short_name} returns a string giving the short
        type name of the extension.
        """
        ext = X509Extension('basicConstraints', True, 'CA:true')
        self.assertEqual(ext.get_short_name(), 'basicConstraints')
        ext = X509Extension('nsComment', True, 'foo bar')
        self.assertEqual(ext.get_short_name(), 'nsComment')



class PKeyTests(TestCase, _Python23TestCaseHelper):
    """
    Unit tests for L{OpenSSL.crypto.PKey}.
    """
    def test_construction(self):
        """
        L{PKey} takes no arguments and returns a new L{PKeyType} instance.
        """
        self.assertRaises(TypeError, PKey, None)
        key = PKey()
        self.assertTrue(
            isinstance(key, PKeyType),
            "%r is of type %r, should be %r" % (key, type(key), PKeyType))


    def test_pregeneration(self):
        """
        L{PKeyType.bits} and L{PKeyType.type} return C{0} before the key is
        generated.
        """
        key = PKey()
        self.assertEqual(key.type(), 0)
        self.assertEqual(key.bits(), 0)


    def test_failedGeneration(self):
        """
        L{PKeyType.generate_key} takes two arguments, the first giving the key
        type as one of L{TYPE_RSA} or L{TYPE_DSA} and the second giving the
        number of bits to generate.  If an invalid type is specified or
        generation fails, L{Error} is raised.  If an invalid number of bits is
        specified, L{ValueError} or L{Error} is raised.
        """
        key = PKey()
        self.assertRaises(TypeError, key.generate_key)
        self.assertRaises(TypeError, key.generate_key, 1, 2, 3)
        self.assertRaises(TypeError, key.generate_key, "foo", "bar")
        self.assertRaises(Error, key.generate_key, -1, 0)

        self.assertRaises(ValueError, key.generate_key, TYPE_RSA, -1)
        self.assertRaises(ValueError, key.generate_key, TYPE_RSA, 0)

        # XXX RSA generation for small values of bits is fairly buggy in a wide
        # range of OpenSSL versions.  I need to figure out what the safe lower
        # bound for a reasonable number of OpenSSL versions is and explicitly
        # check for that in the wrapper.  The failure behavior is typically an
        # infinite loop inside OpenSSL.

        # self.assertRaises(Error, key.generate_key, TYPE_RSA, 2)

        # XXX DSA generation seems happy with any number of bits.  The DSS
        # says bits must be between 512 and 1024 inclusive.  OpenSSL's DSA
        # generator doesn't seem to care about the upper limit at all.  For
        # the lower limit, it uses 512 if anything smaller is specified.
        # So, it doesn't seem possible to make generate_key fail for
        # TYPE_DSA with a bits argument which is at least an int.

        # self.assertRaises(Error, key.generate_key, TYPE_DSA, -7)


    def test_rsaGeneration(self):
        """
        L{PKeyType.generate_key} generates an RSA key when passed
        L{TYPE_RSA} as a type and a reasonable number of bits.
        """
        bits = 128
        key = PKey()
        key.generate_key(TYPE_RSA, bits)
        self.assertEqual(key.type(), TYPE_RSA)
        self.assertEqual(key.bits(), bits)


    def test_dsaGeneration(self):
        """
        L{PKeyType.generate_key} generates a DSA key when passed
        L{TYPE_DSA} as a type and a reasonable number of bits.
        """
        # 512 is a magic number.  The DSS (Digital Signature Standard)
        # allows a minimum of 512 bits for DSA.  DSA_generate_parameters
        # will silently promote any value below 512 to 512.
        bits = 512
        key = PKey()
        key.generate_key(TYPE_DSA, bits)
        self.assertEqual(key.type(), TYPE_DSA)
        self.assertEqual(key.bits(), bits)


    def test_regeneration(self):
        """
        L{PKeyType.generate_key} can be called multiple times on the same
        key to generate new keys.
        """
        key = PKey()
        for type, bits in [(TYPE_RSA, 512), (TYPE_DSA, 576)]:
             key.generate_key(type, bits)
             self.assertEqual(key.type(), type)
             self.assertEqual(key.bits(), bits)



class X509NameTests(TestCase, _Python23TestCaseHelper):
    """
    Unit tests for L{OpenSSL.crypto.X509Name}.
    """
    def _x509name(self, **attrs):
        # XXX There's no other way to get a new X509Name yet.
        name = X509().get_subject()
        attrs = attrs.items()
        # Make the order stable - order matters!
        attrs.sort(lambda (k1, v1), (k2, v2): cmp(v1, v2))
        for k, v in attrs:
            setattr(name, k, v)
        return name


    def test_attributes(self):
        """
        L{X509NameType} instances have attributes for each standard (?)
        X509Name field.
        """
        name = self._x509name()
        name.commonName = "foo"
        self.assertEqual(name.commonName, "foo")
        self.assertEqual(name.CN, "foo")
        name.CN = "baz"
        self.assertEqual(name.commonName, "baz")
        self.assertEqual(name.CN, "baz")
        name.commonName = "bar"
        self.assertEqual(name.commonName, "bar")
        self.assertEqual(name.CN, "bar")
        name.CN = "quux"
        self.assertEqual(name.commonName, "quux")
        self.assertEqual(name.CN, "quux")


    def test_copy(self):
        """
        L{X509Name} creates a new L{X509NameType} instance with all the same
        attributes as an existing L{X509NameType} instance when called with
        one.
        """
        name = self._x509name(commonName="foo", emailAddress="bar@example.com")

        copy = X509Name(name)
        self.assertEqual(copy.commonName, "foo")
        self.assertEqual(copy.emailAddress, "bar@example.com")

        # Mutate the copy and ensure the original is unmodified.
        copy.commonName = "baz"
        self.assertEqual(name.commonName, "foo")

        # Mutate the original and ensure the copy is unmodified.
        name.emailAddress = "quux@example.com"
        self.assertEqual(copy.emailAddress, "bar@example.com")


    def test_repr(self):
        """
        L{repr} passed an L{X509NameType} instance should return a string
        containing a description of the type and the NIDs which have been set
        on it.
        """
        name = self._x509name(commonName="foo", emailAddress="bar")
        self.assertEqual(
            repr(name),
            "<X509Name object '/emailAddress=bar/CN=foo'>")


    def test_comparison(self):
        """
        L{X509NameType} instances should compare based on their NIDs.
        """
        def _equality(a, b, assertTrue, assertFalse):
            assertTrue(a == b, "(%r == %r) --> False" % (a, b))
            assertFalse(a != b)
            assertTrue(b == a)
            assertFalse(b != a)

        def assertEqual(a, b):
            _equality(a, b, self.assertTrue, self.assertFalse)

        # Instances compare equal to themselves.
        name = self._x509name()
        assertEqual(name, name)

        # Empty instances should compare equal to each other.
        assertEqual(self._x509name(), self._x509name())

        # Instances with equal NIDs should compare equal to each other.
        assertEqual(self._x509name(commonName="foo"),
                    self._x509name(commonName="foo"))

        # Instance with equal NIDs set using different aliases should compare
        # equal to each other.
        assertEqual(self._x509name(commonName="foo"),
                    self._x509name(CN="foo"))

        # Instances with more than one NID with the same values should compare
        # equal to each other.
        assertEqual(self._x509name(CN="foo", organizationalUnitName="bar"),
                    self._x509name(commonName="foo", OU="bar"))

        def assertNotEqual(a, b):
            _equality(a, b, self.assertFalse, self.assertTrue)

        # Instances with different values for the same NID should not compare
        # equal to each other.
        assertNotEqual(self._x509name(CN="foo"),
                       self._x509name(CN="bar"))

        # Instances with different NIDs should not compare equal to each other.
        assertNotEqual(self._x509name(CN="foo"),
                       self._x509name(OU="foo"))

        def _inequality(a, b, assertTrue, assertFalse):
            assertTrue(a < b)
            assertTrue(a <= b)
            assertTrue(b > a)
            assertTrue(b >= a)
            assertFalse(a > b)
            assertFalse(a >= b)
            assertFalse(b < a)
            assertFalse(b <= a)

        def assertLessThan(a, b):
            _inequality(a, b, self.assertTrue, self.assertFalse)

        # An X509Name with a NID with a value which sorts less than the value
        # of the same NID on another X509Name compares less than the other
        # X509Name.
        assertLessThan(self._x509name(CN="abc"),
                       self._x509name(CN="def"))

        def assertGreaterThan(a, b):
            _inequality(a, b, self.assertFalse, self.assertTrue)

        # An X509Name with a NID with a value which sorts greater than the
        # value of the same NID on another X509Name compares greater than the
        # other X509Name.
        assertGreaterThan(self._x509name(CN="def"),
                          self._x509name(CN="abc"))


    def test_hash(self):
        """
        L{X509Name.hash} returns an integer hash based on the value of the
        name.
        """
        a = self._x509name(CN="foo")
        b = self._x509name(CN="foo")
        self.assertEqual(a.hash(), b.hash())
        a.CN = "bar"
        self.assertNotEqual(a.hash(), b.hash())


    def test_der(self):
        """
        L{X509Name.der} returns the DER encoded form of the name.
        """
        a = self._x509name(CN="foo", C="US")
        self.assertEqual(
            a.der(),
            '0\x1b1\x0b0\t\x06\x03U\x04\x06\x13\x02US'
            '1\x0c0\n\x06\x03U\x04\x03\x13\x03foo')


    def test_get_components(self):
        """
        L{X509Name.get_components} returns a C{list} of two-tuples of C{str}
        giving the NIDs and associated values which make up the name.
        """
        a = self._x509name()
        self.assertEqual(a.get_components(), [])
        a.CN = "foo"
        self.assertEqual(a.get_components(), [("CN", "foo")])
        a.organizationalUnitName = "bar"
        self.assertEqual(
            a.get_components(),
            [("CN", "foo"), ("OU", "bar")])


class _PKeyInteractionTestsMixin:
    """
    Tests which involve another thing and a PKey.
    """
    def signable(self):
        """
        Return something with a C{set_pubkey}, C{set_pubkey}, and C{sign} method.
        """
        raise NotImplementedError()


    def test_signWithUngenerated(self):
        """
        L{X509Req.sign} raises L{ValueError} when pass a L{PKey} with no parts.
        """
        request = self.signable()
        key = PKey()
        self.assertRaises(ValueError, request.sign, key, 'MD5')


    def test_signWithPublicKey(self):
        """
        L{X509Req.sign} raises L{ValueError} when pass a L{PKey} with no
        private part as the signing key.
        """
        request = self.signable()
        key = PKey()
        key.generate_key(TYPE_RSA, 512)
        request.set_pubkey(key)
        pub = request.get_pubkey()
        self.assertRaises(ValueError, request.sign, pub, 'MD5')



class X509ReqTests(TestCase, _PKeyInteractionTestsMixin, _Python23TestCaseHelper):
    """
    Tests for L{OpenSSL.crypto.X509Req}.
    """
    def signable(self):
        """
        Create and return a new L{X509Req}.
        """
        return X509Req()


    def test_construction(self):
        """
        L{X509Req} takes no arguments and returns an L{X509ReqType} instance.
        """
        request = X509Req()
        self.assertTrue(
            isinstance(request, X509ReqType),
            "%r is of type %r, should be %r" % (request, type(request), X509ReqType))


    def test_version(self):
        """
        L{X509ReqType.set_version} sets the X.509 version of the certificate
        request.  L{X509ReqType.get_version} returns the X.509 version of
        the certificate request.  The initial value of the version is 0.
        """
        request = X509Req()
        self.assertEqual(request.get_version(), 0)
        request.set_version(1)
        self.assertEqual(request.get_version(), 1)
        request.set_version(3)
        self.assertEqual(request.get_version(), 3)


    def test_get_subject(self):
        """
        L{X509ReqType.get_subject} returns an L{X509Name} for the subject of
        the request and which is valid even after the request object is
        otherwise dead.
        """
        request = X509Req()
        subject = request.get_subject()
        self.assertTrue(
            isinstance(subject, X509NameType),
            "%r is of type %r, should be %r" % (subject, type(subject), X509NameType))
        subject.commonName = "foo"
        self.assertEqual(request.get_subject().commonName, "foo")
        del request
        subject.commonName = "bar"
        self.assertEqual(subject.commonName, "bar")



class X509Tests(TestCase, _PKeyInteractionTestsMixin, _Python23TestCaseHelper):
    """
    Tests for L{OpenSSL.crypto.X509}.
    """
    pemData = cleartextCertificatePEM + cleartextPrivateKeyPEM

    def signable(self):
        """
        Create and return a new L{X509}.
        """
        return X509()


    def test_construction(self):
        """
        L{X509} takes no arguments and returns an instance of L{X509Type}.
        """
        certificate = X509()
        self.assertTrue(
            isinstance(certificate, X509Type),
            "%r is of type %r, should be %r" % (certificate,
                                                type(certificate),
                                                X509Type))


    def test_serial_number(self):
        """
        The serial number of an L{X509Type} can be retrieved and modified with
        L{X509Type.get_serial_number} and L{X509Type.set_serial_number}.
        """
        certificate = X509()
        self.assertRaises(TypeError, certificate.set_serial_number)
        self.assertRaises(TypeError, certificate.set_serial_number, 1, 2)
        self.assertRaises(TypeError, certificate.set_serial_number, "1")
        self.assertRaises(TypeError, certificate.set_serial_number, 5.5)
        self.assertEqual(certificate.get_serial_number(), 0)
        certificate.set_serial_number(1)
        self.assertEqual(certificate.get_serial_number(), 1)
        certificate.set_serial_number(2 ** 32 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 32 + 1)
        certificate.set_serial_number(2 ** 64 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 64 + 1)
        certificate.set_serial_number(2 ** 128 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 128 + 1)


    def _setBoundTest(self, which):
        """
        L{X509Type.set_notBefore} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the beginning of the certificate's validity
        period to it.
        """
        certificate = X509()
        set = getattr(certificate, 'set_not' + which)
        get = getattr(certificate, 'get_not' + which)

        # Starts with no value.
        self.assertEqual(get(), None)

        # GMT (Or is it UTC?) -exarkun
        when = "20040203040506Z"
        set(when)
        self.assertEqual(get(), when)

        # A plus two hours and thirty minutes offset
        when = "20040203040506+0530"
        set(when)
        self.assertEqual(get(), when)

        # A minus one hour fifteen minutes offset
        when = "20040203040506-0115"
        set(when)
        self.assertEqual(get(), when)

        # An invalid string results in a ValueError
        self.assertRaises(ValueError, set, "foo bar")


    def test_set_notBefore(self):
        """
        L{X509Type.set_notBefore} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the beginning of the certificate's validity
        period to it.
        """
        self._setBoundTest("Before")


    def test_set_notAfter(self):
        """
        L{X509Type.set_notAfter} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the end of the certificate's validity period
        to it.
        """
        self._setBoundTest("After")


    def test_get_notBefore(self):
        """
        L{X509Type.get_notBefore} returns a string in the format of an ASN1
        GENERALIZEDTIME even for certificates which store it as UTCTIME
        internally.
        """
        cert = load_certificate(FILETYPE_PEM, self.pemData)
        self.assertEqual(cert.get_notBefore(), "20090325123658Z")


    def test_get_notAfter(self):
        """
        L{X509Type.get_notAfter} returns a string in the format of an ASN1
        GENERALIZEDTIME even for certificates which store it as UTCTIME
        internally.
        """
        cert = load_certificate(FILETYPE_PEM, self.pemData)
        self.assertEqual(cert.get_notAfter(), "20170611123658Z")


    def test_digest(self):
        """
        L{X509.digest} returns a string giving ":"-separated hex-encoded words
        of the digest of the certificate.
        """
        cert = X509()
        self.assertEqual(
            cert.digest("md5"),
            "A8:EB:07:F8:53:25:0A:F2:56:05:C5:A5:C4:C4:C7:15")



class FunctionTests(TestCase, _Python23TestCaseHelper):
    """
    Tests for free-functions in the L{OpenSSL.crypto} module.
    """
    def test_load_privatekey_wrongPassphrase(self):
        """
        L{load_privatekey} raises L{OpenSSL.crypto.Error} when it is passed an
        encrypted PEM and an incorrect passphrase.
        """
        self.assertRaises(
            Error,
            load_privatekey, FILETYPE_PEM, encryptedPrivateKeyPEM, "quack")


    def test_load_privatekey_passphrase(self):
        """
        L{load_privatekey} can create a L{PKey} object from an encrypted PEM
        string if given the passphrase.
        """
        key = load_privatekey(
            FILETYPE_PEM, encryptedPrivateKeyPEM,
            encryptedPrivateKeyPEMPassphrase)
        self.assertTrue(isinstance(key, PKeyType))


    def test_load_privatekey_wrongPassphraseCallback(self):
        """
        L{load_privatekey} raises L{OpenSSL.crypto.Error} when it is passed an
        encrypted PEM and a passphrase callback which returns an incorrect
        passphrase.
        """
        called = []
        def cb(*a):
            called.append(None)
            return "quack"
        self.assertRaises(
            Error,
            load_privatekey, FILETYPE_PEM, encryptedPrivateKeyPEM, cb)
        self.assertTrue(called)

    def test_load_privatekey_passphraseCallback(self):
        """
        L{load_privatekey} can create a L{PKey} object from an encrypted PEM
        string if given a passphrase callback which returns the correct
        password.
        """
        called = []
        def cb(writing):
            called.append(writing)
            return encryptedPrivateKeyPEMPassphrase
        key = load_privatekey(FILETYPE_PEM, encryptedPrivateKeyPEM, cb)
        self.assertTrue(isinstance(key, PKeyType))
        self.assertEqual(called, [False])


    def test_dump_privatekey_passphrase(self):
        """
        L{dump_privatekey} writes an encrypted PEM when given a passphrase.
        """
        passphrase = "foo"
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        pem = dump_privatekey(FILETYPE_PEM, key, "blowfish", passphrase)
        self.assertTrue(isinstance(pem, str))
        loadedKey = load_privatekey(FILETYPE_PEM, pem, passphrase)
        self.assertTrue(isinstance(loadedKey, PKeyType))
        self.assertEqual(loadedKey.type(), key.type())
        self.assertEqual(loadedKey.bits(), key.bits())


    def _runopenssl(self, pem, *args):
        """
        Run the command line openssl tool with the given arguments and write
        the given PEM to its stdin.
        """
        write, read = popen2(" ".join(("openssl",) + args), "b")
        write.write(pem)
        write.close()
        return read.read()


    def test_dump_certificate(self):
        """
        L{dump_certificate} writes PEM, DER, and text.
        """
        pemData = cleartextCertificatePEM + cleartextPrivateKeyPEM
        cert = load_certificate(FILETYPE_PEM, pemData)
        dumped_pem = dump_certificate(FILETYPE_PEM, cert)
        self.assertEqual(dumped_pem, cleartextCertificatePEM)
        dumped_der = dump_certificate(FILETYPE_ASN1, cert)
        good_der = self._runopenssl(dumped_pem, "x509", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        cert2 = load_certificate(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_certificate(FILETYPE_PEM, cert2)
        self.assertEqual(dumped_pem2, cleartextCertificatePEM)
        dumped_text = dump_certificate(FILETYPE_TEXT, cert)
        good_text = self._runopenssl(dumped_pem, "x509", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_privatekey(self):
        """
        L{dump_privatekey} writes a PEM, DER, and text.
        """
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        dumped_pem = dump_privatekey(FILETYPE_PEM, key)
        self.assertEqual(dumped_pem, cleartextPrivateKeyPEM)
        dumped_der = dump_privatekey(FILETYPE_ASN1, key)
        # XXX This OpenSSL call writes "writing RSA key" to standard out.  Sad.
        good_der = self._runopenssl(dumped_pem, "rsa", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        key2 = load_privatekey(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_privatekey(FILETYPE_PEM, key2)
        self.assertEqual(dumped_pem2, cleartextPrivateKeyPEM)
        dumped_text = dump_privatekey(FILETYPE_TEXT, key)
        good_text = self._runopenssl(dumped_pem, "rsa", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_certificate_request(self):
        """
        L{dump_certificate_request} writes a PEM, DER, and text.
        """
        req = load_certificate_request(FILETYPE_PEM, cleartextCertificateRequestPEM)
        dumped_pem = dump_certificate_request(FILETYPE_PEM, req)
        self.assertEqual(dumped_pem, cleartextCertificateRequestPEM)
        dumped_der = dump_certificate_request(FILETYPE_ASN1, req)
        good_der = self._runopenssl(dumped_pem, "req", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        req2 = load_certificate_request(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_certificate_request(FILETYPE_PEM, req2)
        self.assertEqual(dumped_pem2, cleartextCertificateRequestPEM)
        dumped_text = dump_certificate_request(FILETYPE_TEXT, req)
        good_text = self._runopenssl(dumped_pem, "req", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_privatekey_passphraseCallback(self):
        """
        L{dump_privatekey} writes an encrypted PEM when given a callback which
        returns the correct passphrase.
        """
        passphrase = "foo"
        called = []
        def cb(writing):
            called.append(writing)
            return passphrase
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        pem = dump_privatekey(FILETYPE_PEM, key, "blowfish", cb)
        self.assertTrue(isinstance(pem, str))
        self.assertEqual(called, [True])
        loadedKey = load_privatekey(FILETYPE_PEM, pem, passphrase)
        self.assertTrue(isinstance(loadedKey, PKeyType))
        self.assertEqual(loadedKey.type(), key.type())
        self.assertEqual(loadedKey.bits(), key.bits())


    def test_load_pkcs7_data(self):
        """
        L{load_pkcs7_data} accepts a PKCS#7 string and returns an instance of
        L{PKCS7Type}.
        """
        pkcs7 = load_pkcs7_data(FILETYPE_PEM, pkcs7Data)
        self.assertTrue(isinstance(pkcs7, PKCS7Type))


    def test_load_pkcs12(self):
        """
        L{load_pkcs12} accepts a PKCS#12 string and returns an instance of
        L{PKCS12Type}.
        """
        pkcs12 = load_pkcs12(pkcs12Data)
        self.assertTrue(isinstance(pkcs12, PKCS12Type))



class NetscapeSPKITests(TestCase):
    """
    Tests for L{OpenSSL.crypto.NetscapeSPKI}.
    """
    def test_construction(self):
        """
        L{NetscapeSPKI} returns an instance of L{NetscapeSPKIType}.
        """
        nspki = NetscapeSPKI()
        self.assertTrue(isinstance(nspki, NetscapeSPKIType))



if __name__ == '__main__':
    main()
