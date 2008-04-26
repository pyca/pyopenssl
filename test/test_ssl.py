# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.SSL}.
"""

from unittest import TestCase
from tempfile import mktemp

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, PKey, dump_privatekey
from OpenSSL.SSL import Context
from OpenSSL.SSL import SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD


class ContextTests(TestCase):
    """
    Unit tests for L{OpenSSL.SSL.Context}.
    """
    def mktemp(self):
        """
        Pathetic substitute for twisted.trial.unittest.TestCase.mktemp.
        """
        return mktemp(dir=".")


    def test_method(self):
        """
        L{Context} can be instantiated with one of L{SSLv2_METHOD},
        L{SSLv3_METHOD}, L{SSLv23_METHOD}, or L{TLSv1_METHOD}.
        """
        for meth in [SSLv2_METHOD, SSLv3_METHOD, SSLv23_METHOD, TLSv1_METHOD]:
            Context(meth)
        self.assertRaises(TypeError, Context, "")
        self.assertRaises(ValueError, Context, 10)


    def test_use_privatekey(self):
        """
        L{Context.use_privatekey} takes an L{OpenSSL.crypto.PKey} instance.
        """
        key = PKey()
        key.generate_key(TYPE_RSA, 128)
        ctx = Context(TLSv1_METHOD)
        ctx.use_privatekey(key)
        self.assertRaises(TypeError, ctx.use_privatekey, "")


    def test_set_passwd_cb(self):
        """
        L{Context.set_passwd_cb} accepts a callable which will be invoked when
        a private key is loaded from an encrypted PEM.
        """
        key = PKey()
        key.generate_key(TYPE_RSA, 128)
        pemFile = self.mktemp()
        fObj = file(pemFile, 'w')
        passphrase = "foobar"
        fObj.write(dump_privatekey(FILETYPE_PEM, key, "blowfish", passphrase))
        fObj.close()

        calledWith = []
        def passphraseCallback(maxlen, verify, extra):
            calledWith.append((maxlen, verify, extra))
            return passphrase
        context = Context(TLSv1_METHOD)
        context.set_passwd_cb(passphraseCallback)
        context.use_privatekey_file(pemFile)
        self.assertTrue(len(calledWith), 1)
        self.assertTrue(isinstance(calledWith[0][0], int))
        self.assertTrue(isinstance(calledWith[0][1], int))
        self.assertEqual(calledWith[0][2], None)
