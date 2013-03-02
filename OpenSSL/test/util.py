# Copyright (C) Jean-Paul Calderone
# Copyright (C) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Helpers for the OpenSSL test suite, largely copied from
U{Twisted<http://twistedmatrix.com/>}.
"""

import shutil
import traceback
import os, os.path
from tempfile import mktemp
from unittest import TestCase
import sys

from OpenSSL.crypto import Error, _exception_from_error_queue

import memdbg

if sys.version_info < (3, 0):
    def b(s):
        return s
    bytes = str
else:
    def b(s):
        return s.encode("charmap")
    bytes = bytes

from tls.c import api

class TestCase(TestCase):
    """
    :py:class:`TestCase` adds useful testing functionality beyond what is available
    from the standard library :py:class:`unittest.TestCase`.
    """
    def setUp(self):
        super(TestCase, self).setUp()
        self._before = set(memdbg.heap)

    def tearDown(self):
        """
        Clean up any files or directories created using :py:meth:`TestCase.mktemp`.
        Subclasses must invoke this method if they override it or the
        cleanup will not occur.
        """
        import gc
        gc.collect(); gc.collect(); gc.collect()

        def format_leak(p):
            stacks = memdbg.heap[p]
            # Eventually look at multiple stacks for the realloc() case.  For
            # now just look at the original allocation location.
            (python_stack, c_stack) = stacks[0]

            stack = traceback.format_list(python_stack)[:-1]

            # c_stack looks something like this (interesting parts indicated
            # with inserted arrows not part of the data):
            #
            # /home/exarkun/Projects/pyOpenSSL/branches/use-opentls/__pycache__/_cffi__x89095113xb9185b9b.so(+0x12cf) [0x7fe2e20582cf]
            # /home/exarkun/Projects/cpython/2.7/python(PyCFunction_Call+0x8b) [0x56265a]
            # /home/exarkun/Projects/cpython/2.7/python() [0x4d5f52]
            # /home/exarkun/Projects/cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            # /home/exarkun/Projects/cpython/2.7/python() [0x4d6419]
            # /home/exarkun/Projects/cpython/2.7/python() [0x4d6129]
            # /home/exarkun/Projects/cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            # /home/exarkun/Projects/cpython/2.7/python(PyEval_EvalCodeEx+0x1043) [0x4d3726]
            # /home/exarkun/Projects/cpython/2.7/python() [0x55fd51]
            # /home/exarkun/Projects/cpython/2.7/python(PyObject_Call+0x7e) [0x420ee6]
            # /home/exarkun/Projects/cpython/2.7/python(PyEval_CallObjectWithKeywords+0x158) [0x4d56ec]
            # /home/exarkun/.local/lib/python2.7/site-packages/cffi-0.5-py2.7-linux-x86_64.egg/_cffi_backend.so(+0xe96e) [0x7fe2e38be96e]
            # /usr/lib/x86_64-linux-gnu/libffi.so.6(ffi_closure_unix64_inner+0x1b9) [0x7fe2e36ad819]
            # /usr/lib/x86_64-linux-gnu/libffi.so.6(ffi_closure_unix64+0x46) [0x7fe2e36adb7c]
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(CRYPTO_malloc+0x64) [0x7fe2e1cef784]           <------ end interesting
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(lh_insert+0x16b) [0x7fe2e1d6a24b]                      .
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(+0x61c18) [0x7fe2e1cf0c18]                             .
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(+0x625ec) [0x7fe2e1cf15ec]                             .
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(DSA_new_method+0xe6) [0x7fe2e1d524d6]                  .
            # /lib/x86_64-linux-gnu/libcrypto.so.1.0.0(DSA_generate_parameters+0x3a) [0x7fe2e1d5364a] <------ begin interesting
            # /home/exarkun/Projects/opentls/trunk/tls/c/__pycache__/_cffi__x305d4698xb539baaa.so(+0x1f397) [0x7fe2df84d397]
            # /home/exarkun/Projects/cpython/2.7/python(PyCFunction_Call+0x8b) [0x56265a]
            # /home/exarkun/Projects/cpython/2.7/python() [0x4d5f52]
            # /home/exarkun/Projects/cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            # /home/exarkun/Projects/cpython/2.7/python() [0x4d6419]
            # ...
            #
            # Notice the stack is upside down compared to a Python traceback.
            # Identify the start and end of interesting bits and stuff it into the stack we report.

            # Figure the first interesting frame will be after a the cffi-compiled module
            while '/__pycache__/_cffi__' not in c_stack[-1]:
                c_stack.pop()

            # Figure the last interesting frame will always be CRYPTO_malloc,
            # since that's where we hooked in to things.
            while 'CRYPTO_malloc' not in c_stack[0]:
                c_stack.pop(0)

            c_stack.reverse()
            stack.extend([frame + "\n" for frame in c_stack])

            # XXX :(
            ptr = int(str(p).split()[-1][:-1], 16)
            stack.insert(0, "Leaked 0x%x at:\n" % (ptr,))
            return "".join(stack)

        after = set(memdbg.heap)
        leak = after - self._before
        if leak:
            reasons = []
            for p in leak:
                reasons.append(format_leak(p))
                del memdbg.heap[p]
            self.fail('\n'.join(reasons))

        if False and self._temporaryFiles is not None:
            for temp in self._temporaryFiles:
                if os.path.isdir(temp):
                    shutil.rmtree(temp)
                elif os.path.exists(temp):
                    os.unlink(temp)
        try:
            _exception_from_error_queue()
        except Error:
            e = sys.exc_info()[1]
            if e.args != ([],):
                self.fail("Left over errors in OpenSSL error queue: " + repr(e))



    def failUnlessIn(self, containee, container, msg=None):
        """
        Fail the test if :py:data:`containee` is not found in :py:data:`container`.

        :param containee: the value that should be in :py:class:`container`
        :param container: a sequence type, or in the case of a mapping type,
                          will follow semantics of 'if key in dict.keys()'
        :param msg: if msg is None, then the failure message will be
                    '%r not in %r' % (first, second)
        """
        if containee not in container:
            raise self.failureException(msg or "%r not in %r"
                                        % (containee, container))
        return containee
    assertIn = failUnlessIn

    def failUnlessIdentical(self, first, second, msg=None):
        """
        Fail the test if :py:data:`first` is not :py:data:`second`.  This is an
        obect-identity-equality test, not an object equality
        (i.e. :py:func:`__eq__`) test.

        :param msg: if msg is None, then the failure message will be
        '%r is not %r' % (first, second)
        """
        if first is not second:
            raise self.failureException(msg or '%r is not %r' % (first, second))
        return first
    assertIdentical = failUnlessIdentical


    def failIfIdentical(self, first, second, msg=None):
        """
        Fail the test if :py:data:`first` is :py:data:`second`.  This is an
        obect-identity-equality test, not an object equality
        (i.e. :py:func:`__eq__`) test.

        :param msg: if msg is None, then the failure message will be
        '%r is %r' % (first, second)
        """
        if first is second:
            raise self.failureException(msg or '%r is %r' % (first, second))
        return first
    assertNotIdentical = failIfIdentical


    def failUnlessRaises(self, exception, f, *args, **kwargs):
        """
        Fail the test unless calling the function :py:data:`f` with the given
        :py:data:`args` and :py:data:`kwargs` raises :py:data:`exception`. The
        failure will report the traceback and call stack of the unexpected
        exception.

        :param exception: exception type that is to be expected
        :param f: the function to call

        :return: The raised exception instance, if it is of the given type.
        :raise self.failureException: Raised if the function call does
            not raise an exception or if it raises an exception of a
            different type.
        """
        try:
            result = f(*args, **kwargs)
        except exception:
            inst = sys.exc_info()[1]
            return inst
        except:
            raise self.failureException('%s raised instead of %s'
                                        % (sys.exc_info()[0],
                                           exception.__name__,
                                          ))
        else:
            raise self.failureException('%s not raised (%r returned)'
                                        % (exception.__name__, result))
    assertRaises = failUnlessRaises


    _temporaryFiles = None
    def mktemp(self):
        """
        Pathetic substitute for twisted.trial.unittest.TestCase.mktemp.
        """
        if self._temporaryFiles is None:
            self._temporaryFiles = []
        temp = mktemp(dir=".")
        self._temporaryFiles.append(temp)
        return temp


    # Python 2.3 compatibility.
    def assertTrue(self, *a, **kw):
        return self.failUnless(*a, **kw)


    def assertFalse(self, *a, **kw):
        return self.failIf(*a, **kw)


    # Other stuff
    def assertConsistentType(self, theType, name, *constructionArgs):
        """
        Perform various assertions about :py:data:`theType` to ensure that it is a
        well-defined type.  This is useful for extension types, where it's
        pretty easy to do something wacky.  If something about the type is
        unusual, an exception will be raised.

        :param theType: The type object about which to make assertions.
        :param name: A string giving the name of the type.
        :param constructionArgs: Positional arguments to use with :py:data:`theType` to
            create an instance of it.
        """
        self.assertEqual(theType.__name__, name)
        self.assertTrue(isinstance(theType, type))
        instance = theType(*constructionArgs)
        self.assertIdentical(type(instance), theType)
