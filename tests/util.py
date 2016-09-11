# Copyright (C) Jean-Paul Calderone
# Copyright (C) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Helpers for the OpenSSL test suite, largely copied from
U{Twisted<http://twistedmatrix.com/>}.
"""

import shutil
import sys
import traceback

from tempfile import mktemp, mkdtemp
from unittest import TestCase

import pytest

from six import PY3

from OpenSSL._util import exception_from_error_queue
from OpenSSL.crypto import Error


from . import memdbg

from OpenSSL._util import ffi, lib


# This is the UTF-8 encoding of the SNOWMAN unicode code point.
NON_ASCII = b"\xe2\x98\x83".decode("utf-8")


class TestCase(TestCase):
    """
    :py:class:`TestCase` adds useful testing functionality beyond what is
    available from the standard library :py:class:`unittest.TestCase`.
    """

    def run(self, result):
        run = super(TestCase, self).run
        if memdbg.heap is None:
            return run(result)

        # Run the test as usual
        before = set(memdbg.heap)
        run(result)

        # Clean up some long-lived allocations so they won't be reported as
        # memory leaks.
        lib.CRYPTO_cleanup_all_ex_data()
        lib.ERR_clear_error()
        after = set(memdbg.heap)

        if not after - before:
            # No leaks, fast succeed
            return

        if result.wasSuccessful():
            # If it passed, run it again with memory debugging
            before = set(memdbg.heap)
            run(result)

            # Clean up some long-lived allocations so they won't be reported as
            # memory leaks.
            lib.CRYPTO_cleanup_all_ex_data()
            lib.ERR_clear_error()

            after = set(memdbg.heap)

            self._reportLeaks(after - before, result)

    def _reportLeaks(self, leaks, result):
        def format_leak(p):
            """
            c_stack looks something like this (interesting parts indicated
            with inserted arrows not part of the data):

            cpython/2.7/python(PyCFunction_Call+0x8b) [0x56265a]
            cpython/2.7/python() [0x4d5f52]
            cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            cpython/2.7/python() [0x4d6419]
            cpython/2.7/python() [0x4d6129]
            cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            cpython/2.7/python(PyEval_EvalCodeEx+0x1043) [0x4d3726]
            cpython/2.7/python() [0x55fd51]
            cpython/2.7/python(PyObject_Call+0x7e) [0x420ee6]
            cpython/2.7/python(PyEval_CallObjectWithKeywords+0x158) [0x4d56ec]
            _cffi_backend.so(+0xe96e) [0x7fe2e38be96e]
            libffi.so.6(ffi_closure_unix64_inner+0x1b9) [0x7fe2e36ad819]
            libffi.so.6(ffi_closure_unix64+0x46) [0x7fe2e36adb7c]

            |----- end interesting
            v
            libcrypto.so.1.0.0(CRYPTO_malloc+0x64) [0x7fe2e1cef784]
            libcrypto.so.1.0.0(lh_insert+0x16b) [0x7fe2e1d6a24b]
            libcrypto.so.1.0.0(+0x61c18) [0x7fe2e1cf0c18]
            libcrypto.so.1.0.0(+0x625ec) [0x7fe2e1cf15ec]
            libcrypto.so.1.0.0(DSA_new_method+0xe6) [0x7fe2e1d524d6]
            libcrypto.so.1.0.0(DSA_generate_parameters+0x3a) [0x7fe2e1d5364a]
            ^
            |----- begin interesting

            _cffi__x305d4698xb539baaa.so(+0x1f397) [0x7fe2df84d397]
            cpython/2.7/python(PyCFunction_Call+0x8b) [0x56265a]
            cpython/2.7/python() [0x4d5f52]
            cpython/2.7/python(PyEval_EvalFrameEx+0x753b) [0x4d0e1e]
            cpython/2.7/python() [0x4d6419]
            ...

            Notice the stack is upside down compared to a Python traceback.
            Identify the start and end of interesting bits and stuff it into
            the stack we report.
            """
            stacks = memdbg.heap[p]
            # Eventually look at multiple stacks for the realloc() case.  For
            # now just look at the original allocation location.
            (size, python_stack, c_stack) = stacks[0]

            stack = traceback.format_list(python_stack)[:-1]
            saved = list(c_stack)

            # Figure the first interesting frame will be after a the
            # cffi-compiled module
            while c_stack and '/__pycache__/_cffi__' not in c_stack[-1]:
                c_stack.pop()

            # Figure the last interesting frame will always be CRYPTO_malloc,
            # since that's where we hooked in to things.
            while (
                c_stack and 'CRYPTO_malloc' not in c_stack[0] and
                'CRYPTO_realloc' not in c_stack[0]
            ):
                c_stack.pop(0)

            if c_stack:
                c_stack.reverse()
            else:
                c_stack = saved[::-1]
            stack.extend([frame + "\n" for frame in c_stack])

            stack.insert(0, "Leaked (%s) at:\n")
            return "".join(stack)

        if leaks:
            unique_leaks = {}
            for p in leaks:
                size = memdbg.heap[p][-1][0]
                new_leak = format_leak(p)
                if new_leak not in unique_leaks:
                    unique_leaks[new_leak] = [(size, p)]
                else:
                    unique_leaks[new_leak].append((size, p))
                memdbg.free(p)

            for (stack, allocs) in unique_leaks.iteritems():
                allocs_accum = []
                for (size, pointer) in allocs:

                    addr = int(ffi.cast('uintptr_t', pointer))
                    allocs_accum.append("%d@0x%x" % (size, addr))
                allocs_report = ", ".join(sorted(allocs_accum))

                result.addError(
                    self,
                    (None, Exception(stack % (allocs_report,)), None))

    _tmpdir = None

    @property
    def tmpdir(self):
        """
        On demand create a temporary directory.
        """
        if self._tmpdir is not None:
            return self._tmpdir

        self._tmpdir = mkdtemp(dir=".")
        return self._tmpdir

    def tearDown(self):
        """
        Clean up any files or directories created using
        :py:meth:`TestCase.mktemp`.  Subclasses must invoke this method if they
        override it or the cleanup will not occur.
        """
        if self._tmpdir is not None:
            shutil.rmtree(self._tmpdir)

        try:
            exception_from_error_queue(Error)
        except Error:
            e = sys.exc_info()[1]
            if e.args != ([],):
                self.fail(
                    "Left over errors in OpenSSL error queue: " + repr(e)
                )

    def assertIsInstance(self, instance, classOrTuple, message=None):
        """
        Fail if C{instance} is not an instance of the given class or of
        one of the given classes.

        @param instance: the object to test the type (first argument of the
            C{isinstance} call).
        @type instance: any.
        @param classOrTuple: the class or classes to test against (second
            argument of the C{isinstance} call).
        @type classOrTuple: class, type, or tuple.

        @param message: Custom text to include in the exception text if the
            assertion fails.
        """
        assert isinstance(instance, classOrTuple)

    def failUnlessIn(self, containee, container, msg=None):
        """
        Fail the test if :py:data:`containee` is not found in
        :py:data:`container`.

        :param containee: the value that should be in :py:class:`container`
        :param container: a sequence type, or in the case of a mapping type,
                          will follow semantics of 'if key in dict.keys()'
        :param msg: if msg is None, then the failure message will be
                    '%r not in %r' % (first, second)
        """
        assert containee in container
    assertIn = failUnlessIn

    def assertNotIn(self, containee, container, msg=None):
        """
        Fail the test if C{containee} is found in C{container}.

        @param containee: the value that should not be in C{container}
        @param container: a sequence type, or in the case of a mapping type,
                          will follow semantics of 'if key in dict.keys()'
        @param msg: if msg is None, then the failure message will be
                    '%r in %r' % (first, second)
        """
        assert containee not in container
    failIfIn = assertNotIn

    def assertIs(self, first, second, msg=None):
        """
        Fail the test if :py:data:`first` is not :py:data:`second`.  This is an
        obect-identity-equality test, not an object equality
        (i.e. :py:func:`__eq__`) test.

        :param msg: if msg is None, then the failure message will be
        '%r is not %r' % (first, second)
        """
        assert first is second
    assertIdentical = failUnlessIdentical = assertIs

    def assertIsNot(self, first, second, msg=None):
        """
        Fail the test if :py:data:`first` is :py:data:`second`.  This is an
        obect-identity-equality test, not an object equality
        (i.e. :py:func:`__eq__`) test.

        :param msg: if msg is None, then the failure message will be
        '%r is %r' % (first, second)
        """
        assert first is not second
    assertNotIdentical = failIfIdentical = assertIsNot

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
        with pytest.raises(exception) as cm:
            f(*args, **kwargs)
        return cm.value
    assertRaises = failUnlessRaises

    def mktemp(self):
        """
        Return UTF-8-encoded bytes of a path to a tmp file.

        The file will be cleaned up after the test run.
        """
        return mktemp(dir=self.tmpdir).encode("utf-8")

    # Other stuff
    def assertConsistentType(self, theType, name, *constructionArgs):
        """
        Perform various assertions about :py:data:`theType` to ensure that it
        is a well-defined type.  This is useful for extension types, where it's
        pretty easy to do something wacky.  If something about the type is
        unusual, an exception will be raised.

        :param theType: The type object about which to make assertions.
        :param name: A string giving the name of the type.
        :param constructionArgs: Positional arguments to use with
            :py:data:`theType` to create an instance of it.
        """
        self.assertEqual(theType.__name__, name)
        self.assertTrue(isinstance(theType, type))
        instance = theType(*constructionArgs)
        self.assertIdentical(type(instance), theType)


class EqualityTestsMixin(object):
    """
    A mixin defining tests for the standard implementation of C{==} and C{!=}.
    """

    def anInstance(self):
        """
        Return an instance of the class under test.  Each call to this method
        must return a different object.  All objects returned must be equal to
        each other.
        """
        raise NotImplementedError()

    def anotherInstance(self):
        """
        Return an instance of the class under test.  Each call to this method
        must return a different object.  The objects must not be equal to the
        objects returned by C{anInstance}.  They may or may not be equal to
        each other (they will not be compared against each other).
        """
        raise NotImplementedError()

    def test_identicalEq(self):
        """
        An object compares equal to itself using the C{==} operator.
        """
        o = self.anInstance()
        self.assertTrue(o == o)

    def test_identicalNe(self):
        """
        An object doesn't compare not equal to itself using the C{!=} operator.
        """
        o = self.anInstance()
        self.assertFalse(o != o)

    def test_sameEq(self):
        """
        Two objects that are equal to each other compare equal to each other
        using the C{==} operator.
        """
        a = self.anInstance()
        b = self.anInstance()
        self.assertTrue(a == b)

    def test_sameNe(self):
        """
        Two objects that are equal to each other do not compare not equal to
        each other using the C{!=} operator.
        """
        a = self.anInstance()
        b = self.anInstance()
        self.assertFalse(a != b)

    def test_differentEq(self):
        """
        Two objects that are not equal to each other do not compare equal to
        each other using the C{==} operator.
        """
        a = self.anInstance()
        b = self.anotherInstance()
        self.assertFalse(a == b)

    def test_differentNe(self):
        """
        Two objects that are not equal to each other compare not equal to each
        other using the C{!=} operator.
        """
        a = self.anInstance()
        b = self.anotherInstance()
        self.assertTrue(a != b)

    def test_anotherTypeEq(self):
        """
        The object does not compare equal to an object of an unrelated type
        (which does not implement the comparison) using the C{==} operator.
        """
        a = self.anInstance()
        b = object()
        self.assertFalse(a == b)

    def test_anotherTypeNe(self):
        """
        The object compares not equal to an object of an unrelated type (which
        does not implement the comparison) using the C{!=} operator.
        """
        a = self.anInstance()
        b = object()
        self.assertTrue(a != b)

    def test_delegatedEq(self):
        """
        The result of comparison using C{==} is delegated to the right-hand
        operand if it is of an unrelated type.
        """
        class Delegate(object):
            def __eq__(self, other):
                # Do something crazy and obvious.
                return [self]

        a = self.anInstance()
        b = Delegate()
        self.assertEqual(a == b, [b])

    def test_delegateNe(self):
        """
        The result of comparison using C{!=} is delegated to the right-hand
        operand if it is of an unrelated type.
        """
        class Delegate(object):
            def __ne__(self, other):
                # Do something crazy and obvious.
                return [self]

        a = self.anInstance()
        b = Delegate()
        self.assertEqual(a != b, [b])


# The type name expected in warnings about using the wrong string type.
if PY3:
    WARNING_TYPE_EXPECTED = "str"
else:
    WARNING_TYPE_EXPECTED = "unicode"
