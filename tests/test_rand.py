# Copyright (c) Frederick Dean
# See LICENSE for details.

"""
Unit tests for `OpenSSL.rand`.
"""

import os
import stat
import sys

import pytest

from OpenSSL import rand

from .util import NON_ASCII


class TestRand(object):

    @pytest.mark.parametrize('args', [
        (),
        (None),
        (3, None)
    ])
    def test_bytes_wrong_args(self, args):
        """
        `OpenSSL.rand.bytes` raises `TypeError` if called with
        the wrong number of arguments or with a non-`int` argument.
        """
        with pytest.raises(TypeError):
            rand.bytes(*args)

    def test_insufficient_memory(self):
        """
        `OpenSSL.rand.bytes` raises `MemoryError` if more bytes
        are requested than will fit in memory.
        """
        with pytest.raises(MemoryError):
            rand.bytes(sys.maxsize)

    def test_bytes(self):
        """
        Verify that we can obtain bytes from rand_bytes() and
        that they are different each time.  Test the parameter
        of rand_bytes() for bad values.
        """
        b1 = rand.bytes(50)
        assert len(b1) == 50
        b2 = rand.bytes(num_bytes=50)  # parameter by name
        assert b1 != b2  # Hip, Hip, Horay! FIPS complaince
        b3 = rand.bytes(num_bytes=0)
        assert len(b3) == 0
        with pytest.raises(ValueError) as exc:
            rand.bytes(-1)
        assert str(exc.value) == "num_bytes must not be negative"

    @pytest.mark.parametrize('args', [
        (),
        (b"foo", None),
        (None, 3),
        (b"foo", 3, None),
    ])
    def test_add_wrong_args(self, args):
        """
        When called with the wrong number of arguments, or with arguments not
        of type `str` and `int`, `OpenSSL.rand.add`
        raises `TypeError`.
        """
        with pytest.raises(TypeError):
            rand.add(*args)

    def test_add(self):
        """
        `OpenSSL.rand.add` adds entropy to the PRNG.
        """
        rand.add(b'hamburger', 3)

    @pytest.mark.parametrize('args', [
        (),
        (None),
        (b"foo", None),
    ])
    def test_seed_wrong_args(self, args):
        """
        When called with the wrong number of arguments, or with
        a non-`str` argument, `OpenSSL.rand.seed` raises
        `TypeError`.
        """
        with pytest.raises(TypeError):
            rand.seed(*args)

    def test_seed(self):
        """
        `OpenSSL.rand.seed` adds entropy to the PRNG.
        """
        rand.seed(b'milk shake')

    def test_status_wrong_args(self):
        """
        `OpenSSL.rand.status` raises `TypeError` when called
        with any arguments.
        """
        with pytest.raises(TypeError):
            rand.status(None)

    def test_status(self):
        """
        `OpenSSL.rand.status` returns `True` if the PRNG has
        sufficient entropy, `False` otherwise.
        """
        # It's hard to know what it is actually going to return.  Different
        # OpenSSL random engines decide differently whether they have enough
        # entropy or not.
        assert rand.status() in (True, False)

    @pytest.mark.parametrize('args', [
        (b"foo", 255),
        (b"foo",),
    ])
    def test_egd_warning(self, args):
        """
        Calling egd raises :exc:`DeprecationWarning`.
        """
        pytest.deprecated_call(rand.egd, *args)

    @pytest.mark.parametrize('args', [
        (),
        (None,),
        ("foo", None),
        (None, 3),
        ("foo", 3, None),
    ])
    def test_egd_wrong_args(self, args):
        """
        :meth:`OpenSSL.rand.egd` raises :exc:`TypeError` when called with the
        wrong number of arguments or with arguments not of type :obj:`str` and
        :obj:`int`.
        """
        with pytest.raises(TypeError):
            rand.egd(*args)

    def test_cleanup_wrong_args(self):
        """
        `OpenSSL.rand.cleanup` raises `TypeError` when called
        with any arguments.
        """
        with pytest.raises(TypeError):
            rand.cleanup(None)

    def test_cleanup(self):
        """
        `OpenSSL.rand.cleanup` releases the memory used by the PRNG and
        returns `None`.
        """
        assert rand.cleanup() is None

    @pytest.mark.parametrize('args', [
        (),
        ("foo", None),
        (None, 1),
        ("foo", 1, None),
    ])
    def test_load_file_wrong_args(self, args):
        """
        `OpenSSL.rand.load_file` raises `TypeError` when called
        the wrong number of arguments or arguments not of type `str`
        and `int`.
        """
        with pytest.raises(TypeError):
            rand.load_file(*args)

    @pytest.mark.parametrize('args', [
        (),
        (None),
        ("foo", None),
    ])
    def test_write_file_wrong_args(self, args):
        """
        `OpenSSL.rand.write_file` raises `TypeError` when
        called with the wrong number of arguments or a non-`str`
        argument.
        """
        with pytest.raises(TypeError):
            rand.write_file(*args)

    def _read_write_test(self, path):
        """
        Verify that ``rand.write_file`` and ``rand.load_file`` can be used.
        """
        # Create the file so cleanup is more straightforward
        with open(path, "w"):
            pass

        try:
            # Write random bytes to a file
            rand.write_file(path)

            # Verify length of written file
            size = os.stat(path)[stat.ST_SIZE]
            assert size == 1024

            # Read random bytes from file
            rand.load_file(path)
            rand.load_file(path, 4)  # specify a length
        finally:
            # Cleanup
            os.unlink(path)

    def test_bytes_paths(self, tmpfile):
        """
        Random data can be saved and loaded to files with paths specified as
        bytes.
        """
        path = tmpfile
        path += NON_ASCII.encode(sys.getfilesystemencoding())
        self._read_write_test(path)

    def test_unicode_paths(self, tmpfile):
        """
        Random data can be saved and loaded to files with paths specified as
        unicode.
        """
        path = tmpfile.decode('utf-8') + NON_ASCII
        self._read_write_test(path)
