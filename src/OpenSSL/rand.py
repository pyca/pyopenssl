"""
PRNG management routines, thin wrappers.
"""

import warnings
from functools import partial

from six import integer_types as _integer_types

from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib,
    exception_from_error_queue as _exception_from_error_queue,
    path_string as _path_string)


warnings.warn(
    "OpenSSL.rand is deprecated - you should use os.urandom instead",
    DeprecationWarning, stacklevel=3
)


class Error(Exception):
    """
    An error occurred in an :mod:`OpenSSL.rand` API.

    If the current RAND method supports any errors, this is raised when needed.
    The default method does not raise this when the entropy pool is depleted.

    Whenever this exception is raised directly, it has a list of error messages
    from the OpenSSL error queue, where each item is a tuple *(lib, function,
    reason)*. Here *lib*, *function* and *reason* are all strings, describing
    where and what the problem is.

    See :manpage:`err(3)` for more information.
    """


_raise_current_error = partial(_exception_from_error_queue, Error)

_unspecified = object()

_builtin_bytes = bytes


def bytes(num_bytes):
    """
    Get some random bytes from the PRNG as a string.

    This is a wrapper for the C function ``RAND_bytes``.

    :param num_bytes: The number of bytes to fetch.

    :return: A string of random bytes.
    """
    if not isinstance(num_bytes, _integer_types):
        raise TypeError("num_bytes must be an integer")

    if num_bytes < 0:
        raise ValueError("num_bytes must not be negative")

    result_buffer = _ffi.new("unsigned char[]", num_bytes)
    result_code = _lib.RAND_bytes(result_buffer, num_bytes)
    if result_code == -1:
        # TODO: No tests for this code path.  Triggering a RAND_bytes failure
        # might involve supplying a custom ENGINE?  That's hard.
        _raise_current_error()

    return _ffi.buffer(result_buffer)[:]


def add(buffer, entropy):
    """
    Mix bytes from *string* into the PRNG state.

    The *entropy* argument is (the lower bound of) an estimate of how much
    randomness is contained in *string*, measured in bytes.

    For more information, see e.g. :rfc:`1750`.

    :param buffer: Buffer with random data.
    :param entropy: The entropy (in bytes) measurement of the buffer.

    :return: :obj:`None`
    """
    if not isinstance(buffer, _builtin_bytes):
        raise TypeError("buffer must be a byte string")

    if not isinstance(entropy, int):
        raise TypeError("entropy must be an integer")

    # TODO Nothing tests this call actually being made, or made properly.
    _lib.RAND_add(buffer, len(buffer), entropy)


def seed(buffer):
    """
    Equivalent to calling :func:`add` with *entropy* as the length of *buffer*.

    :param buffer: Buffer with random data

    :return: :obj:`None`
    """
    if not isinstance(buffer, _builtin_bytes):
        raise TypeError("buffer must be a byte string")

    # TODO Nothing tests this call actually being made, or made properly.
    _lib.RAND_seed(buffer, len(buffer))


def status():
    """
    Check whether the PRNG has been seeded with enough data.

    :return: 1 if the PRNG is seeded enough, 0 otherwise.
    """
    return _lib.RAND_status()


def cleanup():
    """
    Erase the memory used by the PRNG.

    This is a wrapper for the C function ``RAND_cleanup``.

    :return: :obj:`None`
    """
    # TODO Nothing tests this call actually being made, or made properly.
    _lib.RAND_cleanup()


def load_file(filename, maxbytes=_unspecified):
    """
    Read *maxbytes* of data from *filename* and seed the PRNG with it.

    Read the whole file if *maxbytes* is not specified or negative.

    :param filename: The file to read data from (``bytes`` or ``unicode``).
    :param maxbytes: (optional) The number of bytes to read.    Default is to
        read the entire file.

    :return: The number of bytes read
    """
    filename = _path_string(filename)

    if maxbytes is _unspecified:
        maxbytes = -1
    elif not isinstance(maxbytes, int):
        raise TypeError("maxbytes must be an integer")

    return _lib.RAND_load_file(filename, maxbytes)


def write_file(filename):
    """
    Write a number of random bytes (currently 1024) to the file *path*.  This
    file can then be used with :func:`load_file` to seed the PRNG again.

    :param filename: The file to write data to (``bytes`` or ``unicode``).

    :return: The number of bytes written.
    """
    filename = _path_string(filename)
    return _lib.RAND_write_file(filename)


# TODO There are no tests for the RAND strings being loaded, whatever that
# means.
_lib.ERR_load_RAND_strings()
