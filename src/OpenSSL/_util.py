# -*- coding: utf-8 -*-

# Copyright 2001 Martin Sjögren and pyOpenSSL contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from warnings import warn
import sys

from six import PY3, binary_type, text_type

from cryptography.hazmat.bindings.openssl.binding import Binding
binding = Binding()
binding.init_static_locks()
ffi = binding.ffi
lib = binding.lib


def text(charp):
    """
    Get a native string type representing of the given CFFI ``char*`` object.

    :param charp: A C-style string represented using CFFI.

    :return: :class:`str`
    """
    if not charp:
        return ""
    return native(ffi.string(charp))


def exception_from_error_queue(exception_type):
    """
    Convert an OpenSSL library failure into a Python exception.

    When a call to the native OpenSSL library fails, this is usually signalled
    by the return value, and an error code is stored in an error queue
    associated with the current thread. The err library provides functions to
    obtain these error codes and textual error messages.
    """

    errors = []

    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        errors.append((
            text(lib.ERR_lib_error_string(error)),
            text(lib.ERR_func_error_string(error)),
            text(lib.ERR_reason_error_string(error))))

    raise exception_type(errors)


def native(s):
    """
    Convert :py:class:`bytes` or :py:class:`unicode` to the native
    :py:class:`str` type, using UTF-8 encoding if conversion is necessary.

    :raise UnicodeError: The input string is not UTF-8 decodeable.

    :raise TypeError: The input is neither :py:class:`bytes` nor
        :py:class:`unicode`.
    """
    if not isinstance(s, (binary_type, text_type)):
        raise TypeError("%r is neither bytes nor unicode" % s)
    if PY3:
        if isinstance(s, binary_type):
            return s.decode("utf-8")
    else:
        if isinstance(s, text_type):
            return s.encode("utf-8")
    return s


def path_string(s):
    """
    Convert a Python string to a :py:class:`bytes` string identifying the same
    path and which can be passed into an OpenSSL API accepting a filename.

    :param s: An instance of :py:class:`bytes` or :py:class:`unicode`.

    :return: An instance of :py:class:`bytes`.
    """
    if isinstance(s, binary_type):
        return s
    elif isinstance(s, text_type):
        return s.encode(sys.getfilesystemencoding())
    else:
        raise TypeError("Path must be represented as bytes or unicode string")


if PY3:
    def byte_string(s):
        return s.encode("charmap")
else:
    def byte_string(s):
        return s


# A marker object to observe whether some optional arguments are passed any
# value or not.
UNSPECIFIED = object()

_TEXT_WARNING = (
    text_type.__name__ + " for {0} is no longer accepted, use bytes"
)


def text_to_bytes_and_warn(label, obj):
    """
    If ``obj`` is text, emit a warning that it should be bytes instead and try
    to convert it to bytes automatically.

    :param str label: The name of the parameter from which ``obj`` was taken
        (so a developer can easily find the source of the problem and correct
        it).

    :return: If ``obj`` is the text string type, a ``bytes`` object giving the
        UTF-8 encoding of that text is returned.  Otherwise, ``obj`` itself is
        returned.
    """
    if isinstance(obj, text_type):
        warn(
            _TEXT_WARNING.format(label),
            category=DeprecationWarning,
            stacklevel=3
        )
        return obj.encode('utf-8')
    return obj
