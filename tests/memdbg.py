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

import sys
sys.modules['ssl'] = None
sys.modules['_hashlib'] = None


import traceback

from cffi import api as _api
_ffi = _api.FFI()
_ffi.cdef(
    """
    void *malloc(size_t size);
    void free(void *ptr);
    void *realloc(void *ptr, size_t size);

    int  CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));

    int backtrace(void **buffer, int size);
    char **backtrace_symbols(void *const *buffer, int size);
    void backtrace_symbols_fd(void *const *buffer, int size, int fd);
    """)  # noqa
_api = _ffi.verify(
    """
    #include <openssl/crypto.h>
    #include <stdlib.h>
    #include <execinfo.h>
    """, libraries=["crypto"])
C = _ffi.dlopen(None)

verbose = False


def log(s):
    if verbose:
        print(s)


def _backtrace():
    buf = _ffi.new("void*[]", 64)
    result = _api.backtrace(buf, len(buf))
    strings = _api.backtrace_symbols(buf, result)
    stack = [_ffi.string(strings[i]) for i in range(result)]
    C.free(strings)
    return stack


@_ffi.callback("void*(*)(size_t)")
def malloc(n):
    memory = C.malloc(n)
    python_stack = traceback.extract_stack(limit=3)
    c_stack = _backtrace()
    heap[memory] = [(n, python_stack, c_stack)]
    log("malloc(%d) -> %s" % (n, memory))
    return memory


@_ffi.callback("void*(*)(void*, size_t)")
def realloc(p, n):
    memory = C.realloc(p, n)
    old = heap.pop(p)

    python_stack = traceback.extract_stack(limit=3)
    c_stack = _backtrace()

    old.append((n, python_stack, c_stack))
    heap[memory] = old
    log("realloc(0x%x, %d) -> %s" % (int(_ffi.cast("int", p)), n, memory))
    return memory


@_ffi.callback("void(*)(void*)")
def free(p):
    if p != _ffi.NULL:
        C.free(p)
        del heap[p]
        log("free(0x%x)" % (int(_ffi.cast("int", p)),))


if _api.CRYPTO_set_mem_functions(malloc, realloc, free):
    log('Enabled memory debugging')
    heap = {}
else:
    log('Failed to enable memory debugging')
    heap = None
