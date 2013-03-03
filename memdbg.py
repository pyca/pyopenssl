
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
    """)
_api = _ffi.verify(
    """
    #include <openssl/crypto.h>
    #include <stdlib.h>
    #include <execinfo.h>
    """, libraries=["crypto"])
C = _ffi.dlopen(None)

heap = {}

def _backtrace():
    buf = _ffi.new("void*[]", 64)
    result = _api.backtrace(buf, len(buf))
    strings = _api.backtrace_symbols(buf, result)
    stack = [_ffi.string(strings[i]) for i in range(result)]
    C.free(strings)
    return stack


def _malloc(n):
    memory = C.malloc(n)
    python_stack = traceback.extract_stack(limit=3)
    c_stack = _backtrace()
    heap[memory] = [(n, python_stack, c_stack)]
    return memory
malloc = _ffi.callback("void*(*)(size_t)", _malloc)


@_ffi.callback("void*(*)(void*, size_t)")
def realloc(p, n):
    memory = C.realloc(p, n)
    old = heap.pop(p)

    python_stack = traceback.extract_stack(limit=3)
    c_stack = _backtrace()

    old.append((n, python_stack, c_stack))
    heap[memory] = old
    return memory


@_ffi.callback("void(*)(void*)")
def free(p):
    if p != _ffi.NULL:
        C.free(p)
        del heap[p]


if _api.CRYPTO_set_mem_functions(malloc, realloc, free):
    print 'Enabled memory debugging'
else:
    print 'Failed to enable memory debugging'
