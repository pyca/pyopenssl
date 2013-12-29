from cryptography.hazmat.backends.openssl import backend
ffi = backend.ffi
lib = backend.lib

def exception_from_error_queue(exceptionType):
    errors = []
    while True:
        error = lib.ERR_get_error()
        if error == 0:
            break
        errors.append((
                ffi.string(lib.ERR_lib_error_string(error)),
                ffi.string(lib.ERR_func_error_string(error)),
                ffi.string(lib.ERR_reason_error_string(error))))

    raise exceptionType(errors)



def new_mem_buf(buffer=None):
    if buffer is None:
        bio = lib.BIO_new(lib.BIO_s_mem())
        free = lib.BIO_free
    else:
        data = ffi.new("char[]", buffer)
        bio = lib.BIO_new_mem_buf(data, len(buffer))
        # Keep the memory alive as long as the bio is alive!
        def free(bio, ref=data):
            return lib.BIO_free(bio)

    if bio == ffi.NULL:
        1/0

    bio = ffi.gc(bio, free)
    return bio
