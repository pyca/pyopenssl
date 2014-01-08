from cryptography.hazmat.bindings.openssl.binding import Binding
binding = Binding()
ffi = binding.ffi
lib = binding.lib

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
