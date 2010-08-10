#ifndef PyOpenSSL_PY3K_H_
#define PyOpenSSL_PY3K_H_

#if (PY_VERSION_HEX >= 0x03000000)

#define PY3

#define PyOpenSSL_MODINIT(name)                 \
PyMODINIT_FUNC \
PyInit_##name(void)

#define PyText_FromString PyUnicode_FromString

#else /* (PY_VERSION_HEX >= 0x03000000) */

#define PyBytes_FromStringAndSize PyString_FromStringAndSize

#define PyLong_FromLong PyInt_FromLong

#define PyBytes_Size PyString_Size
#define PyBytes_Check PyString_Check
#define PyBytes_AsString PyString_AsString
#define PyBytes_FromStringAndSize PyString_FromStringAndSize

#define PyText_FromString PyString_FromString

#define PyOpenSSL_MODINIT(name)
void \
init##name(void)

#endif /* (PY_VERSION_HEX >= 0x03000000) */

#endif /* PyOpenSSL_PY3K_H_ */

