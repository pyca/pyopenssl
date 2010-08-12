#ifndef PyOpenSSL_PY3K_H_
#define PyOpenSSL_PY3K_H_

#if (PY_VERSION_HEX >= 0x03000000)

#define PY3

#define PyOpenSSL_MODINIT(name)                 \
PyMODINIT_FUNC \
PyInit_##name(void)

#define PyText_FromString PyUnicode_FromString
#define PyText_FromStringAndSize PyUnicode_FromStringAndSize

#else /* (PY_VERSION_HEX >= 0x03000000) */

#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(NULL) 0

#define PyBytes_FromStringAndSize PyString_FromStringAndSize

#define PyLong_FromLong PyInt_FromLong
#define PyLong_AsLong PyInt_AsLong
#define PyLong_Check(o) (PyInt_Check(o) || PyLong_Check(o))

#define PyBytes_Size PyString_Size
#define PyBytes_Check PyString_Check
#define PyBytes_CheckExact PyString_CheckExact
#define PyBytes_AsString PyString_AsString
#define PyBytes_FromStringAndSize PyString_FromStringAndSize

#define PyText_FromString PyString_FromString
#define PyText_FromStringAndSize PyString_FromStringAndSize

#define PyOpenSSL_MODINIT(name)
void \
init##name(void)

#endif /* (PY_VERSION_HEX >= 0x03000000) */

#endif /* PyOpenSSL_PY3K_H_ */

