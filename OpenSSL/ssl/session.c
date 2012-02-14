/*
 * session.c
 *
 * Copyright (C) Jean-Paul Calderone
 * Copyright (C) Alejandro Alvarez Ayllon
 * See LICENSE for details.
 *
 * SSL Session object data structures and functions.
 *
 */
#include <Python.h>
#define SSL_MODULE
#include "ssl.h"

static char ssl_Session_doc[] = "\n\
Session() -> Session instance\n\
\n\
";

/*
 * Initialize an already-constructed Session instance with an OpenSSL session
 * structure (or NULL).  A reference to the OpenSSL session structure is stolen.
 */
static ssl_SessionObj*
ssl_Session_init(ssl_SessionObj *self, SSL_SESSION *native_session) {
    self->session = native_session;
    return self;
}

/*
 * Create a Session object
 */
static PyObject*
ssl_Session_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
    ssl_SessionObj *self;

    if (!PyArg_ParseTuple(args, ":Session")) {
        return NULL;
    }

    self = PyObject_New(ssl_SessionObj, &ssl_Session_Type);
    if (self == NULL) {
        return NULL;
    }

    return (PyObject *)ssl_Session_init(self, NULL);
}

/*
 * Create a Session object from an existing SSL_SESSION*.  A reference to the
 * SSL_SESSION* is stolen.
 */
ssl_SessionObj*
ssl_Session_from_SSL_SESSION(SSL_SESSION *native_session) {
    ssl_SessionObj *self;

    self = PyObject_New(ssl_SessionObj, &ssl_Session_Type);
    if (self == NULL) {
        return NULL;
    }

    return ssl_Session_init(self, native_session);
}

/*
 * Discard the reference to the OpenSSL session structure, if there is one, so
 * that it can be freed if it is no longer in use.  Also release the memory for
 * the Python object.
 */
static void
ssl_Session_dealloc(ssl_SessionObj *self) {
    if (self->session != NULL) {
        SSL_SESSION_free(self->session);
        self->session = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/*
 * Member methods in the Session object
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)ssl_Session_name, METH_VARARGS }
 * for convenience
 * ADD_ALIAS(name,real) creates an "alias" of the ssl_Session_real
 * function with the name 'name'
 */
#define ADD_METHOD(name) { #name, (PyCFunction)ssl_Session_##name, METH_VARARGS, ssl_Session_##name##_doc }
static PyMethodDef ssl_Session_methods[] = {
    { NULL, NULL }
};
#undef ADD_METHOD

/*
 * The Python Session type definition.
 */
PyTypeObject ssl_Session_Type = {
    PyOpenSSL_HEAD_INIT(&PyType_Type, 0)
    "OpenSSL.SSL.Session",
    sizeof(ssl_SessionObj),
    0,
    (destructor)ssl_Session_dealloc, /* tp_dealloc */
    NULL, /* print */
    NULL, /* tp_getattr */
    NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
    NULL, /* call */
    NULL, /* str */
    NULL, /* getattro */
    NULL, /* setattro */
    NULL, /* as_buffer */
    Py_TPFLAGS_DEFAULT, // Py_TPFLAGS_HAVE_GC, /* tp_flags */
    ssl_Session_doc, /* tp_doc */
    NULL, // (traverseproc)ssl_Session_traverse, /* tp_traverse */
    NULL, // (inquiry)ssl_Session_clear, /* tp_clear */
    NULL, /* tp_richcompare */
    0, /* tp_weaklistoffset */
    NULL, /* tp_iter */
    NULL, /* tp_iternext */
    ssl_Session_methods, /* tp_methods */
    NULL, /* tp_members */
    NULL, /* tp_getset */
    NULL, /* tp_base */
    NULL, /* tp_dict */
    NULL, /* tp_descr_get */
    NULL, /* tp_descr_set */
    0, /* tp_dictoffset */
    NULL, /* tp_init */
    NULL, /* tp_alloc */
    ssl_Session_new, /* tp_new */
};

/*
 * Initialize the Session part of the SSL sub module
 *
 * Arguments: dict - The OpenSSL.SSL module
 * Returns:   1 for success, 0 otherwise
 */
int
init_ssl_session(PyObject *module) {

    if (PyType_Ready(&ssl_Session_Type) < 0) {
        return 0;
    }

    /* PyModule_AddObject steals a reference.
     */
    Py_INCREF((PyObject *)&ssl_Session_Type);
    if (PyModule_AddObject(module, "Session", (PyObject *)&ssl_Session_Type) < 0) {
        return 0;
    }

    return 1;
}

