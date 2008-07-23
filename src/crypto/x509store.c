/*
 * x509store.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * X.509 Store handling, mostly thin wrapping.
 * See the file RATIONALE for a short explanation of why this module was written.
 */
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

static char crypto_X509Store_add_cert_doc[] = "\n\
Add a certificate\n\
\n\
Arguments: self - The X509Store object\n\
           args - The Python argument tuple, should be:\n\
             cert - The certificate to add\n\
Returns:   None\n\
";

static PyObject *
crypto_X509Store_add_cert(crypto_X509StoreObj *self, PyObject *args)
{
    crypto_X509Obj *cert;

    if (!PyArg_ParseTuple(args, "O!:add_cert", &crypto_X509_Type, &cert))
        return NULL;

    if (!X509_STORE_add_cert(self->x509_store, cert->x509))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}


/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509Store_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_X509Store_##name, METH_VARARGS, crypto_X509Store_##name##_doc }
static PyMethodDef crypto_X509Store_methods[] =
{
    ADD_METHOD(add_cert),
    { NULL, NULL }
};
#undef ADD_METHOD


/*
 * Constructor for X509Store, never called by Python code directly
 *
 * Arguments: name    - A "real" X509_STORE object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" X509_STORE object
 * Returns:   The newly created X509Store object
 */
crypto_X509StoreObj *
crypto_X509Store_New(X509_STORE *store, int dealloc)
{
    crypto_X509StoreObj *self;

    self = PyObject_New(crypto_X509StoreObj, &crypto_X509Store_Type);

    if (self == NULL)
        return NULL;

    self->x509_store = store;
    self->dealloc = dealloc;

    return self;
}

/*
 * Deallocate the memory used by the X509Store object
 *
 * Arguments: self - The X509Store object
 * Returns:   None
 */
static void
crypto_X509Store_dealloc(crypto_X509StoreObj *self)
{
    /* Sometimes we don't have to dealloc this */
    if (self->dealloc)
        X509_STORE_free(self->x509_store);

    PyObject_Del(self);
}


/*
 * Find attribute.
 *
 * Arguments: self - The X509Store object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_X509Store_getattr(crypto_X509StoreObj *self, char *name)
{
    return Py_FindMethod(crypto_X509Store_methods, (PyObject *)self, name);
}

PyTypeObject crypto_X509Store_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "X509Store",
    sizeof(crypto_X509StoreObj),
    0,
    (destructor)crypto_X509Store_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_X509Store_getattr,
    NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL  /* hash */
};


/*
 * Initialize the X509Store part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509store(PyObject *dict)
{
    crypto_X509Store_Type.ob_type = &PyType_Type;
    Py_INCREF(&crypto_X509Store_Type);
    PyDict_SetItemString(dict, "X509StoreType", (PyObject *)&crypto_X509Store_Type);
    return 1;
}
