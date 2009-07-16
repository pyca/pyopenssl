/*
 * pkcs12.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Certificate transport (PKCS12) handling code, 
 * mostly thin wrappers around OpenSSL.
 * See the file RATIONALE for a short explanation of why 
 * this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

/* 
 * PKCS12 is a standard exchange format for digital certificates.  
 * See e.g. the OpenSSL homepage http://www.openssl.org/ for more information
 */

static void crypto_PKCS12_dealloc(crypto_PKCS12Obj *self);

static char crypto_PKCS12_get_certificate_doc[] = "\n\
Return certificate portion of the PKCS12 structure\n\
\n\
@return: X509 object containing the certificate\n\
";
static PyObject *
crypto_PKCS12_get_certificate(crypto_PKCS12Obj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_certificate"))
        return NULL;

    Py_INCREF(self->cert);
    return self->cert;
}

static char crypto_PKCS12_get_privatekey_doc[] = "\n\
Return private key portion of the PKCS12 structure\n\
\n\
@returns: PKey object containing the private key\n\
";
static PyObject *
crypto_PKCS12_get_privatekey(crypto_PKCS12Obj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_privatekey"))
        return NULL;

    Py_INCREF(self->key);
    return self->key;
}

static char crypto_PKCS12_get_ca_certificates_doc[] = "\n\
Return CA certificates within of the PKCS12 object\n\
\n\
@return: A newly created tuple containing the CA certificates in the chain,\n\
         if any are present, or None if no CA certificates are present.\n\
";
static PyObject *
crypto_PKCS12_get_ca_certificates(crypto_PKCS12Obj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_ca_certificates"))
        return NULL;

    Py_INCREF(self->cacerts);
    return self->cacerts;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_PKCS12_name, METH_VARARGS, crypto_PKCS12_name_doc }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_PKCS12_##name, METH_VARARGS, crypto_PKCS12_##name##_doc }
static PyMethodDef crypto_PKCS12_methods[] =
{
    ADD_METHOD(get_certificate),
    ADD_METHOD(get_privatekey),
    ADD_METHOD(get_ca_certificates),
    { NULL, NULL }
};
#undef ADD_METHOD

/*
 * Constructor for PKCS12 objects, never called by Python code directly.
 * The strategy for this object is to create all the Python objects
 * corresponding to the cert/key/CA certs right away
 *
 * Arguments: p12        - A "real" PKCS12 object
 *            passphrase - Passphrase to use when decrypting the PKCS12 object
 * Returns:   The newly created PKCS12 object
 */
crypto_PKCS12Obj *
crypto_PKCS12_New(PKCS12 *p12, char *passphrase)
{
    crypto_PKCS12Obj *self;
    PyObject *cacertobj = NULL;

    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *cacerts = NULL;

    int i, cacert_count = 0;

    /* allocate space for the CA cert stack */
    cacerts = sk_X509_new_null();

    /* parse the PKCS12 lump */
    if (!(cacerts && PKCS12_parse(p12, passphrase, &pkey, &cert, &cacerts)))
    {
        exception_from_error_queue(crypto_Error);
        return NULL;
    }

    if (!(self = PyObject_GC_New(crypto_PKCS12Obj, &crypto_PKCS12_Type)))
        return NULL;

    self->cert = NULL;
    self->key = NULL;
    Py_INCREF(Py_None);
    self->cacerts = Py_None;

    if ((self->cert = (PyObject *)crypto_X509_New(cert, 1)) == NULL)
        goto error;

    if ((self->key = (PyObject *)crypto_PKey_New(pkey, 1)) == NULL)
        goto error;

    /* Make a tuple for the CA certs */
    cacert_count = sk_X509_num(cacerts);
    if (cacert_count > 0)
    {
        Py_DECREF(self->cacerts);
        if ((self->cacerts = PyTuple_New(cacert_count)) == NULL)
            goto error;

        for (i = 0; i < cacert_count; i++)
        {
            cert = sk_X509_value(cacerts, i);
            if ((cacertobj = (PyObject *)crypto_X509_New(cert, 1)) == NULL)
                goto error;
            PyTuple_SET_ITEM(self->cacerts, i, cacertobj);
        }
    }

    sk_X509_free(cacerts); /* don't free the certs, just the stack */
    PyObject_GC_Track(self);

    return self;
error:
    crypto_PKCS12_dealloc(self);
    return NULL;
}

/*
 * Find attribute
 *
 * Arguments: self - The PKCS12 object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_PKCS12_getattr(crypto_PKCS12Obj *self, char *name)
{
    return Py_FindMethod(crypto_PKCS12_methods, (PyObject *)self, name);
}

/*
 * Call the visitproc on all contained objects.
 *
 * Arguments: self - The PKCS12 object
 *            visit - Function to call
 *            arg - Extra argument to visit
 * Returns:   0 if all goes well, otherwise the return code from the first
 *            call that gave non-zero result.
 */
static int
crypto_PKCS12_traverse(crypto_PKCS12Obj *self, visitproc visit, void *arg)
{
    int ret = 0;

    if (ret == 0 && self->cert != NULL)
        ret = visit(self->cert, arg);
    if (ret == 0 && self->key != NULL)
        ret = visit(self->key, arg);
    if (ret == 0 && self->cacerts != NULL)
        ret = visit(self->cacerts, arg);
    return ret;
}

/*
 * Decref all contained objects and zero the pointers.
 *
 * Arguments: self - The PKCS12 object
 * Returns:   Always 0.
 */
static int
crypto_PKCS12_clear(crypto_PKCS12Obj *self)
{
    Py_XDECREF(self->cert);
    self->cert = NULL;
    Py_XDECREF(self->key);
    self->key = NULL;
    Py_XDECREF(self->cacerts);
    self->cacerts = NULL;
    return 0;
}

/*
 * Deallocate the memory used by the PKCS12 object
 *
 * Arguments: self - The PKCS12 object
 * Returns:   None
 */
static void
crypto_PKCS12_dealloc(crypto_PKCS12Obj *self)
{
    PyObject_GC_UnTrack(self);
    crypto_PKCS12_clear(self);
    PyObject_GC_Del(self);
}

PyTypeObject crypto_PKCS12_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "PKCS12",
    sizeof(crypto_PKCS12Obj),
    0,
    (destructor)crypto_PKCS12_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_PKCS12_getattr,
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
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    NULL, /* doc */
    (traverseproc)crypto_PKCS12_traverse,
    (inquiry)crypto_PKCS12_clear,
};

/*
 * Initialize the PKCS12 part of the crypto sub module
 *
 * Arguments: module - The crypto module
 * Returns:   None
 */
int
init_crypto_pkcs12(PyObject *module) {
    if (PyType_Ready(&crypto_PKCS12_Type) < 0) {
        return 0;
    }

    if (PyModule_AddObject(module, "PKCS12Type", (PyObject *)&crypto_PKCS12_Type) != 0) {
        return 0;
    }

    return 1;
}

