/*
 * netscape_spki.c
 *
 * Copyright (C) Tollef Fog Heen 2003
 *
 * Netscape SPKI handling, thin wrapper
 */
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

/*
 * Constructor for Nestcape_SPKI, never called by Python code directly
 *
 * Arguments: name    - A "real" NetscapeSPKI object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" NetscapeSPKI object
 * Returns:   The newly created NetscapeSPKI object
 */
crypto_NetscapeSPKIObj *
crypto_NetscapeSPKI_New(NETSCAPE_SPKI *name, int dealloc)
{
    crypto_NetscapeSPKIObj *self;

    self = PyObject_New(crypto_NetscapeSPKIObj, &crypto_NetscapeSPKI_Type);

    if (self == NULL)
        return NULL;

    self->netscape_spki = name;
    self->dealloc = dealloc;

    return self;
}

/*
 * Deallocate the memory used by the NetscapeSPKI object
 *
 * Arguments: self - The NetscapeSPKI object
 * Returns:   None
 */
static void
crypto_NetscapeSPKI_dealloc(crypto_NetscapeSPKIObj *self)
{
    /* Sometimes we don't have to dealloc this */
    if (self->dealloc)
        NETSCAPE_SPKI_free(self->netscape_spki);

    PyObject_Del(self);
}

static char crypto_NetscapeSPKI_sign_doc[] = "\n\
Sign the certificate request using the supplied key and digest\n\
\n\
Arguments: self - The NetscapeSPKI object\n\
           args - The Python argument tuple, should be:\n\
             pkey   - The key to sign with\n\
             digest - The message digest to use\n\
Returns:   None\n\
";

static PyObject *
crypto_NetscapeSPKI_sign(crypto_NetscapeSPKIObj *self, PyObject *args)
{
    crypto_PKeyObj *pkey;
    char *digest_name;
    const EVP_MD *digest;

    if (!PyArg_ParseTuple(args, "O!s:sign", &crypto_PKey_Type, &pkey,
			  &digest_name))
        return NULL;

    if ((digest = EVP_get_digestbyname(digest_name)) == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "No such digest method");
        return NULL;
    }

    if (!NETSCAPE_SPKI_sign(self->netscape_spki, pkey->pkey, digest))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_NetscapeSPKI_verify_doc[] = "\n\
Verifies a certificate request using the supplied public key\n\
 \n\
Arguments: self - NetscapeSPKI object\n\
           args - The Python argument tuple, should be:\n\
             key - a public key\n\
Returns:   True, if the signature is correct, 0 otherwise.\n\
";

PyObject *
crypto_NetscapeSPKI_verify(crypto_NetscapeSPKIObj *self, PyObject *args)
{
    crypto_PKeyObj *pkey;
    int answer;

    if (!PyArg_ParseTuple(args, "O!:verify", &crypto_PKey_Type, &pkey)) 
        return NULL;

    if ((answer = NETSCAPE_SPKI_verify(self->netscape_spki, pkey->pkey)) < 0)
    {
        exception_from_error_queue();
        return NULL;
    }

    return PyInt_FromLong((long)answer);
}

static char crypto_NetscapeSPKI_b64_encode_doc[] = "\n\
Generate a base64 encoded string from an SPKI\n\
 \n\
Arguments: self - NetscapeSPKI object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The base64 encoded string\n\
";

PyObject *
crypto_NetscapeSPKI_b64_encode(crypto_NetscapeSPKIObj *self, PyObject *args)
{
    char *str;

    if (!PyArg_ParseTuple(args, ":b64_encode"))
        return NULL;

    str = NETSCAPE_SPKI_b64_encode(self->netscape_spki);
    return PyString_FromString(str);
}


static char crypto_NetscapeSPKI_get_pubkey_doc[] = "\n\
Get the public key of the certificate\n\
\n\
Arguments: self - The NETSCAPE_SPKI object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The public key\n\
";

static PyObject *
crypto_NetscapeSPKI_get_pubkey(crypto_NetscapeSPKIObj *self, PyObject *args)
{
    crypto_PKeyObj *crypto_PKey_New(EVP_PKEY *, int);
    EVP_PKEY *pkey;

    if (!PyArg_ParseTuple(args, ":get_pubkey"))
        return NULL;

    if ((pkey = NETSCAPE_SPKI_get_pubkey(self->netscape_spki)) == NULL)
    {
        exception_from_error_queue();
        return NULL;
    }

    return (PyObject *)crypto_PKey_New(pkey, 0);
}

static char crypto_NetscapeSPKI_set_pubkey_doc[] = "\n\
Set the public key of the certificate\n\
\n\
Arguments: self - The Netscape SPKI object\n\
           args - The Python argument tuple, should be:\n\
             pkey - The public key\n\
Returns:   None\n\
";

static PyObject *
crypto_NetscapeSPKI_set_pubkey(crypto_NetscapeSPKIObj *self, PyObject *args)
{
    crypto_PKeyObj *pkey;

    if (!PyArg_ParseTuple(args, "O!:set_pubkey", &crypto_PKey_Type, &pkey))
        return NULL;

    if (!NETSCAPE_SPKI_set_pubkey(self->netscape_spki, pkey->pkey))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_NetscapeSPKI_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_NetscapeSPKI_##name, METH_VARARGS, crypto_NetscapeSPKI_##name##_doc }
static PyMethodDef crypto_NetscapeSPKI_methods[] =
{
    ADD_METHOD(get_pubkey),
    ADD_METHOD(set_pubkey),
    ADD_METHOD(b64_encode),
    ADD_METHOD(sign),
    ADD_METHOD(verify),
    { NULL, NULL }
};
#undef ADD_METHOD

/*
 * Find attribute
 *
 * Arguments: self - The NetscapeSPKI object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_NetscapeSPKI_getattr(crypto_NetscapeSPKIObj *self, char *name)
{
    return Py_FindMethod(crypto_NetscapeSPKI_methods, (PyObject *)self, name);
}

PyTypeObject crypto_NetscapeSPKI_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "NetscapeSPKI",
    sizeof(crypto_NetscapeSPKIObj),
    0,
    (destructor)crypto_NetscapeSPKI_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_NetscapeSPKI_getattr,
    NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL  /* hash */
};


/*
 * Initialize the X509Name part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_netscape_spki(PyObject *dict)
{
    crypto_NetscapeSPKI_Type.ob_type = &PyType_Type;
    Py_INCREF(&crypto_NetscapeSPKI_Type);
    PyDict_SetItemString(dict, "NetscapeSPKIType", (PyObject *)&crypto_NetscapeSPKI_Type);
    return 1;
}
