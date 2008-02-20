/*
 * x509.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Certificate (X.509) handling code, mostly thin wrappers around OpenSSL.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

static char *CVSid = "@(#) $Id: x509.c,v 1.20 2004/08/10 10:37:31 martin Exp $";

/* 
 * X.509 is a standard for digital certificates.  See e.g. the OpenSSL homepage
 * http://www.openssl.org/ for more information
 */

static char crypto_X509_get_version_doc[] = "\n\
Return version number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Version number as a Python integer\n\
";

static PyObject *
crypto_X509_get_version(crypto_X509Obj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_version"))
        return NULL;

    return PyInt_FromLong((long)X509_get_version(self->x509));
}

static char crypto_X509_set_version_doc[] = "\n\
Set version number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             version - The version number\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_version(crypto_X509Obj *self, PyObject *args)
{
    int version;

    if (!PyArg_ParseTuple(args, "i:set_version", &version))
        return NULL;

    X509_set_version(self->x509, version);

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_get_serial_number_doc[] = "\n\
Return serial number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   Serial number as a Python integer\n\
";

static PyObject *
crypto_X509_get_serial_number(crypto_X509Obj *self, PyObject *args)
{
    ASN1_INTEGER *asn1_i;

    if (!PyArg_ParseTuple(args, ":get_serial_number"))
        return NULL;

    asn1_i = X509_get_serialNumber(self->x509);
    return PyInt_FromLong(ASN1_INTEGER_get(asn1_i));
}

static char crypto_X509_set_serial_number_doc[] = "\n\
Set serial number of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             serial - The serial number\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_serial_number(crypto_X509Obj *self, PyObject *args)
{
    long serial;

    if (!PyArg_ParseTuple(args, "l:set_serial_number", &serial))
        return NULL;

    ASN1_INTEGER_set(X509_get_serialNumber(self->x509), serial);

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_get_issuer_doc[] = "\n\
Create an X509Name object for the issuer of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   An X509Name object\n\
";

static PyObject *
crypto_X509_get_issuer(crypto_X509Obj *self, PyObject *args)
{
    crypto_X509NameObj *pyname;
    X509_NAME *name;

    if (!PyArg_ParseTuple(args, ":get_issuer"))
        return NULL;

    name = X509_get_issuer_name(self->x509);
    pyname = crypto_X509Name_New(name, 0);
    if (pyname != NULL)
    {
        pyname->parent_cert = (PyObject *)self;
        Py_INCREF(self);
    }
    return (PyObject *)pyname;
}

static char crypto_X509_set_issuer_doc[] = "\n\
Set the issuer of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             issuer - The issuer name\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_issuer(crypto_X509Obj *self, PyObject *args)
{
    crypto_X509NameObj *issuer;

    if (!PyArg_ParseTuple(args, "O!:set_issuer", &crypto_X509Name_Type,
			  &issuer))
        return NULL;

    if (!X509_set_issuer_name(self->x509, issuer->x509_name))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_get_subject_doc[] = "\n\
Create an X509Name object for the subject of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   An X509Name object\n\
";

static PyObject *
crypto_X509_get_subject(crypto_X509Obj *self, PyObject *args)
{
    crypto_X509NameObj *pyname;
    X509_NAME *name;

    if (!PyArg_ParseTuple(args, ":get_subject"))
        return NULL;

    name = X509_get_subject_name(self->x509);
    pyname = crypto_X509Name_New(name, 0);
    if (pyname != NULL)
    {
        pyname->parent_cert = (PyObject *)self;
        Py_INCREF(self);
    }
    return (PyObject *)pyname;
}

static char crypto_X509_set_subject_doc[] = "\n\
Set the subject of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             subject - The subject name\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_subject(crypto_X509Obj *self, PyObject *args)
{
    crypto_X509NameObj *subject;

    if (!PyArg_ParseTuple(args, "O!:set_subject", &crypto_X509Name_Type,
			  &subject))
        return NULL;

    if (!X509_set_subject_name(self->x509, subject->x509_name))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_get_pubkey_doc[] = "\n\
Get the public key of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The public key\n\
";

static PyObject *
crypto_X509_get_pubkey(crypto_X509Obj *self, PyObject *args)
{
    crypto_PKeyObj *crypto_PKey_New(EVP_PKEY *, int);
    EVP_PKEY *pkey;

    if (!PyArg_ParseTuple(args, ":get_pubkey"))
        return NULL;

    if ((pkey = X509_get_pubkey(self->x509)) == NULL)
    {
        exception_from_error_queue();
        return NULL;
    }

    return (PyObject *)crypto_PKey_New(pkey, 1);
}

static char crypto_X509_set_pubkey_doc[] = "\n\
Set the public key of the certificate\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             pkey - The public key\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_set_pubkey(crypto_X509Obj *self, PyObject *args)
{
    crypto_PKeyObj *pkey;

    if (!PyArg_ParseTuple(args, "O!:set_pubkey", &crypto_PKey_Type, &pkey))
        return NULL;

    if (!X509_set_pubkey(self->x509, pkey->pkey))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_gmtime_adj_notBefore_doc[] = "\n\
Adjust the time stamp for when the certificate starts being valid\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             i - The adjustment\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_gmtime_adj_notBefore(crypto_X509Obj *self, PyObject *args)
{
    long i;

    if (!PyArg_ParseTuple(args, "l:gmtime_adj_notBefore", &i))
        return NULL;

    X509_gmtime_adj(X509_get_notBefore(self->x509), i);

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_gmtime_adj_notAfter_doc[] = "\n\
Adjust the time stamp for when the certificate stops being valid\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             i - The adjustment\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_gmtime_adj_notAfter(crypto_X509Obj *self, PyObject *args)
{
    long i;

    if (!PyArg_ParseTuple(args, "l:gmtime_adj_notAfter", &i))
        return NULL;

    X509_gmtime_adj(X509_get_notAfter(self->x509), i);

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_sign_doc[] = "\n\
Sign the certificate using the supplied key and digest\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be:\n\
             pkey   - The key to sign with\n\
             digest - The message digest to use\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_sign(crypto_X509Obj *self, PyObject *args)
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

    if (!X509_sign(self->x509, pkey->pkey, digest))
    {
        exception_from_error_queue();
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static char crypto_X509_has_expired_doc[] = "\n\
Check whether the certificate has expired.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   True if the certificate has expired, false otherwise\n\
";

static PyObject *
crypto_X509_has_expired(crypto_X509Obj *self, PyObject *args)
{
    time_t tnow;

    if (!PyArg_ParseTuple(args, ":has_expired"))
        return NULL;

    tnow = time(NULL);
    if (ASN1_UTCTIME_cmp_time_t(X509_get_notAfter(self->x509), tnow) < 0)
        return PyInt_FromLong(1L);
    else
        return PyInt_FromLong(0L);
}

static char crypto_X509_subject_name_hash_doc[] = "\n\
Return the hash of the X509 subject.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The hash of the subject\n\
";

static PyObject *
crypto_X509_subject_name_hash(crypto_X509Obj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":subject_name_hash"))
        return NULL;

    return PyLong_FromLong(X509_subject_name_hash(self->x509));
}

static char crypto_X509_digest_doc[] = "\n\
Return the digest of the X509 object.\n\
\n\
Arguments: self - The X509 object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The digest of the object\n\
";

static PyObject *
crypto_X509_digest(crypto_X509Obj *self, PyObject *args)
{
    unsigned char fp[EVP_MAX_MD_SIZE];
    char *tmp;
    char *digest_name;
    int len,i;
    PyObject *ret;
    const EVP_MD *digest;

    if (!PyArg_ParseTuple(args, "s:digest", &digest_name))
        return NULL;

    if ((digest = EVP_get_digestbyname(digest_name)) == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "No such digest method");
        return NULL;
    }

    if (!X509_digest(self->x509,digest,fp,&len))
    {
        exception_from_error_queue();
    }
    tmp = malloc(3*len+1);
    memset(tmp, 0, 3*len+1);
    for (i = 0; i < len; i++) {
        sprintf(tmp+i*3,"%02X:",fp[i]);
    }
    tmp[3*len-1] = 0;
    ret = PyString_FromStringAndSize(tmp,3*len-1);
    free(tmp);
    return ret;
}


static char crypto_X509_add_extensions_doc[] = "\n\
Add extensions to the certificate.\n\
\n\
Arguments: self - X509 object\n\
           args - The Python argument tuple, should be:\n\
             extensions - a sequence of X509Extension objects\n\
Returns:   None\n\
";

static PyObject *
crypto_X509_add_extensions(crypto_X509Obj *self, PyObject *args)
{   
    PyObject *extensions, *seq;
    crypto_X509ExtensionObj *ext;
    int nr_of_extensions, i;

    if (!PyArg_ParseTuple(args, "O:add_extensions", &extensions))
        return NULL;

    seq = PySequence_Fast(extensions, "Expected a sequence");
    if (seq == NULL)
        return NULL;

    nr_of_extensions = PySequence_Fast_GET_SIZE(seq);

    for (i = 0; i < nr_of_extensions; i++)
    { 
        ext = (crypto_X509ExtensionObj *)PySequence_Fast_GET_ITEM(seq, i);
        if (!crypto_X509Extension_Check(ext))
        {   
            Py_DECREF(seq);
            PyErr_SetString(PyExc_ValueError,
                            "One of the elements is not an X509Extension");
            return NULL;
        }
        if (!X509_add_ext(self->x509, ext->x509_extension, -1))
        {
            Py_DECREF(seq);
            exception_from_error_queue();
            return NULL;
        }
    }

    Py_INCREF(Py_None);
    return Py_None;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_X509_##name, METH_VARARGS, crypto_X509_##name##_doc }
static PyMethodDef crypto_X509_methods[] =
{
    ADD_METHOD(get_version),
    ADD_METHOD(set_version),
    ADD_METHOD(get_serial_number),
    ADD_METHOD(set_serial_number),
    ADD_METHOD(get_issuer),
    ADD_METHOD(set_issuer),
    ADD_METHOD(get_subject),
    ADD_METHOD(set_subject),
    ADD_METHOD(get_pubkey),
    ADD_METHOD(set_pubkey),
    ADD_METHOD(gmtime_adj_notBefore),
    ADD_METHOD(gmtime_adj_notAfter),
    ADD_METHOD(sign),
    ADD_METHOD(has_expired),
    ADD_METHOD(subject_name_hash),
    ADD_METHOD(digest),
    ADD_METHOD(add_extensions),
    { NULL, NULL }
};
#undef ADD_METHOD


/*
 * Constructor for X509 objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" X509 certificate object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" X509 object
 * Returns:   The newly created X509 object
 */
crypto_X509Obj *
crypto_X509_New(X509 *cert, int dealloc)
{
    crypto_X509Obj *self;

    self = PyObject_New(crypto_X509Obj, &crypto_X509_Type);

    if (self == NULL)
        return NULL;

    self->x509 = cert;
    self->dealloc = dealloc;

    return self;
}

/*
 * Deallocate the memory used by the X509 object
 *
 * Arguments: self - The X509 object
 * Returns:   None
 */
static void
crypto_X509_dealloc(crypto_X509Obj *self)
{
    /* Sometimes we don't have to dealloc the "real" X509 pointer ourselves */
    if (self->dealloc)
        X509_free(self->x509);

    PyObject_Del(self);
}

/*
 * Find attribute
 *
 * Arguments: self - The X509 object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
crypto_X509_getattr(crypto_X509Obj *self, char *name)
{
    return Py_FindMethod(crypto_X509_methods, (PyObject *)self, name);
}

PyTypeObject crypto_X509_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "X509",
    sizeof(crypto_X509Obj),
    0,
    (destructor)crypto_X509_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_X509_getattr,
};

/*
 * Initialize the X509 part of the crypto sub module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509(PyObject *dict)
{
    crypto_X509_Type.ob_type = &PyType_Type;
    Py_INCREF(&crypto_X509_Type);
    PyDict_SetItemString(dict, "X509Type", (PyObject *)&crypto_X509_Type);
    return 1;
}

