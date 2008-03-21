/*
 * x509ext.c
 *
 * Copyright (C) Jean-Paul Calderone 2008, All rights reserved
 *
 * Export X.509 extension functions and data structures.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * @(#) $Id: x509ext.c,v 1.1 2002/07/09 13:34:46 martin Exp $
 */

#include <Python.h>
#define crypto_MODULE
#include "crypto.h"

static char crypto_X509Extension_get_critical_doc[] = "\n\
Returns the critical field of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The critical field.\n\
";

static PyObject *
crypto_X509Extension_get_critical(crypto_X509ExtensionObj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_critical"))
        return NULL;

    return PyInt_FromLong(X509_EXTENSION_get_critical(self->x509_extension));
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_X509Extension_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name)        \
{ #name, (PyCFunction)crypto_X509Extension_##name, METH_VARARGS, crypto_X509Extension_##name##_doc }
static PyMethodDef crypto_X509Extension_methods[] =
{
    ADD_METHOD(get_critical),
    { NULL, NULL }
};
#undef ADD_METHOD

/*
 * Constructor for X509Extension, never called by Python code directly
 *
 * Arguments: type_name - ???
 *            critical  - ???
 *            value     - ???
 * Returns:   The newly created X509Extension object
 */
crypto_X509ExtensionObj *
crypto_X509Extension_New(char *type_name, int critical, char *value)
{
    crypto_X509ExtensionObj *self;
    int ext_len, ext_nid;
    unsigned char *ext_der;
    X509V3_EXT_METHOD *ext_method = NULL;
    ASN1_OCTET_STRING *ext_oct;
    STACK_OF(CONF_VALUE) *nval;
    void * ext_struct;
    X509_EXTENSION *extension = NULL;

    self = PyObject_New(crypto_X509ExtensionObj, &crypto_X509Extension_Type);

    if (self == NULL)
        return NULL;

    /* Try to get a NID for the name */
    if ((ext_nid = OBJ_sn2nid(type_name)) == NID_undef)
    {
        PyErr_SetString(PyExc_ValueError, "Unknown extension name");
        return NULL;
    }

    /* Lookup the extension method structure */
    if (!(ext_method = X509V3_EXT_get_nid(ext_nid)))
    {
        PyErr_SetString(PyExc_ValueError, "Unknown extension");
        return NULL;
    }

    /* Look if it has a function to convert value to an 
     * internal structure.
     */
    if (!ext_method->v2i)
    {
        PyErr_SetString(PyExc_ValueError, "Can't initialize exception");
        return NULL;
    }

    /* Parse the value */
    nval = X509V3_parse_list(value);
    if (!nval)
    {
        PyErr_SetString(PyExc_ValueError, "Invalid extension string");
        return NULL;
    }

    /* And use it to get the internal structure */
    if(!(ext_struct = ext_method->v2i(ext_method, NULL, nval))) {
        exception_from_error_queue();
        return NULL;
    }

    /* Deallocate the configuration value stack */
    sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
        
    /* Find out how much memory we need */


    /* Convert internal representation to DER */
    /* and Allocate */
    if (ext_method->it) {
        ext_der = NULL;
        ext_len = ASN1_item_i2d(ext_struct, &ext_der, ASN1_ITEM_ptr(ext_method->it));
        if (ext_len < 0) {
            PyErr_SetString(PyExc_MemoryError, "Could not allocate memory");
            return NULL;
        }
    } else {
        unsigned char *p;
        ext_len = ext_method->i2d(ext_struct, NULL);
        if(!(ext_der = malloc(ext_len))) {
            PyErr_SetString(PyExc_MemoryError, "Could not allocate memory");
            return NULL;
        }
        p = ext_der;
        ext_method->i2d(ext_struct, &p);
    }

    /* And create the ASN1_OCTET_STRING */
    if(!(ext_oct = M_ASN1_OCTET_STRING_new())) {
        exception_from_error_queue();
        return NULL;
    }
        
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;

    /* Now that we got all ingredients, make the extension */
    extension = X509_EXTENSION_create_by_NID(NULL, ext_nid, critical, ext_oct);
    if (extension == NULL)
    {
        exception_from_error_queue();
        M_ASN1_OCTET_STRING_free(ext_oct);
        ext_method->ext_free(ext_struct);
        return NULL;
    }
    
    M_ASN1_OCTET_STRING_free(ext_oct);
    /* ext_method->ext_free(ext_struct); */

    self->x509_extension = extension;
    self->dealloc = 1;

    return self;
}

/*
 * Deallocate the memory used by the X509Extension object
 *
 * Arguments: self - The X509Extension object
 * Returns:   None
 */
static void
crypto_X509Extension_dealloc(crypto_X509ExtensionObj *self)
{
    /* Sometimes we don't have to dealloc this */
    if (self->dealloc)
        X509_EXTENSION_free(self->x509_extension);

    PyObject_Del(self);
}

/*
 * Find attribute
 *
 * Arguments: self - The X509Extension object
 *            name - The attribute name
 * Returns: A Python object for the attribute, or NULL if something
 *          went wrong.
 */       
static PyObject *
crypto_X509Extension_getattr(crypto_X509ExtensionObj *self, char *name)
{
    return Py_FindMethod(crypto_X509Extension_methods, (PyObject *)self, name);
}

/*
 * Print a nice text representation of the certificate request.
 */
static PyObject *
crypto_X509Extension_str(crypto_X509ExtensionObj *self)
{
    int str_len;
    char *tmp_str;
    PyObject *str;
    BIO *bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, self->x509_extension, 0, 0))
    {
        BIO_free(bio);
        exception_from_error_queue();
        return NULL;
    }

    str_len = BIO_get_mem_data(bio, &tmp_str);
    str = PyString_FromStringAndSize(tmp_str, str_len);

    BIO_free(bio);

    return str;
}

PyTypeObject crypto_X509Extension_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "X509Extension",
    sizeof(crypto_X509ExtensionObj),
    0,
    (destructor)crypto_X509Extension_dealloc, 
    NULL, /* print */
    (getattrfunc)crypto_X509Extension_getattr, 
    NULL, /* setattr  (setattrfunc)crypto_X509Name_setattr, */
    NULL, /* compare */
    NULL, /* repr */ 
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
    NULL, /* call */
    (reprfunc)crypto_X509Extension_str /* str */
};

/*
 * Initialize the X509Extension part of the crypto module
 *
 * Arguments: dict - The crypto module dictionary
 * Returns:   None
 */
int
init_crypto_x509extension(PyObject *dict)
{
    crypto_X509Extension_Type.ob_type = &PyType_Type;
    Py_INCREF(&crypto_X509Extension_Type);
    PyDict_SetItemString(dict, "X509ExtensionType",
            (PyObject *)&crypto_X509Extension_Type);
    return 1;
}

