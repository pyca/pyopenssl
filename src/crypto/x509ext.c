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

static char crypto_X509Extension_get_short_name_doc[] = "\n\
Returns the short version of the type name of the X509Extension\n\
\n\
Arguments: self - The X509Extension object\n\
           args - The argument tuple, should be empty\n\
Returns: The short type name.\n\
";

static PyObject *
crypto_X509Extension_get_short_name(crypto_X509ExtensionObj *self, PyObject *args) {
	ASN1_OBJECT *obj;
	const char *extname;

	if (!PyArg_ParseTuple(args, ":get_short_name")) {
		return NULL;
	}

	/* Returns an internal pointer to x509_extension, not a copy */
	obj = X509_EXTENSION_get_object(self->x509_extension);

	extname = OBJ_nid2sn(OBJ_obj2nid(obj));
	return PyString_FromString(extname);
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
    ADD_METHOD(get_short_name),
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
    X509V3_CTX ctx;
    crypto_X509ExtensionObj *self;
    char* value_with_critical = NULL;

    /* We have no configuration database - but perhaps we should.  Anyhow, the
     * context is necessary for any extension which uses the r2i conversion
     * method.  That is, X509V3_EXT_nconf may segfault if passed a NULL ctx. */
    X509V3_set_ctx_nodb(&ctx);

    self = PyObject_New(crypto_X509ExtensionObj, &crypto_X509Extension_Type);

    if (self == NULL) {
	    goto error;
    }

    self->dealloc = 0;

    /* There are other OpenSSL APIs which would let us pass in critical
     * separately, but they're harder to use, and since value is already a pile
     * of crappy junk smuggling a ton of utterly important structured data,
     * what's the point of trying to avoid nasty stuff with strings? (However,
     * X509V3_EXT_i2d in particular seems like it would be a better API to
     * invoke.  I do not know where to get the ext_struc it desires for its
     * last parameter, though.) */
    value_with_critical = malloc(strlen("critical,") + strlen(value) + 1);
    if (!value_with_critical) {
	    goto critical_malloc_error;
    }

    if (critical) {
	    strcpy(value_with_critical, "critical,");
	    strcpy(value_with_critical + strlen("critical,"), value);
    } else {
	    strcpy(value_with_critical, value);
    }

    self->x509_extension = X509V3_EXT_nconf(
	    NULL, &ctx, type_name, value_with_critical);

    free(value_with_critical);

    if (!self->x509_extension) {
	    goto nconf_error;
    }

    self->dealloc = 1;
    return self;

  nconf_error:
    exception_from_error_queue();

  critical_malloc_error:
    PyObject_Free(self);

  error:
    return NULL;

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

