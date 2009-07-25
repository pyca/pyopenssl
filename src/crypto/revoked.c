#include <Python.h>
#define crypto_MODULE
#include "crypto.h"


static char crypto_Revoked_get_rev_date_doc[] = "\n\
Retrieve the revocation date\n\
\n\
@return: A string giving the timestamp, in the format:\n\
\n\
                 YYYYMMDDhhmmssZ\n\
                 YYYYMMDDhhmmss+hhmm\n\
                 YYYYMMDDhhmmss-hhmm\n\
";

static PyObject*
crypto_Revoked_get_rev_date(crypto_RevokedObj *self, PyObject *args)
{
	/* returns a borrowed reference.  */
	return _get_asn1_time(
		":get_rev_date", self->revoked->revocationDate, args);
}

static char crypto_Revoked_set_rev_date_doc[] = "\n\
Set the revocation timestamp\n\
\n\
@param when: A string giving the timestamp, in the format:\n\
\n\
                 YYYYMMDDhhmmssZ\n\
                 YYYYMMDDhhmmss+hhmm\n\
                 YYYYMMDDhhmmss-hhmm\n\
\n\
@return: None\n\
";

static PyObject*
crypto_Revoked_set_rev_date(crypto_RevokedObj *self, PyObject *args)
{
	return _set_asn1_time(
		"s:set_rev_date", self->revoked->revocationDate, args);
}


static PyObject *
ASN1_INTEGER_to_PyString(ASN1_INTEGER *asn1_int)
{
    BIO *bio = NULL;
    PyObject *buf = NULL;
    int ret, pending;

    /* Create a openssl BIO buffer */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        goto err;

    /* Write the integer to the BIO as a hex string. */
    i2a_ASN1_INTEGER(bio, asn1_int);

    /* Allocate a Python string. */
    pending = BIO_pending(bio);
    buf = PyString_FromStringAndSize(NULL, pending);
    if (buf == NULL) {
        goto err;
    }

    /* Copy the BIO contents to a Python string. */
    ret = BIO_read(bio, PyString_AsString(buf), pending);
    if (ret <= 0) { /* problem with BIO_read */
        goto err;
    }

    /* Cleanup */
    BIO_free(bio);
    bio = NULL;
    return buf;

 err:
    if(bio) {
        BIO_free(bio);
    }
    if(buf) {
        Py_DECREF(buf);
    }
    return NULL;
}


static char crypto_Revoked_get_serial_doc[] = "\n\
Return the serial number of a Revoked structure\n\
\n\
@return: The serial number as a string\n\
";
static PyObject *
crypto_Revoked_get_serial(crypto_RevokedObj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_serial"))
        return NULL;

    if(self->revoked->serialNumber == NULL) {
        /* never happens */
        Py_INCREF(Py_None);
        return Py_None;
    } else {
        return ASN1_INTEGER_to_PyString(self->revoked->serialNumber);
    }
}

static char crypto_Revoked_set_serial_doc[] = "\n\
Set the serial number of a revoked Revoked structure\n\
\n\
@param hex_str: The new serial number.\n\
@type hex_str: L{str}\n\
@return: None\n\
";
static PyObject *
crypto_Revoked_set_serial(crypto_RevokedObj *self, PyObject *args, PyObject *keywds)
{
    static char *kwlist[] = {"hex_str", NULL};
    const char *hex_str = NULL;
    BIGNUM *serial = NULL;
    ASN1_INTEGER *tmpser = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s:set_serial", 
        kwlist, &hex_str))
        return NULL;

    if( ! BN_hex2bn(&serial, hex_str) ) {
        PyErr_SetString(PyExc_TypeError, "bad hex string");
        return NULL;
    }

    tmpser = BN_to_ASN1_INTEGER(serial, NULL);
    BN_free(serial);
    serial = NULL;
    X509_REVOKED_set_serialNumber(self->revoked, tmpser);
    ASN1_INTEGER_free(tmpser);

    Py_INCREF(Py_None);
    return Py_None;
}


crypto_RevokedObj *
crypto_Revoked_New(X509_REVOKED *revoked)
{
    crypto_RevokedObj *self;

    self = PyObject_New(crypto_RevokedObj, &crypto_Revoked_Type);
    if (self==NULL)
	    return NULL;
    self->revoked = revoked;
    return self;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_Revoked_name, METH_VARARGS, crypto_Revoked_name_doc }
 * for convenience
 */
#define ADD_METHOD(name)        \
    { #name, (PyCFunction)crypto_Revoked_##name, METH_VARARGS, crypto_Revoked_##name##_doc }
#define ADD_KW_METHOD(name)        \
    { #name, (PyCFunction)crypto_Revoked_##name, METH_VARARGS | METH_KEYWORDS, crypto_Revoked_##name##_doc }
static PyMethodDef crypto_Revoked_methods[] =
{
    ADD_METHOD(get_rev_date),
    ADD_METHOD(set_rev_date),
    ADD_METHOD(get_serial),
    ADD_KW_METHOD(set_serial),
    { NULL, NULL }
};
#undef ADD_METHOD


static PyObject *
crypto_Revoked_getattr(crypto_RevokedObj *self, char *name)
{
    return Py_FindMethod(crypto_Revoked_methods, (PyObject *)self, name);
}

static void
crypto_Revoked_dealloc(crypto_RevokedObj *self)
{
    X509_REVOKED_free(self->revoked);
    self->revoked = NULL;

    PyObject_Del(self);
}

static char crypto_Revoked_doc[] = "\n\
Revoked() -> Revoked instance\n\
\n\
Create a new empty Revoked object.\n\
\n\
@returns: The Revoked object\n\
";

static PyObject* crypto_Revoked_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
    	if (!PyArg_ParseTuple(args, ":Revoked")) {
		return NULL;
    	}
	
    	return (PyObject *)crypto_Revoked_New(X509_REVOKED_new());
}

PyTypeObject crypto_Revoked_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Revoked",
    sizeof(crypto_RevokedObj),
    0,
    (destructor)crypto_Revoked_dealloc,
    NULL, /* print */
    (getattrfunc)crypto_Revoked_getattr,
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
    Py_TPFLAGS_DEFAULT,
    crypto_Revoked_doc, /* doc */
    NULL, /* traverse */
    NULL, /* clear */
    NULL, /* tp_richcompare */
    0, /* tp_weaklistoffset */
    NULL, /* tp_iter */
    NULL, /* tp_iternext */
    crypto_Revoked_methods, /* tp_methods */
    NULL, /* tp_members */
    NULL, /* tp_getset */
    NULL, /* tp_base */
    NULL, /* tp_dict */
    NULL, /* tp_descr_get */
    NULL, /* tp_descr_set */
    0, /* tp_dictoffset */
    NULL, /* tp_init */
    NULL, /* tp_alloc */
    crypto_Revoked_new, /* tp_new */
};

int init_crypto_revoked(PyObject *module) {
       if(PyType_Ready(&crypto_Revoked_Type) < 0) {
       	       return 0;
       }
    
       if (PyModule_AddObject(module, "Revoked", (PyObject *)&crypto_Revoked_Type) != 0) {
       	       return 0;
       }
       return 1;
}

