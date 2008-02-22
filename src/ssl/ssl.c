/*
 * ssl.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * Main file of the SSL sub module.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#define SSL_MODULE
#include "ssl.h"

static char ssl_doc[] = "\n\
Main file of the SSL sub module.\n\
See the file RATIONALE for a short explanation of hy this module was written.\n\
";

static char *CVSid = "@(#) $Id: ssl.c,v 1.12 2004/08/10 21:42:51 martin Exp $";

void **crypto_API;

/* Exceptions defined by the SSL submodule */
PyObject *ssl_Error,                   /* Base class              */
         *ssl_ZeroReturnError,         /* Used with SSL_get_error */
         *ssl_WantReadError,           /* ...                     */
         *ssl_WantWriteError,          /* ...                     */
         *ssl_WantX509LookupError,     /* ...                     */
         *ssl_SysCallError;            /* Uses (errno,errstr)     */

static char ssl_Context_doc[] = "\n\
The factory function inserted in the module dictionary to create Context\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             method - The SSL method to use\n\
Returns:   The Context object\n\
";

static PyObject *
ssl_Context(PyObject *spam, PyObject *args)
{
    int method;

    if (!PyArg_ParseTuple(args, "i:Context", &method))
        return NULL;

    return (PyObject *)ssl_Context_New(method);
}

static char ssl_Connection_doc[] = "\n\
The factory function inserted in the module dictionary to create Connection\n\
objects\n\
\n\
Arguments: spam - Always NULL\n\
           args - The Python argument tuple, should be:\n\
             ctx  - An SSL Context to use for this connection\n\
             sock - The socket to use for transport layer\n\
Returns:   The Connection object\n\
";

static PyObject *
ssl_Connection(PyObject *spam, PyObject *args)
{
    ssl_ContextObj *ctx;
    PyObject *sock;

    if (!PyArg_ParseTuple(args, "O!O:Connection", &ssl_Context_Type, &ctx, &sock))
        return NULL;

    return (PyObject *)ssl_Connection_New(ctx, sock);
}


/* Methods in the OpenSSL.SSL module */
static PyMethodDef ssl_methods[] = {
    { "Context",        ssl_Context,    METH_VARARGS, ssl_Context_doc },
    { "Connection",     ssl_Connection, METH_VARARGS, ssl_Connection_doc },
    { NULL, NULL }
};

/*
 * Initialize SSL sub module
 *
 * Arguments: None
 * Returns:   None
 */
void
initSSL(void)
{
    static void *ssl_API[ssl_API_pointers];
    PyObject *ssl_api_object;
    PyObject *module, *dict;

    SSL_library_init();
    ERR_load_SSL_strings();

    import_crypto();

    if ((module = Py_InitModule3("SSL", ssl_methods, ssl_doc)) == NULL)
        return;

    /* Initialize the C API pointer array */
    ssl_API[ssl_Context_New_NUM]    = (void *)ssl_Context_New;
    ssl_API[ssl_Connection_New_NUM] = (void *)ssl_Connection_New;
    ssl_api_object = PyCObject_FromVoidPtr((void *)ssl_API, NULL);
    if (ssl_api_object != NULL)
        PyModule_AddObject(module, "_C_API", ssl_api_object);

    /* Exceptions */
/*
 * ADD_EXCEPTION(dict,name,base) expands to a correct Exception declaration,
 * inserting OpenSSL.SSL.name into dict, derviving the exception from base.
 */
#define ADD_EXCEPTION(_name, _base)                                    \
do {                                                                          \
    ssl_##_name = PyErr_NewException("OpenSSL.SSL."#_name, _base, NULL);\
    if (ssl_##_name == NULL)                                            \
        goto error;                                                           \
    if (PyModule_AddObject(module, #_name, ssl_##_name) != 0)           \
        goto error;                                                           \
} while (0)

    ssl_Error = PyErr_NewException("OpenSSL.SSL.Error", NULL, NULL);
    if (ssl_Error == NULL)
        goto error;
    if (PyModule_AddObject(module, "Error", ssl_Error) != 0)
        goto error;

    ADD_EXCEPTION(ZeroReturnError,     ssl_Error);
    ADD_EXCEPTION(WantReadError,       ssl_Error);
    ADD_EXCEPTION(WantWriteError,      ssl_Error);
    ADD_EXCEPTION(WantX509LookupError, ssl_Error);
    ADD_EXCEPTION(SysCallError,        ssl_Error);
#undef ADD_EXCEPTION

    /* Method constants */
    PyModule_AddIntConstant(module, "SSLv2_METHOD",  ssl_SSLv2_METHOD);
    PyModule_AddIntConstant(module, "SSLv3_METHOD",  ssl_SSLv3_METHOD);
    PyModule_AddIntConstant(module, "SSLv23_METHOD", ssl_SSLv23_METHOD);
    PyModule_AddIntConstant(module, "TLSv1_METHOD",  ssl_TLSv1_METHOD);

    /* Verify constants */
    PyModule_AddIntConstant(module, "VERIFY_NONE", SSL_VERIFY_NONE);
    PyModule_AddIntConstant(module, "VERIFY_PEER", SSL_VERIFY_PEER);
    PyModule_AddIntConstant(module, "VERIFY_FAIL_IF_NO_PEER_CERT",
                            SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    PyModule_AddIntConstant(module, "VERIFY_CLIENT_ONCE",
                            SSL_VERIFY_CLIENT_ONCE);

    /* File type constants */
    PyModule_AddIntConstant(module, "FILETYPE_PEM",  SSL_FILETYPE_PEM);
    PyModule_AddIntConstant(module, "FILETYPE_ASN1", SSL_FILETYPE_ASN1);

    /* SSL option constants */
    PyModule_AddIntConstant(module, "OP_SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE);
    PyModule_AddIntConstant(module, "OP_EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA);
    PyModule_AddIntConstant(module, "OP_NO_SSLv2", SSL_OP_NO_SSLv2);
    PyModule_AddIntConstant(module, "OP_NO_SSLv3", SSL_OP_NO_SSLv3);
    PyModule_AddIntConstant(module, "OP_NO_TLSv1", SSL_OP_NO_TLSv1);

    /* More SSL option constants */
    PyModule_AddIntConstant(module, "OP_MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG);
    PyModule_AddIntConstant(module, "OP_NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG);
    PyModule_AddIntConstant(module, "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);
    PyModule_AddIntConstant(module, "OP_SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    PyModule_AddIntConstant(module, "OP_MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
    PyModule_AddIntConstant(module, "OP_MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING);
    PyModule_AddIntConstant(module, "OP_SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    PyModule_AddIntConstant(module, "OP_TLS_D5_BUG", SSL_OP_TLS_D5_BUG);
    PyModule_AddIntConstant(module, "OP_TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG);
    PyModule_AddIntConstant(module, "OP_DONT_INSERT_EMPTY_FRAGMENTS", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    PyModule_AddIntConstant(module, "OP_ALL", SSL_OP_ALL);
    PyModule_AddIntConstant(module, "OP_CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE);
    PyModule_AddIntConstant(module, "OP_TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG);
    PyModule_AddIntConstant(module, "OP_PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1);
    PyModule_AddIntConstant(module, "OP_PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2);
    PyModule_AddIntConstant(module, "OP_NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG);
    PyModule_AddIntConstant(module, "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG);

	/* For SSL_set_shutdown */
    PyModule_AddIntConstant(module, "SENT_SHUTDOWN", SSL_SENT_SHUTDOWN);
    PyModule_AddIntConstant(module, "RECEIVED_SHUTDOWN", SSL_RECEIVED_SHUTDOWN);

    dict = PyModule_GetDict(module);
    if (!init_ssl_context(dict))
        goto error;
    if (!init_ssl_connection(dict))
        goto error;

error:
    ;
}
