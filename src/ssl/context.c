/*
 * context.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 *
 * SSL Context objects and their methods.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>



#ifndef MS_WINDOWS
#  include <sys/socket.h>
#  include <netinet/in.h>
#  if !(defined(__BEOS__) || defined(__CYGWIN__))
#    include <netinet/tcp.h>
#  endif
#else
#  include <winsock.h>
#  include <wincrypt.h>
#endif

#define SSL_MODULE
#include "ssl.h"

static char *CVSid = "@(#) $Id: context.c,v 1.17 2004/08/06 10:21:56 martin Exp $";

/*
 * CALLBACKS
 *
 * Callbacks work like this: We provide a "global" callback in C which
 * transforms the arguments into a Python argument tuple and calls the
 * corresponding Python callback, and then parsing the return value back into
 * things the C function can return.
 *
 * Three caveats:
 *  + How do we find the Context object where the Python callbacks are stored?
 *  + What about multithreading and execution frames?
 *  + What about Python callbacks that raise exceptions?
 *
 * The solution to the first issue is trivial if the callback provides
 * "userdata" functionality. Since the only callbacks that don't provide
 * userdata do provide a pointer to an SSL structure, we can associate an SSL
 * object and a Connection one-to-one via the SSL_set/get_app_data()
 * functions.
 *
 * The solution to the other issue is to rewrite the Py_BEGIN_ALLOW_THREADS
 * macro allowing it (or rather a new macro) to specify where to save the
 * thread state (in our case, as a member of the Connection/Context object) so
 * we can retrieve it again before calling the Python callback.
 */

/*
 * Globally defined passphrase callback.
 *
 * Arguments: buf    - Buffer to store the returned passphrase in
 *            maxlen - Maximum length of the passphrase
 *            verify - If true, the passphrase callback should ask for a
 *                     password twice and verify they're equal. If false, only
 *                     ask once.
 *            arg    - User data, always a Context object
 * Returns:   The length of the password if successful, 0 otherwise
 */
static int
global_passphrase_callback(char *buf, int maxlen, int verify, void *arg)
{
    int len;
    char *str;
    PyObject *argv, *ret = NULL;
    ssl_ContextObj *ctx = (ssl_ContextObj *)arg;

    /* The Python callback is called with a (maxlen,verify,userdata) tuple */
    argv = Py_BuildValue("(iiO)", maxlen, verify, ctx->passphrase_userdata);
    if (ctx->tstate != NULL)
    {
        /* We need to get back our thread state before calling the callback */
        MY_END_ALLOW_THREADS(ctx->tstate);
        ret = PyEval_CallObject(ctx->passphrase_callback, argv);
        MY_BEGIN_ALLOW_THREADS(ctx->tstate);
    }
    else
    {
        ret = PyEval_CallObject(ctx->passphrase_callback, argv);
    }
    Py_DECREF(argv);

    if (ret == NULL)
        return 0;

    if (!PyObject_IsTrue(ret))
    {
        Py_DECREF(ret);
	return 0;
    }

    if (!PyString_Check(ret))
    {
        Py_DECREF(ret);
        return 0;
    }

    len = PyString_Size(ret);
    if (len > maxlen)
        len = maxlen;

    str = PyString_AsString(ret);
    strncpy(buf, str, len);
    Py_XDECREF(ret);

    return len;
}

/*
 * Globally defined verify callback
 *
 * Arguments: ok       - True everything is OK "so far", false otherwise
 *            x509_ctx - Contains the certificate being checked, the current
 *                       error number and depth, and the Connection we're
 *                       dealing with
 * Returns:   True if everything is okay, false otherwise
 */
static int
global_verify_callback(int ok, X509_STORE_CTX *x509_ctx)
{
    PyObject *argv, *ret;
    SSL *ssl;
    ssl_ConnectionObj *conn;
    crypto_X509Obj *cert;
    int errnum, errdepth, c_ret;

    cert = crypto_X509_New(X509_STORE_CTX_get_current_cert(x509_ctx), 0);
    errnum = X509_STORE_CTX_get_error(x509_ctx);
    errdepth = X509_STORE_CTX_get_error_depth(x509_ctx);
    ssl = (SSL *)X509_STORE_CTX_get_app_data(x509_ctx);
    conn = (ssl_ConnectionObj *)SSL_get_app_data(ssl);

    argv = Py_BuildValue("(OOiii)", (PyObject *)conn, (PyObject *)cert,
                                    errnum, errdepth, ok);
    Py_DECREF(cert);
    if (conn->tstate != NULL)
    {
        /* We need to get back our thread state before calling the callback */
        MY_END_ALLOW_THREADS(conn->tstate);
        ret = PyEval_CallObject(conn->context->verify_callback, argv);
        MY_BEGIN_ALLOW_THREADS(conn->tstate);
    }
    else
    {
        ret = PyEval_CallObject(conn->context->verify_callback, argv);
    }
    Py_DECREF(argv);

    if (ret == NULL)
        return 0;

    if (PyObject_IsTrue(ret))
    {
        X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
        c_ret = 1;
    }
    else
        c_ret = 0;

    Py_DECREF(ret);

    return c_ret;
}

/*
 * Globally defined info callback
 *
 * Arguments: ssl   - The Connection
 *            where - The part of the SSL code that called us
 *            _ret  - The return code of the SSL function that called us
 * Returns:   None
 */
static void
global_info_callback(SSL *ssl, int where, int _ret)
{
    ssl_ConnectionObj *conn = (ssl_ConnectionObj *)SSL_get_app_data(ssl);
    PyObject *argv, *ret;

    argv = Py_BuildValue("(Oii)", (PyObject *)conn, where, _ret);
    if (conn->tstate != NULL)
    {
        /* We need to get back our thread state before calling the callback */
        MY_END_ALLOW_THREADS(conn->tstate);
        ret = PyEval_CallObject(conn->context->info_callback, argv);
        if (ret == NULL)
            PyErr_Clear();
        else
            Py_DECREF(ret);
        MY_BEGIN_ALLOW_THREADS(conn->tstate);
    }
    else
    {
        ret = PyEval_CallObject(conn->context->info_callback, argv);
        if (ret == NULL)
            PyErr_Clear();
        else
            Py_DECREF(ret);
    }
    Py_DECREF(argv);

    return;
}




static char ssl_Context_load_verify_locations_doc[] = "\n\
Let SSL know where we can find trusted certificates for the certificate\n\
chain\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             cafile - Which file we can find the certificates\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_load_verify_locations(ssl_ContextObj *self, PyObject *args)
{
    char *cafile;

    if (!PyArg_ParseTuple(args, "s:load_verify_locations", &cafile))
        return NULL;

    if (!SSL_CTX_load_verify_locations(self->ctx, cafile, NULL))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_set_passwd_cb_doc[] = "\n\
Set the passphrase callback\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             callback - The Python callback to use\n\
             userdata - (optional) A Python object which will be given as\n\
                        argument to the callback\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_passwd_cb(ssl_ContextObj *self, PyObject *args)
{
    PyObject *callback = NULL, *userdata = Py_None;

    if (!PyArg_ParseTuple(args, "O|O:set_passwd_cb", &callback, &userdata))
        return NULL;

    if (!PyCallable_Check(callback))
    {
        PyErr_SetString(PyExc_TypeError, "expected PyCallable");
        return NULL;
    }

    Py_DECREF(self->passphrase_callback);
    Py_INCREF(callback);
    self->passphrase_callback = callback;
    SSL_CTX_set_default_passwd_cb(self->ctx, global_passphrase_callback);

    Py_DECREF(self->passphrase_userdata);
    Py_INCREF(userdata);
    self->passphrase_userdata = userdata;
    SSL_CTX_set_default_passwd_cb_userdata(self->ctx, (void *)self);

    Py_INCREF(Py_None);
    return Py_None;
}

static crypto_X509Obj *
parse_certificate_argument(const char* format1, const char* format2, PyObject* args)
{
    static PyTypeObject *crypto_X509_type = NULL;
    crypto_X509Obj *cert;

    /* We need to check that cert really is an X509 object before
       we deal with it. The problem is we can't just quickly verify
       the type (since that comes from another module). This should
       do the trick (reasonably well at least): Once we have one
       verified object, we use it's type object for future
       comparisons. */

    if (!crypto_X509_type)
    {
	if (!PyArg_ParseTuple(args, format1, &cert))
	    return NULL;

	if (strcmp(cert->ob_type->tp_name, "X509") != 0 || 
	    cert->ob_type->tp_basicsize != sizeof(crypto_X509Obj))
	{
	    PyErr_SetString(PyExc_TypeError, "Expected an X509 object");
	    return NULL;
	}

	crypto_X509_type = cert->ob_type;
    }
    else
	if (!PyArg_ParseTuple(args, format2, crypto_X509_type,
			      &cert))
	    return NULL;
    return cert;
}

static char ssl_Context_add_extra_chain_cert_doc[] = "\n\
Add certificate to chain\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             certobj - The X509 certificate object to add to the chain\n\
Returns:   None\n\
";

static PyObject *
ssl_Context_add_extra_chain_cert(ssl_ContextObj *self, PyObject *args)
{
    X509* cert_original;
    crypto_X509Obj *cert = parse_certificate_argument(
        "O:add_extra_chain_cert", "O!:add_extra_chain_cert", args);
    if (cert == NULL)
    {
        return NULL;
    }
    if (!(cert_original = X509_dup(cert->x509)))
    {
        /* exception_from_error_queue(); */
        PyErr_SetString(PyExc_RuntimeError, "X509_dup failed");
        return NULL;
    }
    if (!SSL_CTX_add_extra_chain_cert(self->ctx, cert_original))
    {
        X509_free(cert_original);
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}


static char ssl_Context_use_certificate_chain_file_doc[] = "\n\
Load a certificate chain from a file\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             certfile - The name of the certificate chain file\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_use_certificate_chain_file(ssl_ContextObj *self, PyObject *args)
{
    char *certfile;

    if (!PyArg_ParseTuple(args, "s:use_certificate_chain_file", &certfile))
        return NULL;

    if (!SSL_CTX_use_certificate_chain_file(self->ctx, certfile))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}


static char ssl_Context_use_certificate_file_doc[] = "\n\
Load a certificate from a file\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             certfile - The name of the certificate file\n\
             filetype - (optional) The encoding of the file, default is PEM\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_use_certificate_file(ssl_ContextObj *self, PyObject *args)
{
    char *certfile;
    int filetype = SSL_FILETYPE_PEM;

    if (!PyArg_ParseTuple(args, "s|i:use_certificate_file", &certfile, &filetype))
        return NULL;

    if (!SSL_CTX_use_certificate_file(self->ctx, certfile, filetype))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_use_certificate_doc[] = "\n\
Load a certificate from a X509 object\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             cert - The X509 object\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_use_certificate(ssl_ContextObj *self, PyObject *args)
{
    crypto_X509Obj *cert = parse_certificate_argument(
        "O:use_certificate", "O!:use_certificate", args);
    if (cert == NULL) {
        return NULL;
    }
    
    if (!SSL_CTX_use_certificate(self->ctx, cert->x509))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_use_privatekey_file_doc[] = "\n\
Load a private key from a file\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             keyfile  - The name of the key file\n\
             filetype - (optional) The encoding of the file, default is PEM\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_use_privatekey_file(ssl_ContextObj *self, PyObject *args)
{
    char *keyfile;
    int filetype = SSL_FILETYPE_PEM, ret;

    if (!PyArg_ParseTuple(args, "s|i:use_privatekey_file", &keyfile, &filetype))
        return NULL;

    MY_BEGIN_ALLOW_THREADS(self->tstate);
    ret = SSL_CTX_use_PrivateKey_file(self->ctx, keyfile, filetype);
    MY_END_ALLOW_THREADS(self->tstate);

    if (PyErr_Occurred())
    {
        flush_error_queue();
        return NULL;
    }

    if (!ret)
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_use_privatekey_doc[] = "\n\
Load a private key from a PKey object\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             pkey - The PKey object\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_use_privatekey(ssl_ContextObj *self, PyObject *args)
{
    static PyTypeObject *crypto_PKey_type = NULL;
    crypto_PKeyObj *pkey;

    /* We need to check that cert really is a PKey object before
       we deal with it. The problem is we can't just quickly verify
       the type (since that comes from another module). This should
       do the trick (reasonably well at least): Once we have one
       verified object, we use it's type object for future
       comparisons. */

    if (!crypto_PKey_type)
    {
	if (!PyArg_ParseTuple(args, "O:use_privatekey", &pkey))
	    return NULL;

	if (strcmp(pkey->ob_type->tp_name, "PKey") != 0 || 
	    pkey->ob_type->tp_basicsize != sizeof(crypto_PKeyObj))
	{
	    PyErr_SetString(PyExc_TypeError, "Expected a PKey object");
	    return NULL;
	}

	crypto_PKey_type = pkey->ob_type;
    }
    else
    if (!PyArg_ParseTuple(args, "O!:use_privatekey", crypto_PKey_type, &pkey))
        return NULL;

    if (!SSL_CTX_use_PrivateKey(self->ctx, pkey->pkey))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_check_privatekey_doc[] = "\n\
Check that the private key and certificate match up\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   None (raises an exception if something's wrong)\n\
";
static PyObject *
ssl_Context_check_privatekey(ssl_ContextObj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":check_privatekey"))
        return NULL;

    if (!SSL_CTX_check_private_key(self->ctx))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_load_client_ca_doc[] = "\n\
Load the trusted certificates that will be sent to the client (basically\n\
telling the client \"These are the guys I trust\")\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             cafile - The name of the certificates file\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_load_client_ca(ssl_ContextObj *self, PyObject *args)
{
    char *cafile;

    if (!PyArg_ParseTuple(args, "s:load_client_ca", &cafile))
        return NULL;

    SSL_CTX_set_client_CA_list(self->ctx, SSL_load_client_CA_file(cafile));

    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_set_session_id_doc[] = "\n\
Set the session identifier, this is needed if you want to do session\n\
resumption (which, ironically, isn't implemented yet)\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             buf - A Python object that can be safely converted to a string\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_session_id(ssl_ContextObj *self, PyObject *args)
{
    char *buf;
    int len;

    if (!PyArg_ParseTuple(args, "s#:set_session_id", &buf, &len))
        return NULL;

    if (!SSL_CTX_set_session_id_context(self->ctx, buf, len))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_set_verify_doc[] = "\n\
Set the verify mode and verify callback\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             mode     - The verify mode, this is either SSL_VERIFY_NONE or\n\
                        SSL_VERIFY_PEER combined with possible other flags\n\
             callback - The Python callback to use\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_verify(ssl_ContextObj *self, PyObject *args)
{
    int mode;
    PyObject *callback = NULL;

    if (!PyArg_ParseTuple(args, "iO:set_verify", &mode, &callback))
        return NULL;

    if (!PyCallable_Check(callback))
    {
        PyErr_SetString(PyExc_TypeError, "expected PyCallable");
        return NULL;
    }

    Py_DECREF(self->verify_callback);
    Py_INCREF(callback);
    self->verify_callback = callback;
    SSL_CTX_set_verify(self->ctx, mode, global_verify_callback);

    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_set_verify_depth_doc[] = "\n\
Set the verify depth\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             depth - An integer specifying the verify depth\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_verify_depth(ssl_ContextObj *self, PyObject *args)
{
    int depth;

    if (!PyArg_ParseTuple(args, "i:set_verify_depth", &depth))
        return NULL;

    SSL_CTX_set_verify_depth(self->ctx, depth);
    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_get_verify_mode_doc[] = "\n\
Get the verify mode\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The verify mode\n\
";
static PyObject *
ssl_Context_get_verify_mode(ssl_ContextObj *self, PyObject *args)
{
    int mode;

    if (!PyArg_ParseTuple(args, ":get_verify_mode"))
        return NULL;

    mode = SSL_CTX_get_verify_mode(self->ctx);
    return PyInt_FromLong((long)mode);
}

static char ssl_Context_get_verify_depth_doc[] = "\n\
Get the verify depth\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The verify depth\n\
";
static PyObject *
ssl_Context_get_verify_depth(ssl_ContextObj *self, PyObject *args)
{
    int depth;

    if (!PyArg_ParseTuple(args, ":get_verify_depth"))
        return NULL;

    depth = SSL_CTX_get_verify_depth(self->ctx);
    return PyInt_FromLong((long)depth);
}

static char ssl_Context_load_tmp_dh_doc[] = "\n\
Load parameters for Ephemeral Diffie-Hellman\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             dhfile - The file to load EDH parameters from\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_load_tmp_dh(ssl_ContextObj *self, PyObject *args)
{
    char *dhfile;
    BIO *bio;
    DH *dh;

    if (!PyArg_ParseTuple(args, "s:load_tmp_dh", &dhfile))
        return NULL;

    bio = BIO_new_file(dhfile, "r");
    if (bio == NULL)
        return PyErr_NoMemory();

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    SSL_CTX_set_tmp_dh(self->ctx, dh);
    DH_free(dh);
    BIO_free(bio);

    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_set_cipher_list_doc[] = "\n\
Change the cipher list\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             cipher_list - A cipher list, see ciphers(1)\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_cipher_list(ssl_ContextObj *self, PyObject *args)
{
    char *cipher_list;

    if (!PyArg_ParseTuple(args, "s:set_cipher_list", &cipher_list))
        return NULL;

    if (!SSL_CTX_set_cipher_list(self->ctx, cipher_list))
    {
        exception_from_error_queue();
        return NULL;
    }
    else
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
}

static char ssl_Context_set_timeout_doc[] = "\n\
Set session timeout\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             t - The timeout in seconds\n\
Returns:   The previous session timeout\n\
";
static PyObject *
ssl_Context_set_timeout(ssl_ContextObj *self, PyObject *args)
{
    long t, ret;

    if (!PyArg_ParseTuple(args, "l:set_timeout", &t))
        return NULL;

    ret = SSL_CTX_set_timeout(self->ctx, t);
    return PyLong_FromLong(ret);
}

static char ssl_Context_get_timeout_doc[] = "\n\
Get the session timeout\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The session timeout\n\
";
static PyObject *
ssl_Context_get_timeout(ssl_ContextObj *self, PyObject *args)
{
    long ret;

    if (!PyArg_ParseTuple(args, ":get_timeout"))
        return NULL;

    ret = SSL_CTX_get_timeout(self->ctx);
    return PyLong_FromLong(ret);
}

static char ssl_Context_set_info_callback_doc[] = "\n\
Set the info callback\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             callback - The Python callback to use\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_info_callback(ssl_ContextObj *self, PyObject *args)
{
    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O:set_info_callback", &callback))
        return NULL;

    if (!PyCallable_Check(callback))
    {
        PyErr_SetString(PyExc_TypeError, "expected PyCallable");
        return NULL;
    }

    Py_DECREF(self->info_callback);
    Py_INCREF(callback);
    self->info_callback = callback;
    SSL_CTX_set_info_callback(self->ctx, global_info_callback);

    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_get_app_data_doc[] = "\n\
Get the application data (supplied via set_app_data())\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   The application data\n\
";
static PyObject *
ssl_Context_get_app_data(ssl_ContextObj *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":get_app_data"))
        return NULL;

    Py_INCREF(self->app_data);
    return self->app_data;
}

static char ssl_Context_set_app_data_doc[] = "\n\
Set the application data (will be returned from get_app_data())\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             data - Any Python object\n\
Returns:   None\n\
";
static PyObject *
ssl_Context_set_app_data(ssl_ContextObj *self, PyObject *args)
{
    PyObject *data;

    if (!PyArg_ParseTuple(args, "O:set_app_data", &data))
        return NULL;

    Py_DECREF(self->app_data);
    Py_INCREF(data);
    self->app_data = data;

    Py_INCREF(Py_None);
    return Py_None;
}

static char ssl_Context_get_cert_store_doc[] = "\n\
Get the certificate store for the context\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be empty\n\
Returns:   A X509Store object\n\
";
static PyObject *
ssl_Context_get_cert_store(ssl_ContextObj *self, PyObject *args)
{
    X509_STORE *store;

    if (!PyArg_ParseTuple(args, ":get_cert_store"))
        return NULL;

    if ((store = SSL_CTX_get_cert_store(self->ctx)) == NULL)
    {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else
    {
        return (PyObject *)crypto_X509Store_New(store, 0);
    }
}

static char ssl_Context_set_options_doc[] = "\n\
Add options. Options set before are not cleared!\n\
\n\
Arguments: self - The Context object\n\
           args - The Python argument tuple, should be:\n\
             options - The options to add.\n\
Returns:   The new option bitmask.\n\
";
static PyObject *
ssl_Context_set_options(ssl_ContextObj *self, PyObject *args)
{
    long options;

    if (!PyArg_ParseTuple(args, "l:set_options", &options))
        return NULL;

    return PyInt_FromLong(SSL_CTX_set_options(self->ctx, options));
}


/*
 * Member methods in the Context object
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)ssl_Context_name, METH_VARARGS }
 * for convenience
 * ADD_ALIAS(name,real) creates an "alias" of the ssl_Context_real
 * function with the name 'name'
 */
#define ADD_METHOD(name) { #name, (PyCFunction)ssl_Context_##name, METH_VARARGS, ssl_Context_##name##_doc }
static PyMethodDef ssl_Context_methods[] = {
    ADD_METHOD(load_verify_locations),
    ADD_METHOD(set_passwd_cb),
    ADD_METHOD(use_certificate_chain_file),
    ADD_METHOD(use_certificate_file),
    ADD_METHOD(use_certificate),
    ADD_METHOD(add_extra_chain_cert),
    ADD_METHOD(use_privatekey_file),
    ADD_METHOD(use_privatekey),
    ADD_METHOD(check_privatekey),
    ADD_METHOD(load_client_ca),
    ADD_METHOD(set_session_id),
    ADD_METHOD(set_verify),
    ADD_METHOD(set_verify_depth),
    ADD_METHOD(get_verify_mode),
    ADD_METHOD(get_verify_depth),
    ADD_METHOD(load_tmp_dh),
    ADD_METHOD(set_cipher_list),
    ADD_METHOD(set_timeout),
    ADD_METHOD(get_timeout),
    ADD_METHOD(set_info_callback),
    ADD_METHOD(get_app_data),
    ADD_METHOD(set_app_data),
    ADD_METHOD(get_cert_store),
    ADD_METHOD(set_options),
    { NULL, NULL }
};
#undef ADD_METHOD


/* Constructor, takes an int specifying which method to use */
/*
 * Constructor for Context objects
 *
 * Arguments: i_method - The SSL method to use, one of the SSLv2_METHOD,
 *                       SSLv3_METHOD, SSLv23_METHOD and TLSv1_METHOD
 *                       constants.
 * Returns:   The newly created Context object
 */
ssl_ContextObj *
ssl_Context_New(int i_method)
{
    SSL_METHOD *method;
    ssl_ContextObj *self;

    switch (i_method)
    {
        /* Too bad TLSv1 servers can't accept SSLv3 clients */
        case ssl_SSLv2_METHOD:    method = SSLv2_method();  break;
        case ssl_SSLv23_METHOD:   method = SSLv23_method(); break;
        case ssl_SSLv3_METHOD:    method = SSLv3_method();  break;
        case ssl_TLSv1_METHOD:    method = TLSv1_method();  break;
        default:
            PyErr_SetString(PyExc_ValueError, "No such protocol");
            return NULL;
    }

    self = PyObject_GC_New(ssl_ContextObj, &ssl_Context_Type);
    if (self == NULL)
        return (ssl_ContextObj *)PyErr_NoMemory();

    self->ctx = SSL_CTX_new(method);
    Py_INCREF(Py_None);
    self->passphrase_callback = Py_None;
    Py_INCREF(Py_None);
    self->verify_callback = Py_None;
    Py_INCREF(Py_None);
    self->info_callback = Py_None;

    Py_INCREF(Py_None);
    self->passphrase_userdata = Py_None;

    Py_INCREF(Py_None);
    self->app_data = Py_None;

    /* Some initialization that's required to operate smoothly in Python */
    SSL_CTX_set_app_data(self->ctx, self);
    SSL_CTX_set_mode(self->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                                SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                                SSL_MODE_AUTO_RETRY);

    self->tstate = NULL;
    PyObject_GC_Track((PyObject *)self);

    return self;
}

/*
 * Find attribute
 *
 * Arguments: self - The Context object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
ssl_Context_getattr(ssl_ContextObj *self, char *name)
{
    return Py_FindMethod(ssl_Context_methods, (PyObject *)self, name);
}

/*
 * Call the visitproc on all contained objects.
 *
 * Arguments: self - The Context object
 *            visit - Function to call
 *            arg - Extra argument to visit
 * Returns:   0 if all goes well, otherwise the return code from the first
 *            call that gave non-zero result.
 */
static int
ssl_Context_traverse(ssl_ContextObj *self, visitproc visit, void *arg)
{
    int ret = 0;

    if (ret == 0 && self->passphrase_callback != NULL)
        ret = visit((PyObject *)self->passphrase_callback, arg);
    if (ret == 0 && self->passphrase_userdata != NULL)
        ret = visit((PyObject *)self->passphrase_userdata, arg);
    if (ret == 0 && self->verify_callback != NULL)
        ret = visit((PyObject *)self->verify_callback, arg);
    if (ret == 0 && self->info_callback != NULL)
        ret = visit((PyObject *)self->info_callback, arg);
    if (ret == 0 && self->app_data != NULL)
        ret = visit(self->app_data, arg);
    return ret;
}

/*
 * Decref all contained objects and zero the pointers.
 *
 * Arguments: self - The Context object
 * Returns:   Always 0.
 */
static int
ssl_Context_clear(ssl_ContextObj *self)
{
    Py_XDECREF(self->passphrase_callback);
    self->passphrase_callback = NULL;
    Py_XDECREF(self->passphrase_userdata);
    self->passphrase_userdata = NULL;
    Py_XDECREF(self->verify_callback);
    self->verify_callback = NULL;
    Py_XDECREF(self->info_callback);
    self->info_callback = NULL;
    Py_XDECREF(self->app_data);
    self->app_data = NULL;
    return 0;
}

/*
 * Deallocate the memory used by the Context object
 *
 * Arguments: self - The Context object
 * Returns:   None
 */
static void
ssl_Context_dealloc(ssl_ContextObj *self)
{
    PyObject_GC_UnTrack((PyObject *)self);
    SSL_CTX_free(self->ctx);
    ssl_Context_clear(self);
    PyObject_GC_Del(self);
}


PyTypeObject ssl_Context_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Context",
    sizeof(ssl_ContextObj),
    0,
    (destructor)ssl_Context_dealloc,
    NULL, /* print */
    (getattrfunc)ssl_Context_getattr,
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
    (traverseproc)ssl_Context_traverse,
    (inquiry)ssl_Context_clear,
};


/*
 * Initialize the Context part of the SSL sub module
 *
 * Arguments: dict - Dictionary of the OpenSSL.SSL module
 * Returns:   1 for success, 0 otherwise
 */
int
init_ssl_context(PyObject *dict)
{
    ssl_Context_Type.ob_type = &PyType_Type;
    Py_INCREF(&ssl_Context_Type);
    if (PyDict_SetItemString(dict, "ContextType", (PyObject *)&ssl_Context_Type) != 0)
        return 0;

    return 1;
}

