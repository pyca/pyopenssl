/*
 * session.h
 * Copyright (C) Jean-Paul Calderone
 * See LICENSE for details.
 *
 * Defined here is the Python type which represents an SSL session by wrapping
 * an OpenSSL SSL_SESSION*.
 *
 */

#ifndef PyOpenSSL_SSL_SESSION_H_
#define PyOpenSSL_SSL_SESSION_H_

#include <Python.h>
#include <openssl/ssl.h>

typedef struct {
    PyObject_HEAD
    SSL_SESSION *session;
} ssl_SessionObj;

extern PyTypeObject ssl_Session_Type;

extern int init_ssl_session(PyObject *);
extern ssl_SessionObj *ssl_Session_from_SSL_SESSION(SSL_SESSION *native_session);

#endif
