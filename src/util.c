/*
 * util.c
 *
 * Copyright (C) AB Strakt 2001, All rights reserved
 * Copyright (C) Jean-Paul Calderone 2009, All rights reserved
 *
 * Utility functions.
 * See the file RATIONALE for a short explanation of why this module was written.
 *
 * Reviewed 2001-07-23
 */
#include <Python.h>
#include "util.h"

/*
 * Flush OpenSSL's error queue and return a list of errors (a (library,
 * function, reason) string tuple)
 *
 * Arguments: None
 * Returns:   A list of errors (new reference)
 */
PyObject *
error_queue_to_list(void) {
    PyObject *errlist, *tuple;
    int failed;
    long err;

    errlist = PyList_New(0);
    if (errlist == NULL) {
        return NULL;
    }
    while ((err = ERR_get_error()) != 0) {
        tuple = Py_BuildValue("(sss)", ERR_lib_error_string(err),
                                       ERR_func_error_string(err),
                                       ERR_reason_error_string(err));
        if (tuple == NULL) {
            Py_DECREF(errlist);
            return NULL;
        }
        failed = PyList_Append(errlist, tuple);
        Py_DECREF(tuple);
        if (failed) {
            Py_DECREF(errlist);
            return NULL;
        }
    }

    return errlist;
}

void exception_from_error_queue(PyObject *the_Error) {
    PyObject *errlist = error_queue_to_list();

    if (errlist != NULL) {
        PyErr_SetObject(the_Error, errlist);
        Py_DECREF(errlist);
    }
}

/*
 * Flush OpenSSL's error queue and ignore the result
 *
 * Arguments: None
 * Returns:   None
 */
void
flush_error_queue(void) {
    /*
     * Make sure to save the errors to a local.  Py_DECREF might expand such
     * that it evaluates its argument more than once, which would lead to
     * very nasty things if we just invoked it with error_queue_to_list().
     */
    PyObject *list = error_queue_to_list();
    Py_XDECREF(list);
}
