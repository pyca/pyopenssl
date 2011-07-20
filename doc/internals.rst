.. _internals:

Internals
=========

We ran into three main problems developing this: Exceptions, callbacks and
accessing socket methods. This is what this chapter is about.


.. _exceptions:

Exceptions
----------

We realized early that most of the exceptions would be raised by the I/O
functions of OpenSSL, so it felt natural to mimic OpenSSL's error code system,
translating them into Python exceptions. This naturally gives us the exceptions
:py:exc:`.SSL.ZeroReturnError`, :py:exc:`.SSL.WantReadError`,
:py:exc:`.SSL.WantWriteError`, :py:exc:`.SSL.WantX509LookupError` and
:py:exc:`.SSL.SysCallError`.

For more information about this, see section :ref:`openssl-ssl`.


.. _callbacks:

Callbacks
---------

There are a number of problems with callbacks. First of all, OpenSSL is written
as a C library, it's not meant to have Python callbacks, so a way around that
is needed. Another problem is thread support. A lot of the OpenSSL I/O
functions can block if the socket is in blocking mode, and then you want other
Python threads to be able to do other things. The real trouble is if you've
released the global CPython interpreter lock to do a potentially blocking
operation, and the operation calls a callback. Then we must take the GIL back,
since calling Python APIs without holding it is not allowed.

There are two solutions to the first problem, both of which are necessary. The
first solution to use is if the C callback allows ''userdata'' to be passed to
it (an arbitrary pointer normally). This is great! We can set our Python
function object as the real userdata and emulate userdata for the Python
function in another way. The other solution can be used if an object with an
''app_data'' system always is passed to the callback. For example, the SSL
object in OpenSSL has app_data functions and in e.g. the verification
callbacks, you can retrieve the related SSL object. What we do is to set our
wrapper :py:class:`.Connection` object as app_data for the SSL object, and we can
easily find the Python callback.

The other problem is solved using thread local variables.  Whenever the GIL is
released before calling into an OpenSSL API, the PyThreadState pointer returned
by :c:func:`PyEval_SaveState` is stored in a global thread local variable
(using Python's own TLS API, :c:func:`PyThread_set_key_value`).  When it is
necessary to re-acquire the GIL, either after the OpenSSL API returns or in a C
callback invoked by that OpenSSL API, the value of the thread local variable is
retrieved (:c:func:`PyThread_get_key_value`) and used to re-acquire the GIL.
This allows Python threads to execute while OpenSSL APIs are running and allows
use of any particular pyOpenSSL object from any Python thread, since there is
no per-thread state associated with any of these objects and since OpenSSL is
threadsafe (as long as properly initialized, as pyOpenSSL initializes it).


.. _socket-methods:

Accessing Socket Methods
------------------------

We quickly saw the benefit of wrapping socket methods in the
:py:class:`.SSL.Connection` class, for an easy transition into using SSL. The
problem here is that the :py:mod:`socket` module lacks a C API, and all the
methods are declared static. One approach would be to have :py:mod:`.OpenSSL` as
a submodule to the :py:mod:`socket` module, placing all the code in
``socketmodule.c``, but this is obviously not a good solution, since you
might not want to import tonnes of extra stuff you're not going to use when
importing the :py:mod:`socket` module. The other approach is to somehow get a
pointer to the method to be called, either the C function, or a callable Python
object. This is not really a good solution either, since there's a lot of
lookups involved.

The way it works is that you have to supply a :py:class:`socket`- **like** transport
object to the :py:class:`.SSL.Connection`. The only requirement of this object is
that it has a :py:meth:`fileno()` method that returns a file descriptor that's
valid at the C level (i.e. you can use the system calls read and write). If you
want to use the :py:meth:`connect()` or :py:meth:`accept()` methods of the
:py:class:`.SSL.Connection` object, the transport object has to supply such
methods too. Apart from them, any method lookups in the :py:class:`.SSL.Connection`
object that fail are passed on to the underlying transport object.

Future changes might be to allow Python-level transport objects, that instead
of having :py:meth:`fileno()` methods, have :py:meth:`read()` and :py:meth:`write()`
methods, so more advanced features of Python can be used. This would probably
entail some sort of OpenSSL **BIOs**, but converting Python strings back and
forth is expensive, so this shouldn't be used unless necessary. Other nice
things would be to be able to pass in different transport objects for reading
and writing, but then the :py:meth:`fileno()` method of :py:class:`.SSL.Connection`
becomes virtually useless. Also, should the method resolution be used on the
read-transport or the write-transport?
