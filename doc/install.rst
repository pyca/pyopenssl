.. _building:

Building and Installing
=======================


These instructions can also be found in the file ``INSTALL``.

I have tested this on Debian Linux systems (woody and sid), Solaris 2.6 and
2.7. Others have successfully compiled it on Windows and NT.

.. _building-unix:

Building the Module on a Unix System
------------------------------------

pyOpenSSL uses distutils, so there really shouldn't be any problems. To build
the library::

    python setup.py build

If your OpenSSL header files aren't in ``/usr/include``, you may need to supply
the ``-I`` flag to let the setup script know where to look. The same goes for
the libraries of course, use the ``-L`` flag. Note that ``build`` won't accept
these flags, so you have to run first ``build_ext`` and then ``build``!
Example::

    python setup.py build_ext -I/usr/local/ssl/include -L/usr/local/ssl/lib
    python setup.py build

Now you should have a directory called ``OpenSSL`` that contains e.g.
``SSL.so`` and ``__init__.py`` somewhere in the build dicrectory,
so just::

    python setup.py install

If you, for some arcane reason, don't want the module to appear in the
``site-packages`` directory, use the ``--prefix`` option.

You can, of course, do::

    python setup.py --help

to find out more about how to use the script.

.. _building-windows:

Building the Module on a Windows System
---------------------------------------

Big thanks to Itamar Shtull-Trauring and Oleg Orlov for their help with
Windows build instructions.  Same as for Unix systems, we have to separate
the ``build_ext`` and the ``build``.

Building the library::

    setup.py build_ext -I ...\openssl\inc32 -L ...\openssl\out32dll
    setup.py build

Where ``...\openssl`` is of course the location of your OpenSSL installation.

Installation is the same as for Unix systems::

    setup.py install

And similarily, you can do::

    setup.py --help

to get more information.
