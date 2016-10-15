.. _openssl-rand:

:mod:`rand` --- An interface to the OpenSSL pseudo random number generator
==========================================================================

.. warning::
   Functions from this module shouldn't be used.
   `Use urandom <https://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/>`_ instead.


.. py:module:: OpenSSL.rand
   :synopsis: An interface to the OpenSSL pseudo random number generator


This module handles the OpenSSL pseudo random number generator (PRNG) and declares the following:

.. autofunction:: add

.. autofunction:: bytes

.. autofunction:: cleanup

.. autofunction:: egd(path[, bytes])

.. autofunction:: load_file(filename[, bytes])

.. autofunction:: seed

.. autofunction:: status

.. autofunction:: write_file


.. function:: screen

    Add the current contents of the screen to the PRNG state.

    Availability: Windows.

    :return: :obj:`None`


.. autoexception:: Error
