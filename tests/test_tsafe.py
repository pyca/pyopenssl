# -*- coding: utf-8 -*-

# Copyright 2001 Martin Sjögren and pyOpenSSL contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Unit tests for :mod:`OpenSSL.tsafe`.
"""

from OpenSSL.SSL import TLSv1_METHOD, Context
from OpenSSL.tsafe import Connection

from .util import TestCase


class ConnectionTest(TestCase):
    """
    Tests for :py:obj:`OpenSSL.tsafe.Connection`.
    """
    def test_instantiation(self):
        """
        :py:obj:`OpenSSL.tsafe.Connection` can be instantiated.
        """
        # The following line should not throw an error.  This isn't an ideal
        # test.  It would be great to refactor the other Connection tests so
        # they could automatically be applied to this class too.
        Connection(Context(TLSv1_METHOD), None)
