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

from OpenSSL._util import exception_from_error_queue, lib

from .util import TestCase


class ErrorTests(TestCase):
    """
    Tests for handling of certain OpenSSL error cases.
    """
    def test_exception_from_error_queue_nonexistent_reason(self):
        """
        :py:func:`exception_from_error_queue` raises ``ValueError`` when it
        encounters an OpenSSL error code which does not have a reason string.
        """
        lib.ERR_put_error(lib.ERR_LIB_EVP, 0, 1112, b"", 10)
        exc = self.assertRaises(
            ValueError, exception_from_error_queue, ValueError
        )
        self.assertEqual(exc.args[0][0][2], "")
