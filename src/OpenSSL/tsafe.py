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

from OpenSSL import SSL
_ssl = SSL
del SSL

import threading
_RLock = threading.RLock
del threading


class Connection:
    def __init__(self, *args):
        self._ssl_conn = _ssl.Connection(*args)
        self._lock = _RLock()

    for f in ('get_context', 'pending', 'send', 'write', 'recv', 'read',
              'renegotiate', 'bind', 'listen', 'connect', 'accept',
              'setblocking', 'fileno', 'shutdown', 'close', 'get_cipher_list',
              'getpeername', 'getsockname', 'getsockopt', 'setsockopt',
              'makefile', 'get_app_data', 'set_app_data', 'state_string',
              'sock_shutdown', 'get_peer_certificate', 'get_peer_cert_chain',
              'want_read', 'want_write', 'set_connect_state',
              'set_accept_state', 'connect_ex', 'sendall'):
        exec("""def %s(self, *args):
            self._lock.acquire()
            try:
                return self._ssl_conn.%s(*args)
            finally:
                self._lock.release()\n""" % (f, f))
