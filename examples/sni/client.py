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

if __name__ == '__main__':
    import client
    raise SystemExit(client.main())

from sys import argv, stdout
from socket import socket

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection

def main():
    """
    Connect to an SNI-enabled server and request a specific hostname, specified
    by argv[1], of it.
    """
    if len(argv) < 2:
        print 'Usage: %s <hostname>' % (argv[0],)
        return 1

    client = socket()

    print 'Connecting...',
    stdout.flush()
    client.connect(('127.0.0.1', 8443))
    print 'connected', client.getpeername()

    client_ssl = Connection(Context(TLSv1_METHOD), client)
    client_ssl.set_connect_state()
    client_ssl.set_tlsext_host_name(argv[1])
    client_ssl.do_handshake()
    print 'Server subject is', client_ssl.get_peer_certificate().get_subject()
    client_ssl.close()

