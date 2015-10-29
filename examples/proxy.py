#!/usr/bin/env python
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
This script demonstrates how one can use pyOpenSSL to speak SSL over an HTTP
proxy.
The challenge here is to start talking SSL over an already connected socket.
"""


import sys, socket, string
from OpenSSL import SSL

def usage(exit_code=0):
    print "Usage: %s server[:port] proxy[:port]" % sys.argv[0]
    print "  Connects SSL to the specified server (port 443 by default)"
    print "    using the specified proxy (port 8080 by default)"
    sys.exit(exit_code)

def main():
    # Command-line processing
    if len(sys.argv) != 3:
        usage(-1)

    server, proxy = sys.argv[1:3]

    run(split_host(server, 443), split_host(proxy, 8080))

def split_host(hostname, default_port=80):
    a = string.split(hostname, ':', 1)
    if len(a) == 1:
        a.append(default_port)
    return a[0], int(a[1])
    

# Connects to the server, through the proxy
def run(server, proxy):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(proxy)
    except socket.error, e:
        print "Unable to connect to %s:%s %s" % (proxy[0], proxy[1], str(e))
        sys.exit(-1)

    # Use the CONNECT method to get a connection to the actual server
    s.send("CONNECT %s:%s HTTP/1.0\n\n" % (server[0], server[1]))
    print "Proxy response: %s" % string.strip(s.recv(1024))

    ctx = SSL.Context(SSL.SSLv23_METHOD)
    conn = SSL.Connection(ctx, s)

    # Go to client mode
    conn.set_connect_state()

    # start using HTTP

    conn.send("HEAD / HTTP/1.0\n\n")
    print "Sever response:"
    print "-" * 40
    while 1:
        try:
            buff = conn.recv(4096)
        except SSL.ZeroReturnError:
            # we're done
            break

        print buff,

if __name__ == '__main__':
    main()
