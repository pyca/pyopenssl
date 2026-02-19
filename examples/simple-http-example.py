#!/usr/bin/env python3

"""A simple Python program to show the use of the pyOpenSSL
library. We connect to a HTTPS server and retrieve its home page. (Of
course, for this specific task, pyCurl would be a better solution but
the goal is to demonstrate pyOpenSSL.)"""

PORT = 443 # Hardwired
PATH = "/" # Hardwired

# https://www.pyopenssl.org/
# https://pyopenssl.readthedocs.io/
import OpenSSL

import socket
import sys

if len(sys.argv) != 2:
    raise Exception("Usage: %s hostname" % sys.argv[0])
host = sys.argv[1]

addrinfo = socket.getaddrinfo(host, PORT, 0)

# We should loop over the IP addresses instead of taking only the first one…
sock = socket.socket(addrinfo[0][0], socket.SOCK_STREAM)
addr = addrinfo[0][4]
print("Connecting to %s ..." % str(addr))

context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)

# Use the OS' default CAs
context.set_default_verify_paths()

# Ask for a certificate check. Warning, this does not check the host
# name, just the path from the CA, the expiration, may be the CRLs…
context.set_verify(OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT | \
                   OpenSSL.SSL.VERIFY_CLIENT_ONCE,
                   lambda conn, cert, errno, depth, preverify_ok: preverify_ok)

session = OpenSSL.SSL.Connection(context, sock)
session.set_tlsext_host_name(host.encode()) # Server Name Indication (SNI)

# TCP
session.connect((addr))

# TLS
session.do_handshake()
cert = session.get_peer_certificate()
print("Connected, its certificate is for \"%s\", delivered by \"%s\"" % \
      (cert.get_subject().commonName,
       cert.get_issuer().commonName))

# HTTP
request = """GET %s HTTP/1.1
Host: %s
Connection: close

"""  % (PATH, host)
session.write(request.replace("\n","\r\n"))

# A real program must loop to read all the data
data = session.read(4096)
print("Got %i bytes, the first ones are: \"%s...\"" % (len(data),
                                                       data[:256].decode()))

session.close()
sock.close()
