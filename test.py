#!/usr/bin/env python3

import socket
from OpenSSL import SSL

import os
import sys

print(f"DEBUG_ENV_PYTHON: DYLD_LIBRARY_PATH from Python: {os.environ.get('DYLD_LIBRARY_PATH')}")
print(f"DEBUG_ENV_PYTHON: Python executable: {sys.executable}")
# You might also want to print other relevant vars if you set them:
print(f"DEBUG_ENV_PYTHON: OPENSSL_CONF from Python: {os.environ.get('OPENSSL_CONF')}")
print(f"DEBUG_ENV_PYTHON: OPENSSL_MODULES from Python: {os.environ.get('OPENSSL_MODULES')}")

def test_ssl_send():
    # Create SSL context
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    
    # Create a regular socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Wrap it with SSL
    connection = SSL.Connection(context, sock)
    
    try:
        # Connect to a real HTTPS server
        print("Connecting to httpbin.org:443...")
        connection.connect(('httpbin.org', 443))
        
        # Do the SSL handshake
        print("Performing SSL handshake...")
        connection.do_handshake()
        
        # Prepare HTTP request
        http_request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
        
        print(f"About to send {len(http_request)} bytes...")
        print("** SET YOUR BREAKPOINT ON SSL_write NOW **")

        import os
        print("Client PID:{d}", os.getpid())

        
        # This will call _lib.SSL_write() in pyOpenSSL
        # Which calls SSL_write() in OpenSSL C library
        bytes_sent = connection.send(http_request)
        
        print(f"Sent {bytes_sent} bytes")
        
        # Read the response
        print("Reading response...")
        response = connection.recv(1024)
        print(f"Received: {response[:100]}...")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            connection.close()
        except:
            pass

if __name__ == "__main__":
    test_ssl_send()