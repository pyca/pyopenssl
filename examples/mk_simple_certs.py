"""
Create certificates and private keys for the 'simple' example.
"""

from OpenSSL import crypto
from certgen import createKeyPair, createCertRequest, createCertificate, \
                    TYPE_RSA, TYPE_DSA

FIVE_YEARS = 60*60*24*365*5
BIT_LENGTH = 1024

serial_number = 0
# Create a self signed CA certificate
cakey = createKeyPair(TYPE_RSA, BIT_LENGTH)
careq = createCertRequest(cakey, CN='Certificate Authority')
cacert = createCertificate(careq, (careq, cakey), serial_number, (0, FIVE_YEARS))
serial_number += 1
with open('simple/CA.pkey', 'w') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey))
with open('simple/CA.cert', 'w') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))

# Create the server and client certificate signed by the CA created above
for (fname, cname) in [('client', 'Simple Client'), ('server', 'Simple Server')]:
    pkey = createKeyPair(TYPE_RSA, BIT_LENGTH)
    req = createCertRequest(pkey, CN=cname)
    cert = createCertificate(req, (cacert, cakey), serial_number, (0, FIVE_YEARS))
    serial_number += 1
    with open('simple/%s.pkey' % (fname,), 'w') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
    with open('simple/%s.cert' % (fname,), 'w') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
