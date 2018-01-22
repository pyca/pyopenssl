"""
Create certificates and private keys for the 'simple_dtls' example.
"""

from __future__ import print_function

from OpenSSL import crypto
from certgen import (
    createKeyPair,
    createCertRequest,
    createCertificate,
)

cakey = createKeyPair(crypto.TYPE_RSA, 2048)
careq = createCertRequest(cakey, CN='Certificate Authority')
# CA certificate is valid for five years.
cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5))

print('Creating Certificate Authority private key in "simple_dtls/CA.pkey"')
with open('simple_dtls/CA.pkey', 'w') as capkey:
    capkey.write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey).decode('utf-8')
    )

print('Creating Certificate Authority certificate in "simple_dtls/CA.cert"')
with open('simple_dtls/CA.cert', 'w') as ca:
    ca.write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8')
    )

for (fname, cname) in [('client', 'Simple DTLS Client'),
                       ('server', 'Simple DTLS Server')]:
    pkey = createKeyPair(crypto.TYPE_RSA, 2048)
    req = createCertRequest(pkey, CN=cname)
    # Certificates are valid for five years.
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5))

    print('Creating Certificate %s private key in "simple_dtls/%s.pkey"'
          % (fname, fname))
    with open('simple_dtls/%s.pkey' % (fname,), 'w') as leafpkey:
        leafpkey.write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8')
        )

    print('Creating Certificate %s certificate in "simple_dtls/%s.cert"'
          % (fname, fname))
    with open('simple_dtls/%s.cert' % (fname,), 'w') as leafcert:
        leafcert.write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
        )
