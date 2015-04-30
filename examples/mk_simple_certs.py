"""
Create certificates and private keys for the 'simple' example.
"""

from OpenSSL import crypto
from certgen import *   # yes yes, I know, I'm lazy
cakey = createKeyPair(TYPE_RSA, 2048)
careq = createCertRequest(cakey, CN='Certificate Authority')
cacert = createCertificate(careq, (careq, cakey), 0, (0, 60*60*24*365*5)) # five years

print('Creating Certificate Authority private key in "simple/CA.pkey"')
with open('simple/CA.pkey', 'w') as capkey:
    capkey.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey).decode('utf-8'))
print('Creating Certificate Authority certificate in "simple/CA.cert"')
with open('simple/CA.cert', 'w') as ca:
    ca.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert).decode('utf-8'))

for (fname, cname) in [('client', 'Simple Client'), ('server', 'Simple Server')]:
    pkey = createKeyPair(TYPE_RSA, 2048)
    req = createCertRequest(pkey, CN=cname)
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60*60*24*365*5)) # five years

    print('Creating Certificate %s private key in "simple/%s.pkey"' % (fname, fname))
    with open('simple/%s.pkey' % (fname,), 'w') as leafpkey:
        leafpkey.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode('utf-8'))
    print('Creating Certificate %s certificate in "simple/%s.cert"' % (fname, fname))
    with open('simple/%s.cert' % (fname,), 'w') as leafcert:
        leafcert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))

