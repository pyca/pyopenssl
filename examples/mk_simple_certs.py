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

