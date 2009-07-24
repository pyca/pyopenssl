# Copyright (C) Jean-Paul Calderone 2008, All rights reserved

"""
Unit tests for L{OpenSSL.crypto}.
"""

from unittest import main

from os import popen2

from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, Error, PKey, PKeyType
from OpenSSL.crypto import X509, X509Type, X509Name, X509NameType
from OpenSSL.crypto import X509Req, X509ReqType
from OpenSSL.crypto import X509Extension, X509ExtensionType
from OpenSSL.crypto import load_certificate, load_privatekey
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
from OpenSSL.crypto import dump_certificate, load_certificate_request
from OpenSSL.crypto import dump_certificate_request, dump_privatekey
from OpenSSL.crypto import PKCS7Type, load_pkcs7_data
from OpenSSL.crypto import PKCS12Type, load_pkcs12, PKCS12
from OpenSSL.crypto import NetscapeSPKI, NetscapeSPKIType
from OpenSSL.test.util import TestCase


root_cert_pem = """-----BEGIN CERTIFICATE-----
MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
-----END CERTIFICATE-----
"""

root_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD5mkLpi7q6ROdu7khB3S9aanA0Zls7vvfGOmB80/yeylhGpsjA
jWen0VtSQke/NlEPGtO38tsV7CsuFnSmschvAnGrcJl76b0UOOHUgDTIoRxC6QDU
3claegwsrBA+sJEBbqx5RdXbIRGicPG/8qQ4Zm1SKOgotcbwiaor2yxZ2wIDAQAB
AoGBAPCgMpmLxzwDaUmcFbTJUvlLW1hoxNNYSu2jIZm1k/hRAcE60JYwvBkgz3UB
yMEh0AtLxYe0bFk6EHah11tMUPgscbCq73snJ++8koUw+csk22G65hOs51bVb7Aa
6JBe67oLzdtvgCUFAA2qfrKzWRZzAdhUirQUZgySZk+Xq1pBAkEA/kZG0A6roTSM
BVnx7LnPfsycKUsTumorpXiylZJjTi9XtmzxhrYN6wgZlDOOwOLgSQhszGpxVoMD
u3gByT1b2QJBAPtL3mSKdvwRu/+40zaZLwvSJRxaj0mcE4BJOS6Oqs/hS1xRlrNk
PpQ7WJ4yM6ZOLnXzm2mKyxm50Mv64109FtMCQQDOqS2KkjHaLowTGVxwC0DijMfr
I9Lf8sSQk32J5VWCySWf5gGTfEnpmUa41gKTMJIbqZZLucNuDcOtzUaeWZlZAkA8
ttXigLnCqR486JDPTi9ZscoZkZ+w7y6e/hH8t6d5Vjt48JVyfjPIaJY+km58LcN3
6AWSeGAdtRFHVzR7oHjVAkB4hutvxiOeiIVQNBhM6RSI9aBPMI21DoX2JRoxvNW2
cbvAhow217X9V0dVerEOKxnNYspXRrh36h7k4mQA+sDq
-----END RSA PRIVATE KEY-----
"""

server_cert_pem = """-----BEGIN CERTIFICATE-----
MIICKDCCAZGgAwIBAgIJAJn/HpR21r/8MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMH
VGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBMCIYDzIwMDkwMzI1MTIz
NzUzWhgPMjAxNzA2MTExMjM3NTNaMBgxFjAUBgNVBAMTDWxvdmVseSBzZXJ2ZXIw
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL6m+G653V0tpBC/OKl22VxOi2Cv
lK4TYu9LHSDP9uDVTe7V5D5Tl6qzFoRRx5pfmnkqT5B+W9byp2NU3FC5hLm5zSAr
b45meUhjEJ/ifkZgbNUjHdBIGP9MAQUHZa5WKdkGIJvGAvs8UzUqlr4TBWQIB24+
lJ+Ukk/CRgasrYwdAgMBAAGjNjA0MB0GA1UdDgQWBBS4kC7Ij0W1TZXZqXQFAM2e
gKEG2DATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQUFAAOBgQBh30Li
dJ+NlxIOx5343WqIBka3UbsOb2kxWrbkVCrvRapCMLCASO4FqiKWM+L0VDBprqIp
2mgpFQ6FHpoIENGvJhdEKpptQ5i7KaGhnDNTfdy3x1+h852G99f1iyj0RmbuFcM8
uzujnS8YXWvM7DM1Ilozk4MzPug8jzFp5uhKCQ==
-----END CERTIFICATE-----
"""

server_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC+pvhuud1dLaQQvzipdtlcTotgr5SuE2LvSx0gz/bg1U3u1eQ+
U5eqsxaEUceaX5p5Kk+QflvW8qdjVNxQuYS5uc0gK2+OZnlIYxCf4n5GYGzVIx3Q
SBj/TAEFB2WuVinZBiCbxgL7PFM1Kpa+EwVkCAduPpSflJJPwkYGrK2MHQIDAQAB
AoGAbwuZ0AR6JveahBaczjfnSpiFHf+mve2UxoQdpyr6ROJ4zg/PLW5K/KXrC48G
j6f3tXMrfKHcpEoZrQWUfYBRCUsGD5DCazEhD8zlxEHahIsqpwA0WWssJA2VOLEN
j6DuV2pCFbw67rfTBkTSo32ahfXxEKev5KswZk0JIzH3ooECQQDgzS9AI89h0gs8
Dt+1m11Rzqo3vZML7ZIyGApUzVan+a7hbc33nbGRkAXjHaUBJO31it/H6dTO+uwX
msWwNG5ZAkEA2RyFKs5xR5USTFaKLWCgpH/ydV96KPOpBND7TKQx62snDenFNNbn
FwwOhpahld+vqhYk+pfuWWUpQciE+Bu7ZQJASjfT4sQv4qbbKK/scePicnDdx9th
4e1EeB9xwb+tXXXUo/6Bor/AcUNwfiQ6Zt9PZOK9sR3lMZSsP7rMi7kzuQJABie6
1sXXjFH7nNJvRG4S39cIxq8YRYTy68II/dlB2QzGpKxV/POCxbJ/zu0CU79tuYK7
NaeNCFfH3aeTrX0LyQJAMBWjWmeKM2G2sCExheeQK0ROnaBC8itCECD4Jsve4nqf
r50+LF74iLXFwqysVCebPKMOpDWp/qQ1BbJQIPs7/A==
-----END RSA PRIVATE KEY-----
"""

client_cert_pem = """-----BEGIN CERTIFICATE-----
MIICJjCCAY+gAwIBAgIJAKxpFI5lODkjMA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UEBxMHQ2hpY2FnbzEQMA4GA1UEChMH
VGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBMCIYDzIwMDkwMzI1MTIz
ODA1WhgPMjAxNzA2MTExMjM4MDVaMBYxFDASBgNVBAMTC3VnbHkgY2xpZW50MIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAZh/SRtNm5ntMT4qb6YzEpTroMlq2
rn+GrRHRiZ+xkCw/CGNhbtPir7/QxaUj26BSmQrHw1bGKEbPsWiW7bdXSespl+xK
iku4G/KvnnmWdeJHqsiXeUZtqurMELcPQAw9xPHEuhqqUJvvEoMTsnCEqGM+7Dtb
oCRajYyHfluARQIDAQABozYwNDAdBgNVHQ4EFgQUNQB+qkaOaEVecf1J3TTUtAff
0fAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQEFBQADgYEAyv/Jh7gM
Q3OHvmsFEEvRI+hsW8y66zK4K5de239Y44iZrFYkt7Q5nBPMEWDj4F2hLYWL/qtI
9Zdr0U4UDCU9SmmGYh4o7R4TZ5pGFvBYvjhHbkSFYFQXZxKUi+WUxplP6I0wr2KJ
PSTJCjJOn3xo2NTKRgV1gaoTf2EhL+RG8TQ=
-----END CERTIFICATE-----
"""

client_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDAZh/SRtNm5ntMT4qb6YzEpTroMlq2rn+GrRHRiZ+xkCw/CGNh
btPir7/QxaUj26BSmQrHw1bGKEbPsWiW7bdXSespl+xKiku4G/KvnnmWdeJHqsiX
eUZtqurMELcPQAw9xPHEuhqqUJvvEoMTsnCEqGM+7DtboCRajYyHfluARQIDAQAB
AoGATkZ+NceY5Glqyl4mD06SdcKfV65814vg2EL7V9t8+/mi9rYL8KztSXGlQWPX
zuHgtRoMl78yQ4ZJYOBVo+nsx8KZNRCEBlE19bamSbQLCeQMenWnpeYyQUZ908gF
h6L9qsFVJepgA9RDgAjyDoS5CaWCdCCPCH2lDkdcqC54SVUCQQDseuduc4wi8h4t
V8AahUn9fn9gYfhoNuM0gdguTA0nPLVWz4hy1yJiWYQe0H7NLNNTmCKiLQaJpAbb
TC6vE8C7AkEA0Ee8CMJUc20BnGEmxwgWcVuqFWaKCo8jTH1X38FlATUsyR3krjW2
dL3yDD9NwHxsYP7nTKp/U8MV7U9IBn4y/wJBAJl7H0/BcLeRmuJk7IqJ7b635iYB
D/9beFUw3MUXmQXZUfyYz39xf6CDZsu1GEdEC5haykeln3Of4M9d/4Kj+FcCQQCY
si6xwT7GzMDkk/ko684AV3KPc/h6G0yGtFIrMg7J3uExpR/VdH2KgwMkZXisSMvw
JJEQjOMCVsEJlRk54WWjAkEAzoZNH6UhDdBK5F38rVt/y4SEHgbSfJHIAmPS32Kq
f6GGcfNpip0Uk7q7udTKuX7Q/buZi/C4YW7u3VKAquv9NA==
-----END RSA PRIVATE KEY-----
"""

cleartextCertificatePEM = """-----BEGIN CERTIFICATE-----
MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
-----END CERTIFICATE-----
"""

cleartextPrivateKeyPEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD5mkLpi7q6ROdu7khB3S9aanA0Zls7vvfGOmB80/yeylhGpsjA
jWen0VtSQke/NlEPGtO38tsV7CsuFnSmschvAnGrcJl76b0UOOHUgDTIoRxC6QDU
3claegwsrBA+sJEBbqx5RdXbIRGicPG/8qQ4Zm1SKOgotcbwiaor2yxZ2wIDAQAB
AoGBAPCgMpmLxzwDaUmcFbTJUvlLW1hoxNNYSu2jIZm1k/hRAcE60JYwvBkgz3UB
yMEh0AtLxYe0bFk6EHah11tMUPgscbCq73snJ++8koUw+csk22G65hOs51bVb7Aa
6JBe67oLzdtvgCUFAA2qfrKzWRZzAdhUirQUZgySZk+Xq1pBAkEA/kZG0A6roTSM
BVnx7LnPfsycKUsTumorpXiylZJjTi9XtmzxhrYN6wgZlDOOwOLgSQhszGpxVoMD
u3gByT1b2QJBAPtL3mSKdvwRu/+40zaZLwvSJRxaj0mcE4BJOS6Oqs/hS1xRlrNk
PpQ7WJ4yM6ZOLnXzm2mKyxm50Mv64109FtMCQQDOqS2KkjHaLowTGVxwC0DijMfr
I9Lf8sSQk32J5VWCySWf5gGTfEnpmUa41gKTMJIbqZZLucNuDcOtzUaeWZlZAkA8
ttXigLnCqR486JDPTi9ZscoZkZ+w7y6e/hH8t6d5Vjt48JVyfjPIaJY+km58LcN3
6AWSeGAdtRFHVzR7oHjVAkB4hutvxiOeiIVQNBhM6RSI9aBPMI21DoX2JRoxvNW2
cbvAhow217X9V0dVerEOKxnNYspXRrh36h7k4mQA+sDq
-----END RSA PRIVATE KEY-----
"""

cleartextCertificateRequestPEM = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIBnjCCAQcCAQAwXjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQH\n"
    "EwdDaGljYWdvMRcwFQYDVQQKEw5NeSBDb21wYW55IEx0ZDEXMBUGA1UEAxMORnJl\n"
    "ZGVyaWNrIERlYW4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANp6Y17WzKSw\n"
    "BsUWkXdqg6tnXy8H8hA1msCMWpc+/2KJ4mbv5NyD6UD+/SqagQqulPbF/DFea9nA\n"
    "E0zhmHJELcM8gUTIlXv/cgDWnmK4xj8YkjVUiCdqKRAKeuzLG1pGmwwF5lGeJpXN\n"
    "xQn5ecR0UYSOWj6TTGXB9VyUMQzCClcBAgMBAAGgADANBgkqhkiG9w0BAQUFAAOB\n"
    "gQAAJGuF/R/GGbeC7FbFW+aJgr9ee0Xbl6nlhu7pTe67k+iiKT2dsl2ti68MVTnu\n"
    "Vrb3HUNqOkiwsJf6kCtq5oPn3QVYzTa76Dt2y3Rtzv6boRSlmlfrgS92GNma8JfR\n"
    "oICQk3nAudi6zl1Dix3BCv1pUp5KMtGn3MeDEi6QFGy2rA==\n"
    "-----END CERTIFICATE REQUEST-----\n")

encryptedPrivateKeyPEM = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9573604A18579E9E

SHOho56WxDkT0ht10UTeKc0F5u8cqIa01kzFAmETw0MAs8ezYtK15NPdCXUm3X/2
a17G7LSF5bkxOgZ7vpXyMzun/owrj7CzvLxyncyEFZWvtvzaAhPhvTJtTIB3kf8B
8+qRcpTGK7NgXEgYBW5bj1y4qZkD4zCL9o9NQzsKI3Ie8i0239jsDOWR38AxjXBH
mGwAQ4Z6ZN5dnmM4fhMIWsmFf19sNyAML4gHenQCHhmXbjXeVq47aC2ProInJbrm
+00TcisbAQ40V9aehVbcDKtS4ZbMVDwncAjpXpcncC54G76N6j7F7wL7L/FuXa3A
fvSVy9n2VfF/pJ3kYSflLHH2G/DFxjF7dl0GxhKPxJjp3IJi9VtuvmN9R2jZWLQF
tfC8dXgy/P9CfFQhlinqBTEwgH0oZ/d4k4NVFDSdEMaSdmBAjlHpc+Vfdty3HVnV
rKXj//wslsFNm9kIwJGIgKUa/n2jsOiydrsk1mgH7SmNCb3YHgZhbbnq0qLat/HC
gHDt3FHpNQ31QzzL3yrenFB2L9osIsnRsDTPFNi4RX4SpDgNroxOQmyzCCV6H+d4
o1mcnNiZSdxLZxVKccq0AfRpHqpPAFnJcQHP6xyT9MZp6fBa0XkxDnt9kNU8H3Qw
7SJWZ69VXjBUzMlQViLuaWMgTnL+ZVyFZf9hTF7U/ef4HMLMAVNdiaGG+G+AjCV/
MbzjS007Oe4qqBnCWaFPSnJX6uLApeTbqAxAeyCql56ULW5x6vDMNC3dwjvS/CEh
11n8RkgFIQA0AhuKSIg3CbuartRsJnWOLwgLTzsrKYL4yRog1RJrtw==
-----END RSA PRIVATE KEY-----
"""
encryptedPrivateKeyPEMPassphrase = "foobar"

# Some PKCS#7 stuff.  Generated with the openssl command line:
#
#    openssl crl2pkcs7 -inform pem -outform pem -certfile s.pem -nocrl
#
# with a certificate and key (but the key should be irrelevant) in s.pem
pkcs7Data = """\
-----BEGIN PKCS7-----
MIIDNwYJKoZIhvcNAQcCoIIDKDCCAyQCAQExADALBgkqhkiG9w0BBwGgggMKMIID
BjCCAm+gAwIBAgIBATANBgkqhkiG9w0BAQQFADB7MQswCQYDVQQGEwJTRzERMA8G
A1UEChMITTJDcnlwdG8xFDASBgNVBAsTC00yQ3J5cHRvIENBMSQwIgYDVQQDExtN
MkNyeXB0byBDZXJ0aWZpY2F0ZSBNYXN0ZXIxHTAbBgkqhkiG9w0BCQEWDm5ncHNA
cG9zdDEuY29tMB4XDTAwMDkxMDA5NTEzMFoXDTAyMDkxMDA5NTEzMFowUzELMAkG
A1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIwEAYDVQQDEwlsb2NhbGhvc3Qx
HTAbBgkqhkiG9w0BCQEWDm5ncHNAcG9zdDEuY29tMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAKy+e3dulvXzV7zoTZWc5TzgApr8DmeQHTYC8ydfzH7EECe4R1Xh5kwI
zOuuFfn178FBiS84gngaNcrFi0Z5fAkCAwEAAaOCAQQwggEAMAkGA1UdEwQCMAAw
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0G
A1UdDgQWBBTPhIKSvnsmYsBVNWjj0m3M2z0qVTCBpQYDVR0jBIGdMIGagBT7hyNp
65w6kxXlxb8pUU/+7Sg4AaF/pH0wezELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0y
Q3J5cHRvMRQwEgYDVQQLEwtNMkNyeXB0byBDQTEkMCIGA1UEAxMbTTJDcnlwdG8g
Q2VydGlmaWNhdGUgTWFzdGVyMR0wGwYJKoZIhvcNAQkBFg5uZ3BzQHBvc3QxLmNv
bYIBADANBgkqhkiG9w0BAQQFAAOBgQA7/CqT6PoHycTdhEStWNZde7M/2Yc6BoJu
VwnW8YxGO8Sn6UJ4FeffZNcYZddSDKosw8LtPOeWoK3JINjAk5jiPQ2cww++7QGG
/g5NDjxFZNDJP1dGiLAxPW6JXwov4v0FmdzfLOZ01jDcgQQZqEpYlgpuI5JEWUQ9
Ho4EzbYCOaEAMQA=
-----END PKCS7-----
"""



class X509ExtTests(TestCase):
    def test_construction(self):
        """
        L{X509Extension} accepts an extension type name, a critical flag,
        and an extension value and returns an L{X509ExtensionType} instance.
        """
        basic = X509Extension('basicConstraints', True, 'CA:true')
        self.assertTrue(
            isinstance(basic, X509ExtensionType),
            "%r is of type %r, should be %r" % (
                basic, type(basic), X509ExtensionType))

        comment = X509Extension('nsComment', False, 'pyOpenSSL unit test')
        self.assertTrue(
            isinstance(comment, X509ExtensionType),
            "%r is of type %r, should be %r" % (
                comment, type(comment), X509ExtensionType))


    def test_invalid_extension(self):
        """
        L{X509Extension} raises something if it is passed a bad extension
        name or value.
        """
        self.assertRaises(
            Error, X509Extension, 'thisIsMadeUp', False, 'hi')
        self.assertRaises(
            Error, X509Extension, 'basicConstraints', False, 'blah blah')

        # Exercise a weird one (an extension which uses the r2i method).  This
        # exercises the codepath that requires a non-NULL ctx to be passed to
        # X509V3_EXT_nconf.  It can't work now because we provide no
        # configuration database.  It might be made to work in the future.
        self.assertRaises(
            Error, X509Extension, 'proxyCertInfo', True,
            'language:id-ppl-anyLanguage,pathlen:1,policy:text:AB')


    def test_get_critical(self):
        """
        L{X509ExtensionType.get_critical} returns the value of the
        extension's critical flag.
        """
        ext = X509Extension('basicConstraints', True, 'CA:true')
        self.assertTrue(ext.get_critical())
        ext = X509Extension('basicConstraints', False, 'CA:true')
        self.assertFalse(ext.get_critical())


    def test_get_short_name(self):
        """
        L{X509ExtensionType.get_short_name} returns a string giving the short
        type name of the extension.
        """
        ext = X509Extension('basicConstraints', True, 'CA:true')
        self.assertEqual(ext.get_short_name(), 'basicConstraints')
        ext = X509Extension('nsComment', True, 'foo bar')
        self.assertEqual(ext.get_short_name(), 'nsComment')



class PKeyTests(TestCase):
    """
    Unit tests for L{OpenSSL.crypto.PKey}.
    """
    def test_construction(self):
        """
        L{PKey} takes no arguments and returns a new L{PKeyType} instance.
        """
        self.assertRaises(TypeError, PKey, None)
        key = PKey()
        self.assertTrue(
            isinstance(key, PKeyType),
            "%r is of type %r, should be %r" % (key, type(key), PKeyType))


    def test_pregeneration(self):
        """
        L{PKeyType.bits} and L{PKeyType.type} return C{0} before the key is
        generated.
        """
        key = PKey()
        self.assertEqual(key.type(), 0)
        self.assertEqual(key.bits(), 0)


    def test_failedGeneration(self):
        """
        L{PKeyType.generate_key} takes two arguments, the first giving the key
        type as one of L{TYPE_RSA} or L{TYPE_DSA} and the second giving the
        number of bits to generate.  If an invalid type is specified or
        generation fails, L{Error} is raised.  If an invalid number of bits is
        specified, L{ValueError} or L{Error} is raised.
        """
        key = PKey()
        self.assertRaises(TypeError, key.generate_key)
        self.assertRaises(TypeError, key.generate_key, 1, 2, 3)
        self.assertRaises(TypeError, key.generate_key, "foo", "bar")
        self.assertRaises(Error, key.generate_key, -1, 0)

        self.assertRaises(ValueError, key.generate_key, TYPE_RSA, -1)
        self.assertRaises(ValueError, key.generate_key, TYPE_RSA, 0)

        # XXX RSA generation for small values of bits is fairly buggy in a wide
        # range of OpenSSL versions.  I need to figure out what the safe lower
        # bound for a reasonable number of OpenSSL versions is and explicitly
        # check for that in the wrapper.  The failure behavior is typically an
        # infinite loop inside OpenSSL.

        # self.assertRaises(Error, key.generate_key, TYPE_RSA, 2)

        # XXX DSA generation seems happy with any number of bits.  The DSS
        # says bits must be between 512 and 1024 inclusive.  OpenSSL's DSA
        # generator doesn't seem to care about the upper limit at all.  For
        # the lower limit, it uses 512 if anything smaller is specified.
        # So, it doesn't seem possible to make generate_key fail for
        # TYPE_DSA with a bits argument which is at least an int.

        # self.assertRaises(Error, key.generate_key, TYPE_DSA, -7)


    def test_rsaGeneration(self):
        """
        L{PKeyType.generate_key} generates an RSA key when passed
        L{TYPE_RSA} as a type and a reasonable number of bits.
        """
        bits = 128
        key = PKey()
        key.generate_key(TYPE_RSA, bits)
        self.assertEqual(key.type(), TYPE_RSA)
        self.assertEqual(key.bits(), bits)


    def test_dsaGeneration(self):
        """
        L{PKeyType.generate_key} generates a DSA key when passed
        L{TYPE_DSA} as a type and a reasonable number of bits.
        """
        # 512 is a magic number.  The DSS (Digital Signature Standard)
        # allows a minimum of 512 bits for DSA.  DSA_generate_parameters
        # will silently promote any value below 512 to 512.
        bits = 512
        key = PKey()
        key.generate_key(TYPE_DSA, bits)
        self.assertEqual(key.type(), TYPE_DSA)
        self.assertEqual(key.bits(), bits)


    def test_regeneration(self):
        """
        L{PKeyType.generate_key} can be called multiple times on the same
        key to generate new keys.
        """
        key = PKey()
        for type, bits in [(TYPE_RSA, 512), (TYPE_DSA, 576)]:
             key.generate_key(type, bits)
             self.assertEqual(key.type(), type)
             self.assertEqual(key.bits(), bits)



class X509NameTests(TestCase):
    """
    Unit tests for L{OpenSSL.crypto.X509Name}.
    """
    def _x509name(self, **attrs):
        # XXX There's no other way to get a new X509Name yet.
        name = X509().get_subject()
        attrs = attrs.items()
        # Make the order stable - order matters!
        attrs.sort(lambda (k1, v1), (k2, v2): cmp(v1, v2))
        for k, v in attrs:
            setattr(name, k, v)
        return name


    def test_attributes(self):
        """
        L{X509NameType} instances have attributes for each standard (?)
        X509Name field.
        """
        name = self._x509name()
        name.commonName = "foo"
        self.assertEqual(name.commonName, "foo")
        self.assertEqual(name.CN, "foo")
        name.CN = "baz"
        self.assertEqual(name.commonName, "baz")
        self.assertEqual(name.CN, "baz")
        name.commonName = "bar"
        self.assertEqual(name.commonName, "bar")
        self.assertEqual(name.CN, "bar")
        name.CN = "quux"
        self.assertEqual(name.commonName, "quux")
        self.assertEqual(name.CN, "quux")


    def test_copy(self):
        """
        L{X509Name} creates a new L{X509NameType} instance with all the same
        attributes as an existing L{X509NameType} instance when called with
        one.
        """
        name = self._x509name(commonName="foo", emailAddress="bar@example.com")

        copy = X509Name(name)
        self.assertEqual(copy.commonName, "foo")
        self.assertEqual(copy.emailAddress, "bar@example.com")

        # Mutate the copy and ensure the original is unmodified.
        copy.commonName = "baz"
        self.assertEqual(name.commonName, "foo")

        # Mutate the original and ensure the copy is unmodified.
        name.emailAddress = "quux@example.com"
        self.assertEqual(copy.emailAddress, "bar@example.com")


    def test_repr(self):
        """
        L{repr} passed an L{X509NameType} instance should return a string
        containing a description of the type and the NIDs which have been set
        on it.
        """
        name = self._x509name(commonName="foo", emailAddress="bar")
        self.assertEqual(
            repr(name),
            "<X509Name object '/emailAddress=bar/CN=foo'>")


    def test_comparison(self):
        """
        L{X509NameType} instances should compare based on their NIDs.
        """
        def _equality(a, b, assertTrue, assertFalse):
            assertTrue(a == b, "(%r == %r) --> False" % (a, b))
            assertFalse(a != b)
            assertTrue(b == a)
            assertFalse(b != a)

        def assertEqual(a, b):
            _equality(a, b, self.assertTrue, self.assertFalse)

        # Instances compare equal to themselves.
        name = self._x509name()
        assertEqual(name, name)

        # Empty instances should compare equal to each other.
        assertEqual(self._x509name(), self._x509name())

        # Instances with equal NIDs should compare equal to each other.
        assertEqual(self._x509name(commonName="foo"),
                    self._x509name(commonName="foo"))

        # Instance with equal NIDs set using different aliases should compare
        # equal to each other.
        assertEqual(self._x509name(commonName="foo"),
                    self._x509name(CN="foo"))

        # Instances with more than one NID with the same values should compare
        # equal to each other.
        assertEqual(self._x509name(CN="foo", organizationalUnitName="bar"),
                    self._x509name(commonName="foo", OU="bar"))

        def assertNotEqual(a, b):
            _equality(a, b, self.assertFalse, self.assertTrue)

        # Instances with different values for the same NID should not compare
        # equal to each other.
        assertNotEqual(self._x509name(CN="foo"),
                       self._x509name(CN="bar"))

        # Instances with different NIDs should not compare equal to each other.
        assertNotEqual(self._x509name(CN="foo"),
                       self._x509name(OU="foo"))

        def _inequality(a, b, assertTrue, assertFalse):
            assertTrue(a < b)
            assertTrue(a <= b)
            assertTrue(b > a)
            assertTrue(b >= a)
            assertFalse(a > b)
            assertFalse(a >= b)
            assertFalse(b < a)
            assertFalse(b <= a)

        def assertLessThan(a, b):
            _inequality(a, b, self.assertTrue, self.assertFalse)

        # An X509Name with a NID with a value which sorts less than the value
        # of the same NID on another X509Name compares less than the other
        # X509Name.
        assertLessThan(self._x509name(CN="abc"),
                       self._x509name(CN="def"))

        def assertGreaterThan(a, b):
            _inequality(a, b, self.assertFalse, self.assertTrue)

        # An X509Name with a NID with a value which sorts greater than the
        # value of the same NID on another X509Name compares greater than the
        # other X509Name.
        assertGreaterThan(self._x509name(CN="def"),
                          self._x509name(CN="abc"))


    def test_hash(self):
        """
        L{X509Name.hash} returns an integer hash based on the value of the
        name.
        """
        a = self._x509name(CN="foo")
        b = self._x509name(CN="foo")
        self.assertEqual(a.hash(), b.hash())
        a.CN = "bar"
        self.assertNotEqual(a.hash(), b.hash())


    def test_der(self):
        """
        L{X509Name.der} returns the DER encoded form of the name.
        """
        a = self._x509name(CN="foo", C="US")
        self.assertEqual(
            a.der(),
            '0\x1b1\x0b0\t\x06\x03U\x04\x06\x13\x02US'
            '1\x0c0\n\x06\x03U\x04\x03\x13\x03foo')


    def test_get_components(self):
        """
        L{X509Name.get_components} returns a C{list} of two-tuples of C{str}
        giving the NIDs and associated values which make up the name.
        """
        a = self._x509name()
        self.assertEqual(a.get_components(), [])
        a.CN = "foo"
        self.assertEqual(a.get_components(), [("CN", "foo")])
        a.organizationalUnitName = "bar"
        self.assertEqual(
            a.get_components(),
            [("CN", "foo"), ("OU", "bar")])


class _PKeyInteractionTestsMixin:
    """
    Tests which involve another thing and a PKey.
    """
    def signable(self):
        """
        Return something with a C{set_pubkey}, C{set_pubkey}, and C{sign} method.
        """
        raise NotImplementedError()


    def test_signWithUngenerated(self):
        """
        L{X509Req.sign} raises L{ValueError} when pass a L{PKey} with no parts.
        """
        request = self.signable()
        key = PKey()
        self.assertRaises(ValueError, request.sign, key, 'MD5')


    def test_signWithPublicKey(self):
        """
        L{X509Req.sign} raises L{ValueError} when pass a L{PKey} with no
        private part as the signing key.
        """
        request = self.signable()
        key = PKey()
        key.generate_key(TYPE_RSA, 512)
        request.set_pubkey(key)
        pub = request.get_pubkey()
        self.assertRaises(ValueError, request.sign, pub, 'MD5')



class X509ReqTests(TestCase, _PKeyInteractionTestsMixin):
    """
    Tests for L{OpenSSL.crypto.X509Req}.
    """
    def signable(self):
        """
        Create and return a new L{X509Req}.
        """
        return X509Req()


    def test_construction(self):
        """
        L{X509Req} takes no arguments and returns an L{X509ReqType} instance.
        """
        request = X509Req()
        self.assertTrue(
            isinstance(request, X509ReqType),
            "%r is of type %r, should be %r" % (request, type(request), X509ReqType))


    def test_version(self):
        """
        L{X509ReqType.set_version} sets the X.509 version of the certificate
        request.  L{X509ReqType.get_version} returns the X.509 version of
        the certificate request.  The initial value of the version is 0.
        """
        request = X509Req()
        self.assertEqual(request.get_version(), 0)
        request.set_version(1)
        self.assertEqual(request.get_version(), 1)
        request.set_version(3)
        self.assertEqual(request.get_version(), 3)


    def test_get_subject(self):
        """
        L{X509ReqType.get_subject} returns an L{X509Name} for the subject of
        the request and which is valid even after the request object is
        otherwise dead.
        """
        request = X509Req()
        subject = request.get_subject()
        self.assertTrue(
            isinstance(subject, X509NameType),
            "%r is of type %r, should be %r" % (subject, type(subject), X509NameType))
        subject.commonName = "foo"
        self.assertEqual(request.get_subject().commonName, "foo")
        del request
        subject.commonName = "bar"
        self.assertEqual(subject.commonName, "bar")



class X509Tests(TestCase, _PKeyInteractionTestsMixin):
    """
    Tests for L{OpenSSL.crypto.X509}.
    """
    pemData = cleartextCertificatePEM + cleartextPrivateKeyPEM

    def signable(self):
        """
        Create and return a new L{X509}.
        """
        return X509()


    def test_construction(self):
        """
        L{X509} takes no arguments and returns an instance of L{X509Type}.
        """
        certificate = X509()
        self.assertTrue(
            isinstance(certificate, X509Type),
            "%r is of type %r, should be %r" % (certificate,
                                                type(certificate),
                                                X509Type))


    def test_serial_number(self):
        """
        The serial number of an L{X509Type} can be retrieved and modified with
        L{X509Type.get_serial_number} and L{X509Type.set_serial_number}.
        """
        certificate = X509()
        self.assertRaises(TypeError, certificate.set_serial_number)
        self.assertRaises(TypeError, certificate.set_serial_number, 1, 2)
        self.assertRaises(TypeError, certificate.set_serial_number, "1")
        self.assertRaises(TypeError, certificate.set_serial_number, 5.5)
        self.assertEqual(certificate.get_serial_number(), 0)
        certificate.set_serial_number(1)
        self.assertEqual(certificate.get_serial_number(), 1)
        certificate.set_serial_number(2 ** 32 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 32 + 1)
        certificate.set_serial_number(2 ** 64 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 64 + 1)
        certificate.set_serial_number(2 ** 128 + 1)
        self.assertEqual(certificate.get_serial_number(), 2 ** 128 + 1)


    def _setBoundTest(self, which):
        """
        L{X509Type.set_notBefore} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the beginning of the certificate's validity
        period to it.
        """
        certificate = X509()
        set = getattr(certificate, 'set_not' + which)
        get = getattr(certificate, 'get_not' + which)

        # Starts with no value.
        self.assertEqual(get(), None)

        # GMT (Or is it UTC?) -exarkun
        when = "20040203040506Z"
        set(when)
        self.assertEqual(get(), when)

        # A plus two hours and thirty minutes offset
        when = "20040203040506+0530"
        set(when)
        self.assertEqual(get(), when)

        # A minus one hour fifteen minutes offset
        when = "20040203040506-0115"
        set(when)
        self.assertEqual(get(), when)

        # An invalid string results in a ValueError
        self.assertRaises(ValueError, set, "foo bar")


    def test_set_notBefore(self):
        """
        L{X509Type.set_notBefore} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the beginning of the certificate's validity
        period to it.
        """
        self._setBoundTest("Before")


    def test_set_notAfter(self):
        """
        L{X509Type.set_notAfter} takes a string in the format of an ASN1
        GENERALIZEDTIME and sets the end of the certificate's validity period
        to it.
        """
        self._setBoundTest("After")


    def test_get_notBefore(self):
        """
        L{X509Type.get_notBefore} returns a string in the format of an ASN1
        GENERALIZEDTIME even for certificates which store it as UTCTIME
        internally.
        """
        cert = load_certificate(FILETYPE_PEM, self.pemData)
        self.assertEqual(cert.get_notBefore(), "20090325123658Z")


    def test_get_notAfter(self):
        """
        L{X509Type.get_notAfter} returns a string in the format of an ASN1
        GENERALIZEDTIME even for certificates which store it as UTCTIME
        internally.
        """
        cert = load_certificate(FILETYPE_PEM, self.pemData)
        self.assertEqual(cert.get_notAfter(), "20170611123658Z")


    def test_digest(self):
        """
        L{X509.digest} returns a string giving ":"-separated hex-encoded words
        of the digest of the certificate.
        """
        cert = X509()
        self.assertEqual(
            cert.digest("md5"),
            "A8:EB:07:F8:53:25:0A:F2:56:05:C5:A5:C4:C4:C7:15")



class PKCS12Tests(TestCase):
    """
    Tests functions in the L{OpenSSL.crypto.PKCS12} module.
    """
    pemData = cleartextCertificatePEM + cleartextPrivateKeyPEM

    def test_empty_construction(self):
        """
        Confirm L{OpenSSL.crypto.PKCS12} returs a PKCS12.  Confirm
        that the new PKCS12 is empty.
        """
        self.assertTrue(type(PKCS12).__name__, 'PKCS12')
        p12 = PKCS12() 
        self.assertTrue(isinstance(p12, PKCS12))
        self.assertEqual(None, p12.get_certificate())
        self.assertEqual(None, p12.get_privatekey())
        self.assertEqual(None, p12.get_ca_certificates())
        self.assertEqual(None, p12.get_friendlyname())


    def test_type_errors(self):
        """
        Try the set functions L{OpenSSL.crypto.PKCS12} with bad
        types to see them raise TypeError.
        """
        p12 = PKCS12() 
        self.assertRaises(TypeError, p12.set_certificate, 3)
        self.assertRaises(TypeError, p12.set_certificate, PKey())
        self.assertRaises(TypeError, p12.set_certificate, X509)
        self.assertRaises(TypeError, p12.set_privatekey, 3)
        self.assertRaises(TypeError, p12.set_privatekey, 'legbone')
        self.assertRaises(TypeError, p12.set_privatekey, X509())
        self.assertRaises(TypeError, p12.set_ca_certificates, 3)
        self.assertRaises(TypeError, p12.set_ca_certificates, X509())
        self.assertRaises(TypeError, p12.set_ca_certificates, (3, 4))
        self.assertRaises(TypeError, p12.set_ca_certificates, ( PKey(), ))
        self.assertRaises(TypeError, p12.set_friendlyname, 6)
        self.assertRaises(TypeError, p12.set_friendlyname, ('foo', 'bar'))


    def test_key_only(self):
        """
        Run L{OpenSSL.crypto.PKCS12.export} and 
        L{OpenSSL.crypto.load_pkcs12} without any certs, only
        a private key.
        """
        passwd = 'blah'
        p12 = PKCS12()
        pkey = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM) 
        p12.set_privatekey( pkey )
        self.assertEqual(None, p12.get_certificate())
        self.assertEqual(pkey, p12.get_privatekey())
        dumped_p12 = p12.export(passphrase=passwd, iter=2, maciter=3)
        p12 = load_pkcs12(dumped_p12, passwd)
        self.assertEqual(None, p12.get_ca_certificates())
        self.assertEqual(None, p12.get_certificate())
        #  It's actually in the pkcs12, but we silently don't find it (a key without a cert)
        #self.assertEqual(cleartextPrivateKeyPEM, dump_privatekey(FILETYPE_PEM, p12.get_privatekey()))


    def test_cert_only(self):
        """
        Run L{OpenSSL.crypto.PKCS12.export} and 
        L{OpenSSL.crypto.load_pkcs12} without a private key.
        Strangely, OpenSSL converts it to a CA cert.
        """
        passwd = 'blah'
        p12 = PKCS12()
        cert = load_certificate(FILETYPE_PEM, cleartextCertificatePEM) 
        p12.set_certificate( cert )
        self.assertEqual(cert, p12.get_certificate())
        self.assertEqual(None, p12.get_privatekey())
        dumped_p12 = p12.export(passphrase=passwd, iter=2, maciter=3)
        p12 = load_pkcs12(dumped_p12, passwd)
        self.assertEqual(None, p12.get_privatekey())
        self.assertEqual(None, p12.get_certificate())
        self.assertEqual(cleartextCertificatePEM, dump_certificate(FILETYPE_PEM, p12.get_ca_certificates()[0]))


    def gen_pkcs12( self, cert_pem=None, key_pem=None, ca_pem=None, fn=None ):
        """
        Generate a PKCS12 object with components from PEM.
        Verify that the set functions return None.
        """
        p12 = PKCS12()
        if cert_pem:
            ret = p12.set_certificate(load_certificate(FILETYPE_PEM, cert_pem))
            self.assertEqual(ret, None)
        if key_pem:
            ret = p12.set_privatekey( load_privatekey(FILETYPE_PEM, key_pem) )
            self.assertEqual(ret, None)
        if ca_pem:
            ret = p12.set_ca_certificates( ( load_certificate(FILETYPE_PEM, ca_pem), ) )
            self.assertEqual(ret, None)
        if fn:
            ret = p12.set_friendlyname( fn )
            self.assertEqual(ret, None)
        return p12


    def check_recovery(self, p12_str, key=None, cert=None, ca=None, 
                       passwd='', extra=()):
        """
        Use openssl program to confirm three components are recoverable 
        from a PKCS12 string.
        """
        if key:
            recovered_key = _runopenssl(p12_str, "pkcs12", '-nocerts', '-nodes',
                                '-passin', 'pass:'+passwd, *extra ) 
            self.assertEqual(recovered_key[-len(key):], key)
        if cert:
            recovered_cert = _runopenssl(p12_str, "pkcs12", '-clcerts', '-nodes', 
                               '-passin', 'pass:'+passwd, '-nokeys', *extra)
            self.assertEqual(recovered_cert[-len(cert):], cert)
        if ca:
            recovered_cert = _runopenssl(p12_str, "pkcs12", '-cacerts', '-nodes', 
                                '-passin', 'pass:'+passwd, '-nokeys', *extra)
            self.assertEqual(recovered_cert[-len(ca):], ca)


    def test_load_pkcs12(self):
        """
        Generate a PKCS12 string using openssl, then load it with
        L{load_pkcs12} and verify the returned object.
        """
        passwd = 'whatever'
        pem = client_key_pem + client_cert_pem
        p12_str = _runopenssl(pem, "pkcs12", '-export', '-clcerts', 
                                   '-passout', 'pass:'+passwd)
        p12 = load_pkcs12(p12_str, passwd)
        # verify 
        self.assertTrue(isinstance(p12, PKCS12))
        self.assertTrue(isinstance(p12, PKCS12Type))
        cert_pem = dump_certificate(FILETYPE_PEM, p12.get_certificate())
        self.assertEqual(cert_pem, client_cert_pem)
        key_pem = dump_privatekey(FILETYPE_PEM, p12.get_privatekey())
        self.assertEqual(key_pem, client_key_pem)
        self.assertEqual(None, p12.get_ca_certificates())


    def test_load_pkcs12_garbage(self):
        """
        Use L{load_pkcs12} on a string of garbage.
        """
        passwd = 'whatever'
        e = self.assertRaises(Error, load_pkcs12, 'fruit loops', passwd)
        self.assertEqual( e[0][0][0], 'asn1 encoding routines')
        self.assertEqual( len(e[0][0]), 3)


    def test_replace(self):
        """
        Test replacing components of a L{PKCS12} object.  Test multiple
        CA certificates.
        """
        p12 = self.gen_pkcs12( client_cert_pem, client_key_pem, root_cert_pem )
        p12.set_certificate( load_certificate(FILETYPE_PEM, server_cert_pem) )
        p12.set_privatekey( load_privatekey(FILETYPE_PEM, server_key_pem) )
        root_cert = load_certificate(FILETYPE_PEM, root_cert_pem) 
        client_cert = load_certificate(FILETYPE_PEM, client_cert_pem)
        p12.set_ca_certificates( [ root_cert, ] )  # not a tuple
        self.assertEqual(1, len(p12.get_ca_certificates()))
        self.assertEqual(root_cert, p12.get_ca_certificates()[0])
        p12.set_ca_certificates( [ client_cert, root_cert ] )
        self.assertEqual(2, len(p12.get_ca_certificates()))
        self.assertEqual(client_cert, p12.get_ca_certificates()[0])
        self.assertEqual(root_cert, p12.get_ca_certificates()[1])


    def test_friendly_name(self):
        """
        Test that we can get and set a friendlyName on a PKCS12.
        Test that we can export a L{PKCS12} with a friendly name,
        and confirm we can load the PKCS12 and find the friendly name.
        Use the openssl program to also verify the certs in the PKCS12.
        """
        passwd = 'Dogmeat[]{}!@#$%^&*()~`?/.,<>-_+=";:'
        p12 = self.gen_pkcs12( server_cert_pem, server_key_pem, root_cert_pem )
        for friendly_name in ('Serverlicious', None, '###'):
            p12.set_friendlyname(friendly_name)
            self.assertEqual(p12.get_friendlyname(), friendly_name)
            dumped_p12 = p12.export(passphrase=passwd, iter=2, maciter=3) 
            reloaded_p12 = load_pkcs12(dumped_p12, passwd)
            self.assertEqual(p12.get_friendlyname(), 
                    reloaded_p12.get_friendlyname())
            # We would use the openssl program to confirm the friendly 
            # name, but it is not possible.  The pkcs12 command 
            # does not store the friendly name in the cert's 
            # alias, which we could then extract.
            self.check_recovery(dumped_p12, key=server_key_pem, 
                    cert=server_cert_pem, ca=root_cert_pem, passwd=passwd)


    def test_various_empty_passphrases(self):
        """
        Test that missing, None, and '' passphrases are identical
        for PKCS12 export.
        """
        p12 = self.gen_pkcs12( client_cert_pem, client_key_pem, root_cert_pem )
        passwd = ''
        dumped_p12_empty = p12.export(passphrase=passwd, iter=2, maciter=0)
        dumped_p12_none  = p12.export(passphrase=None,   iter=3, maciter=2)
        dumped_p12_nopw  = p12.export(                   iter=9, maciter=4)
        for dumped_p12 in ( dumped_p12_empty, dumped_p12_none, dumped_p12_nopw ):
            self.check_recovery( dumped_p12, key=client_key_pem, 
                    cert=client_cert_pem, ca=root_cert_pem, passwd=passwd)


    def test_removing_ca_cert(self):
        """
        Test that we can remove a CA cert from a PKCS12 object.
        """
        p12 = self.gen_pkcs12( server_cert_pem, server_key_pem, root_cert_pem )
        p12.set_ca_certificates( None )
        self.assertEqual(None, p12.get_ca_certificates())


    def test_export_without_mac(self):
        """
        Export a PKCS12 without a MAC (message integrity checksum).
        Verify it with the openssl program.
        """
        passwd = 'Lake Michigan'
        p12 = self.gen_pkcs12( server_cert_pem, server_key_pem, root_cert_pem )
        dumped_p12 = p12.export(maciter=-1, passphrase=passwd, iter=2)
        self.check_recovery(dumped_p12, key=server_key_pem, 
                cert=server_cert_pem, passwd=passwd, extra=( '-nomacver', ))
        #  We can't load PKCS12 without MAC, because we use PCKS_parse()
        #p12 = load_pkcs12(dumped_p12, passwd)


    def test_zero_len_list_for_ca(self):
        """
        Export a PKCS12 with a zero length list for CA.
        Verify it with the openssl program.
        """
        passwd = 'Hobie 18'
        p12 = self.gen_pkcs12( server_cert_pem, server_key_pem )
        p12.set_ca_certificates( [] )
        self.assertEqual((), p12.get_ca_certificates())
        dumped_p12 = p12.export(passphrase=passwd, iter=3)
        self.check_recovery(dumped_p12, key=server_key_pem, 
                cert=server_cert_pem, passwd=passwd, )


    def test_export_without_args(self):
        """
        Run L{OpenSSL.crypto.PKCS12.export} without any
        args to show they are all truely optional.  Confirm
        with openssl program.
        """
        p12 = self.gen_pkcs12( server_cert_pem, server_key_pem, root_cert_pem )
        dumped_p12 = p12.export()  # no args
        self.check_recovery( dumped_p12, key=server_key_pem, 
                cert=server_cert_pem, passwd='')


    def test_key_cert_mismatch(self):
        """
        Verify L{OpenSSL.crypto.PKCS12.export} raises an exception when a
        key and certificate mismatch.
        """
        p12 = self.gen_pkcs12( server_cert_pem, client_key_pem, root_cert_pem )
        self.assertRaises( Error, p12.export )



def _runopenssl(stdin, *args):
    """
    Run the command line openssl tool with the given arguments and write
    the given string to its stdin.  Args are not safe for single quotes.
    """
    write, read = popen2("'" + "' '".join(("openssl",) + args) + "'", "b")
    write.write(stdin)
    write.close()
    return read.read()



class FunctionTests(TestCase):
    """
    Tests for free-functions in the L{OpenSSL.crypto} module.
    """
    def test_load_privatekey_wrongPassphrase(self):
        """
        L{load_privatekey} raises L{OpenSSL.crypto.Error} when it is passed an
        encrypted PEM and an incorrect passphrase.
        """
        self.assertRaises(
            Error,
            load_privatekey, FILETYPE_PEM, encryptedPrivateKeyPEM, "quack")


    def test_load_privatekey_passphrase(self):
        """
        L{load_privatekey} can create a L{PKey} object from an encrypted PEM
        string if given the passphrase.
        """
        key = load_privatekey(
            FILETYPE_PEM, encryptedPrivateKeyPEM,
            encryptedPrivateKeyPEMPassphrase)
        self.assertTrue(isinstance(key, PKeyType))


    def test_load_privatekey_wrongPassphraseCallback(self):
        """
        L{load_privatekey} raises L{OpenSSL.crypto.Error} when it is passed an
        encrypted PEM and a passphrase callback which returns an incorrect
        passphrase.
        """
        called = []
        def cb(*a):
            called.append(None)
            return "quack"
        self.assertRaises(
            Error,
            load_privatekey, FILETYPE_PEM, encryptedPrivateKeyPEM, cb)
        self.assertTrue(called)

    def test_load_privatekey_passphraseCallback(self):
        """
        L{load_privatekey} can create a L{PKey} object from an encrypted PEM
        string if given a passphrase callback which returns the correct
        password.
        """
        called = []
        def cb(writing):
            called.append(writing)
            return encryptedPrivateKeyPEMPassphrase
        key = load_privatekey(FILETYPE_PEM, encryptedPrivateKeyPEM, cb)
        self.assertTrue(isinstance(key, PKeyType))
        self.assertEqual(called, [False])


    def test_dump_privatekey_passphrase(self):
        """
        L{dump_privatekey} writes an encrypted PEM when given a passphrase.
        """
        passphrase = "foo"
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        pem = dump_privatekey(FILETYPE_PEM, key, "blowfish", passphrase)
        self.assertTrue(isinstance(pem, str))
        loadedKey = load_privatekey(FILETYPE_PEM, pem, passphrase)
        self.assertTrue(isinstance(loadedKey, PKeyType))
        self.assertEqual(loadedKey.type(), key.type())
        self.assertEqual(loadedKey.bits(), key.bits())


    def test_dump_certificate(self):
        """
        L{dump_certificate} writes PEM, DER, and text.
        """
        pemData = cleartextCertificatePEM + cleartextPrivateKeyPEM
        cert = load_certificate(FILETYPE_PEM, pemData)
        dumped_pem = dump_certificate(FILETYPE_PEM, cert)
        self.assertEqual(dumped_pem, cleartextCertificatePEM)
        dumped_der = dump_certificate(FILETYPE_ASN1, cert)
        good_der = _runopenssl(dumped_pem, "x509", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        cert2 = load_certificate(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_certificate(FILETYPE_PEM, cert2)
        self.assertEqual(dumped_pem2, cleartextCertificatePEM)
        dumped_text = dump_certificate(FILETYPE_TEXT, cert)
        good_text = _runopenssl(dumped_pem, "x509", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_privatekey(self):
        """
        L{dump_privatekey} writes a PEM, DER, and text.
        """
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        dumped_pem = dump_privatekey(FILETYPE_PEM, key)
        self.assertEqual(dumped_pem, cleartextPrivateKeyPEM)
        dumped_der = dump_privatekey(FILETYPE_ASN1, key)
        # XXX This OpenSSL call writes "writing RSA key" to standard out.  Sad.
        good_der = _runopenssl(dumped_pem, "rsa", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        key2 = load_privatekey(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_privatekey(FILETYPE_PEM, key2)
        self.assertEqual(dumped_pem2, cleartextPrivateKeyPEM)
        dumped_text = dump_privatekey(FILETYPE_TEXT, key)
        good_text = _runopenssl(dumped_pem, "rsa", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_certificate_request(self):
        """
        L{dump_certificate_request} writes a PEM, DER, and text.
        """
        req = load_certificate_request(FILETYPE_PEM, cleartextCertificateRequestPEM)
        dumped_pem = dump_certificate_request(FILETYPE_PEM, req)
        self.assertEqual(dumped_pem, cleartextCertificateRequestPEM)
        dumped_der = dump_certificate_request(FILETYPE_ASN1, req)
        good_der = _runopenssl(dumped_pem, "req", "-outform", "DER")
        self.assertEqual(dumped_der, good_der)
        req2 = load_certificate_request(FILETYPE_ASN1, dumped_der)
        dumped_pem2 = dump_certificate_request(FILETYPE_PEM, req2)
        self.assertEqual(dumped_pem2, cleartextCertificateRequestPEM)
        dumped_text = dump_certificate_request(FILETYPE_TEXT, req)
        good_text = _runopenssl(dumped_pem, "req", "-noout", "-text")
        self.assertEqual(dumped_text, good_text)


    def test_dump_privatekey_passphraseCallback(self):
        """
        L{dump_privatekey} writes an encrypted PEM when given a callback which
        returns the correct passphrase.
        """
        passphrase = "foo"
        called = []
        def cb(writing):
            called.append(writing)
            return passphrase
        key = load_privatekey(FILETYPE_PEM, cleartextPrivateKeyPEM)
        pem = dump_privatekey(FILETYPE_PEM, key, "blowfish", cb)
        self.assertTrue(isinstance(pem, str))
        self.assertEqual(called, [True])
        loadedKey = load_privatekey(FILETYPE_PEM, pem, passphrase)
        self.assertTrue(isinstance(loadedKey, PKeyType))
        self.assertEqual(loadedKey.type(), key.type())
        self.assertEqual(loadedKey.bits(), key.bits())


    def test_load_pkcs7_data(self):
        """
        L{load_pkcs7_data} accepts a PKCS#7 string and returns an instance of
        L{PKCS7Type}.
        """
        pkcs7 = load_pkcs7_data(FILETYPE_PEM, pkcs7Data)
        self.assertTrue(isinstance(pkcs7, PKCS7Type))



class NetscapeSPKITests(TestCase):
    """
    Tests for L{OpenSSL.crypto.NetscapeSPKI}.
    """
    def test_construction(self):
        """
        L{NetscapeSPKI} returns an instance of L{NetscapeSPKIType}.
        """
        nspki = NetscapeSPKI()
        self.assertTrue(isinstance(nspki, NetscapeSPKIType))



if __name__ == '__main__':
    main()
