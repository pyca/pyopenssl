all: client_cert.pem intermediate_server_cert.pem server_cert.pem intermediate_cert.pem
root_cert.pem: root_key.pem
	openssl req -x509 -new -key $< -extensions v3_ca -out $@ -days 365000 -subj '/C=US/ST=IL/L=Chicago/O=Testing/CN=Testing Root CA' -sha256

intermediate_cert.pem: intermediate_key.pem root_cert.pem
	openssl req -new -key $< -out $<.csr -subj '/CN=dummy'
	OPENSSL_CONF=./openssl.cnf openssl ca -batch -out $@ -in $<.csr -create_serial -md sha512 -extensions v3_ca -subj '/CN=intermediate/O=org/OU=org-unit/C=US/ST=CA/L=San Diego'

server_cert.pem: server_key.pem root_cert.pem
	openssl req -new -key $< -out $<.csr -subj '/CN=lovely server'
	OPENSSL_CONF=./openssl.cnf openssl ca -batch -out $@ -in $<.csr -create_serial -md sha512 -subj '/CN=lovely server' -extensions v3_req

intermediate_server_cert.pem: intermediate_server_key.pem intermediate_cert.pem
	openssl req -new -key $< -out $<.csr -subj '/CN=dummy'
	OPENSSL_CONF=./openssl.cnf openssl ca -batch -out $@ -in $<.csr -keyfile intermediate_key.pem -cert intermediate_cert.pem -create_serial -md sha512 -subj '/CN=intermediate-service/O=org/OU=org-unit/C=US/ST=CA/L=San Diego' -extensions v3_req -days 6840

client_cert.pem: client_key.pem root_cert.pem
	openssl req -new -key $< -out $<.csr -subj '/CN=ugly client'
	OPENSSL_CONF=./openssl.cnf openssl ca -batch -out $@ -in $<.csr -create_serial -md sha512 -subj '/CN=ugly client' -extensions v3_client

init:
	rm -rf certs ; mkdir certs
	echo -n > index.txt
	echo -n > index.txt.attr
