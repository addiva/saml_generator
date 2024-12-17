It has code that generates Metadata and SAMLResponse; it is built in Java.
DO CONFIGURE IT before running it.
It is built with IDP initiated process in mind.

For generating the keys the commands are following (set the days you need for it to be valid):
openssl genpkey -algorithm RSA -out privateKey.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key privateKey.pem -out certificate.pem -days 365
