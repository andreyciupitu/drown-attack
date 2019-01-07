# Drown attack 'extra-clear' oracle

Implementation of the 'extra-clear' oracle for the drown attack on TLS.
Based on the implementation at: https://github.com/Tim---/drown

## Requirements
We need a previous version of OpenSSL that is vulnerable to the attack:

    wget https://www.openssl.org/source/openssl-1.0.1l.tar.gz
    tar xzf openssl-1.0.1l.tar.gz
	cd openssl-1.0.1l
    ./config enable-ssl2 enable-weak-ciphers --openssldir=install_dir
    make && make install

We need to generate a pair of rsa keys:

	cd instal_dir
	./bin/openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 123

We start a new OpenSSL SSLv2 server using:

	./bin/openssl s_server -cert cert.pem -key key.pem -accept 4433 -www -ssl2


In another terminal we can connect to the server using:

	./bin/openssl s_client -connect 127.0.0.1:4433 -cipher kRSA


## Compilation
To build the executable from the source files use:

    SSL_PREFIX=openssl_install_dir make

## Note

The oracle requires a SSLv2 compliant input (encrypted key).
The DROWN attack transforms the TLS PMS into an SSLv2 compliant ciphertext, however,
for the purpose of this project, we have captured directly SSLv2 traffic.