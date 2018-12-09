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

	if ((pos[0] & TWO_BYTE_BIT))
	{
		s->s2->three_byte_header = 0;
		s->s2->rlength &= TWO_BYTE_MASK;
	}
	// else
	// {
		// s->s2->three_byte_header = 1;
		// s->s2->rlength &= THREE_BYTE_MASK;
	// }
	pos += 2;

	// // Read padding if any
	// if (s->s2->three_byte_header)
		// s->s2->padding = *(pos++);
	// else
		s->s2->padding = 0;

	// Adjust fields if cleartext or not
	s->s2->mac_data = pos;
	s->s2->ract_data = pos;
	s->s2->ract_data_length = s->s2->rlength;
	// if (!s->s2->clear_text)
	// {
		// unsigned int mac_size = EVP_MD_CTX_size(s->read_hash);
		// s->s2->ract_data += mac_size;
		// s->s2->ract_data_length -= mac_size;
	// }
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

	return 0;
}