// This code is public-domain - it is based on libcrypt 
// Placed in the public domain by Wei Dai and other contributors.

#ifndef _SHA1_H
#define _SHA1_H

#define SHA1_HASH_LENGTH    20
#define SHA1_BLOCK_LENGTH   64
#define SHA1_K0             0x5a827999
#define SHA1_K20            0x6ed9eba1
#define SHA1_K40            0x8f1bbcdc
#define SHA1_K60            0xca62c1d6
#define SHA1_HMAC_IPAD      0x36
#define SHA1_HMAC_OPAD      0x5c

union sha1_buffer {
    uint8_t b[SHA1_BLOCK_LENGTH];
    uint32_t w[SHA1_BLOCK_LENGTH / 4];
};

union sha1_state {
    uint8_t b[SHA1_HASH_LENGTH];
    uint32_t w[SHA1_HASH_LENGTH / 4];
};

typedef struct sha1_t
{
    union sha1_buffer buffer;
    uint8_t buffer_offset;
    union sha1_state state;
    uint32_t byte_count;
    uint8_t key_buffer[SHA1_BLOCK_LENGTH];
    uint8_t inner_hash[SHA1_HASH_LENGTH];
} sha1;

void sha1_init(sha1 *s);
void sha1_writebyte(sha1 *s, uint8_t data);
void sha1_write(sha1 *s, const char *data, size_t len);
uint8_t *sha1_result(sha1 *s);
void sha1_init_hmac(sha1 *s, const uint8_t *key, int key_length);
uint8_t *sha1_result_hmac(sha1 *s);

#endif // _SHA1_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
