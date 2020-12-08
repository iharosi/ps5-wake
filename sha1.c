// This code is public-domain - it is based on libcrypt 
// Placed in the public domain by Wei Dai and other contributors.

#include <stdint.h>
#include <string.h>

#include "sha1.h"

const uint8_t sha1_init_state[] = {
    0x01, 0x23, 0x45, 0x67, // H0
    0x89, 0xab, 0xcd, 0xef, // H1
    0xfe, 0xdc, 0xba, 0x98, // H2
    0x76, 0x54, 0x32, 0x10, // H3
    0xf0, 0xe1, 0xd2, 0xc3  // H4
};

void sha1_init(sha1 *s)
{
    memcpy(s->state.b, sha1_init_state, SHA1_HASH_LENGTH);
    s->byte_count = 0;
    s->buffer_offset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits)
{
    return ((number << bits) | (number >> (32 - bits)));
}

void sha1_hash_block(sha1 *s)
{
    uint8_t i;
    uint32_t a, b, c, d, e, t;

    a = s->state.w[0];
    b = s->state.w[1];
    c = s->state.w[2];
    d = s->state.w[3];
    e = s->state.w[4];

    for (i = 0; i < 80; i++) {
        if (i >= 16) {
            t = s->buffer.w[(i + 13) & 15] ^
                s->buffer.w[(i + 8) & 15] ^
                s->buffer.w[(i + 2) & 15] ^
                s->buffer.w[i & 15];
            s->buffer.w[i & 15] = sha1_rol32(t, 1);
        }

        if (i < 20) {
            t = (d ^ (b & (c ^ d))) + SHA1_K0;
        } else if (i < 40) {
          t = (b ^ c ^ d) + SHA1_K20;
        } else if (i < 60) {
          t = ((b & c) | (d & (b | c))) + SHA1_K40;
        } else {
          t = (b ^ c ^ d) + SHA1_K60;
        }

        t += sha1_rol32(a, 5) + e + s->buffer.w[i & 15];
        e = d;
        d = c;
        c = sha1_rol32(b, 30);
        b = a;
        a = t;
    }

    s->state.w[0] += a;
    s->state.w[1] += b;
    s->state.w[2] += c;
    s->state.w[3] += d;
    s->state.w[4] += e;
}

void sha1_add_uncounted(sha1 *s, uint8_t data)
{
    s->buffer.b[s->buffer_offset ^ 3] = data;
    s->buffer_offset++;
    if (s->buffer_offset == SHA1_BLOCK_LENGTH) {
        sha1_hash_block(s);
        s->buffer_offset = 0;
    }
}

void sha1_writebyte(sha1 *s, uint8_t data)
{
    ++s->byte_count;
    sha1_add_uncounted(s, data);
}

void sha1_write(sha1 *s, const char *data, size_t len)
{
    for ( ; len--; ) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1 *s)
{
    // Implement SHA-1 padding (fips180-2 Â§5.1.1)

    // Pad with 0x80 followed by 0x00 until the end of the block
    sha1_add_uncounted(s, 0x80);
    while (s->buffer_offset != 56) sha1_add_uncounted(s, 0x00);

    // Append length in the last 8 bytes
    sha1_add_uncounted(s, 0); // We're only using 32 bit lengths
    sha1_add_uncounted(s, 0); // But SHA-1 supports 64 bit lengths
    sha1_add_uncounted(s, 0); // So zero pad the top bits
    sha1_add_uncounted(s, s->byte_count >> 29); // Shifting to multiply by 8
    sha1_add_uncounted(s, s->byte_count >> 21); // as SHA-1 supports bitstreams as well as
    sha1_add_uncounted(s, s->byte_count >> 13); // byte.
    sha1_add_uncounted(s, s->byte_count >> 5);
    sha1_add_uncounted(s, s->byte_count << 3);
}

uint8_t *sha1_result(sha1 *s)
{
    int i;
    // Pad to complete the last block
    sha1_pad(s);
  
    // Swap byte order back
    for (i = 0; i < 5; i++) {
        uint32_t a, b;
        a = s->state.w[i];
        b = a << 24;
        b |= (a << 8) & 0x00ff0000;
        b |= (a >> 8) & 0x0000ff00;
        b |= a >> 24;
        s->state.w[i] = b;
    }
  
    // Return pointer to hash (20 characters)
    return s->state.b;
}

void sha1_init_hmac(sha1 *s, const uint8_t *key, int key_length)
{
    uint8_t i;
    memset(s->key_buffer, 0, SHA1_BLOCK_LENGTH);

    if (key_length > SHA1_BLOCK_LENGTH) {
        // Hash long keys
        sha1_init(s);
        for ( ; key_length--; ) sha1_writebyte(s, *key++);
        memcpy(s->key_buffer, sha1_result(s), SHA1_HASH_LENGTH);
    } else {
        // Block length keys are used as is
        memcpy(s->key_buffer, key, key_length);
    }

    // Start inner hash
    sha1_init(s);
    for (i = 0; i < SHA1_BLOCK_LENGTH; i++) {
        sha1_writebyte(s, s->key_buffer[i] ^ SHA1_HMAC_IPAD);
    }
}

uint8_t *sha1_result_hmac(sha1 *s)
{
    uint8_t i;

    // Complete inner hash
    memcpy(s->inner_hash, sha1_result(s), SHA1_HASH_LENGTH);

    // Calculate outer hash
    sha1_init(s);
    for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
        sha1_writebyte(s, s->key_buffer[i] ^ SHA1_HMAC_OPAD);
    for (i = 0; i < SHA1_HASH_LENGTH; i++)
        sha1_writebyte(s, s->inner_hash[i]);
    return sha1_result(s);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
