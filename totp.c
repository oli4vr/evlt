#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include "totp.h"

//b32_decode helper function
int b32c(unsigned char c) {
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= '2' && c <= '7')
		return (c - '2' + 26);
	errno = EINVAL;
	return (-1);
}

//Base 32 decoding
size_t b32_decode(const char *s, unsigned char *q, size_t qlen) {
	int	 i, val[8];
	unsigned char *t = q;

	while (*s != '\0') {
		memset(val, 0, sizeof(val));
		for (i = 0; i < 8; ++i) {
			if (*s == '\0')
				break;
			if ((val[i] = b32c(*s)) == -1)
				return (0);
			s++;
		}

		if (qlen < 5) {
			errno = ENOSPC;
			return (0);
		}
		qlen -= 5;

		*q++ = (val[0] << 3) | (val[1] >> 2);
		*q++ = ((val[1] & 0x03) << 6) | (val[2] << 1) | (val[3] >> 4);
		*q++ = ((val[3] & 0x0F) << 4) | (val[4] >> 1);
		*q++ = ((val[4] & 0x01) << 7) | (val[5] << 2) | (val[6] >> 3);
		*q++ = ((val[6] & 0x07) << 5) | val[7];
	}

	return (q - t);
}

//Calculate totp authentication key from base32 secret
int totp_calc(const char *base32_secret) {
    uint8_t key[64];
    size_t key_len = b32_decode(base32_secret, key, sizeof(key));
    if (key_len <= 0) return -1;

    uint64_t timestep = (uint64_t)time(NULL) / 30;
    uint8_t msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = timestep & 0xFF;
        timestep >>= 8;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (!HMAC(EVP_sha1(), key, key_len, msg, 8, hash, &hash_len)) return -2;

    int offset = hash[hash_len - 1] & 0x0F;
    int code = (hash[offset] & 0x7F) << 24 |
               (hash[offset + 1] & 0xFF) << 16 |
               (hash[offset + 2] & 0xFF) << 8 |
               (hash[offset + 3] & 0xFF);

    return code % 1000000;
}

