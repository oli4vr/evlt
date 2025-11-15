#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// Function to parse the URI and extract parameters
int parse_uri(const char *uri, char **secret, int *period, int *digits) {
 const char *prefix = "otpauth://totp/";
 if (strncmp(uri, prefix, strlen(prefix)) != 0) {
  return -1;
 }

 // Extract the label and parameters
 const char *label_start = uri + strlen(prefix);
 const char *param_start = strchr(label_start, '?');
 if (!param_start) {
  return -1;
 }
 int label_len = param_start - label_start;

 // Parse parameters
 const char *secret_param = strstr(param_start, "secret=");
 if (!secret_param) {
  return -1;
 }
 secret_param += 7; // Length of "secret="
 const char *next_param = strchr(secret_param, '&');
 int secret_len = next_param ? (int)(next_param - secret_param) : (int)strlen(secret_param);

 *secret = strndup(secret_param, secret_len);
 if (!*secret) {
  return -1;
 }

 const char *period_param = strstr(param_start, "period=");
 if (period_param) {
  period_param += 7; // Length of "period="
  next_param = strchr(period_param, '&');
  int period_len = next_param ? (int)(next_param - period_param) : (int)strlen(period_param);
  *period = atoi(strndup(period_param, period_len));
 } else {
  *period = 30; // Default period
 }

 const char *digits_param = strstr(param_start, "digits=");
 if (digits_param) {
  digits_param += 7; // Length of "digits="
  next_param = strchr(digits_param, '&');
  int digits_len = next_param ? (int)(next_param - digits_param) : (int)strlen(digits_param);
  *digits = atoi(strndup(digits_param, digits_len));
 } else {
  *digits = 6; // Default digits
 }

 return 0;
}

// Function to convert base32 string to binary
int base32_decode(const char *input, unsigned char **output, int *output_length) {
 const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
 int len = strlen(input);
 *output_length = (len * 5 / 8) + 1;
 *output = malloc(*output_length);
 if (!*output) {
  return -1;
 }

 int i, j, index, value = 0, bits = 0;
 for (i = 0, j = 0; i < len; ++i) {
  char c = input[i];
  if (c == '=') break;
  index = strchr(base32_chars, toupper(c)) - base32_chars;
  value = (value << 5) | index;
  bits += 5;
  if (bits >= 8) {
   (*output)[j++] = (unsigned char)(value >> (bits - 8));
   bits -= 8;
  }
 }

 *output_length = j;
 return 0;
}

// Function to compute the TOTP code
int compute_totp(const unsigned char *key, int key_len, int period, int digits) {
 time_t now = time(NULL);
 uint64_t counter = (uint64_t)(now / period);
 unsigned char counter_bytes[8];
 for (int i = 0; i < 8; ++i) {
  counter_bytes[i] = (counter >> (56 - i * 8)) & 0xFF;
 }

 unsigned char hmac[20];
 HMAC(EVP_sha1(), key, key_len, counter_bytes, 8, hmac, NULL);

 int offset = hmac[19] & 0x0F;
 uint32_t truncated_hash = (hmac[offset] & 0x7F) << 24 |
                           (hmac[offset + 1] & 0xFF) << 16 |
                           (hmac[offset + 2] & 0xFF) << 8 |
                           (hmac[offset + 3] & 0xFF);

 uint32_t code = truncated_hash % (uint32_t)pow(10, digits);
 return code;
}

// Main function to calculate TOTP from URI
int totp_calc(const char *uri) {
 char *secret = NULL;
 int period, digits,rc;

 if (parse_uri(uri, &secret, &period, &digits) != 0) {
  fprintf(stderr, "Failed to parse URI\n");
  return -1;
 }

 unsigned char *key = NULL;
 int key_len;
 if (base32_decode(secret, &key, &key_len) != 0) {
  fprintf(stderr, "Failed to decode secret\n");
  free(secret);
  return -2;
 }

 rc=compute_totp(key, key_len, period, digits);

 free(secret);
 free(key);
 return rc;
}

