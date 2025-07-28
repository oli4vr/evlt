/* encrypt.h
 *
 * by Olivier Van Rompuy
 *
 */
#include <openssl/sha.h>
#include <openssl/evp.h>

/* Structure for holding encryption key and translation tables */
#define KEY_SIZE 1024
#define KEY_DIFF (KEY_SIZE - 1)
#define KEY_NRSHA (KEY_SIZE >> 6)
#define CTX_NUM (KEY_SIZE >> 5)
#define CTX_DIFF CTX_NUM - 1

// Internal crypto struct
typedef struct _crypttale {
 unsigned char key[KEY_SIZE];
 unsigned char ttable[256][256];
 unsigned char dtable[256][256];
 int rounds;
 unsigned char method;
 EVP_CIPHER_CTX *CTX_EN[CTX_NUM];
 EVP_CIPHER_CTX *CTX_DE[CTX_NUM];
} crypttale;

#define CT_ROTATE       1
#define CT_SUB          2
#define CT_AES256       4

/* Initializes the encryption structure with the provided key and number of rounds */
int init_encrypt(crypttale * ct,unsigned char * keystr,int nr_rounds,unsigned char method);

/* Cleanup encryption structure */
int exit_encrypt(crypttale *ct);

/* Encrypts the provided buffer using the crypttale structure */
int encrypt_data(crypttale * ct,unsigned char * buffer,int len);

/* Decrypts the provided buffer using the crypttale structure */
int decrypt_data(crypttale * ct,unsigned char * buffer,int len);

/* Obscure a source key by sha512-ing every 64byte block and writing it's hash to the target key */
void sha_key(unsigned char * src,unsigned char * tgt);

/* Get a local unique sha512 hash from a combination of hostname, username and mac addresses */
void get_unique_hash(unsigned char *hash);
