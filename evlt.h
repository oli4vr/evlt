#include <bits/pthreadtypes.h>
#define BLOCK_SIZE 65536
#define META_SIZE 68 //16bit length + 16bit flags + sha512
#define MAX_DATA_SIZE (BLOCK_SIZE - META_SIZE) 
#define MAX_SEGMENTS 32
#define MAX_THREADS 8
#define BUFFER_SIZE (BLOCK_SIZE * MAX_SEGMENTS)
#define RW_SIZE (MAX_DATA_SIZE * MAX_SEGMENTS)
#define THREADS_MINSEG_W 3
#define THREADS_MINSEG_R 2
#define FLAG_STOP 0x8000

#define LIBSSH_STATIC

/* Structure for holding a block of data with its SHA-512 hash and metadata */
typedef struct _evlt_block {
 unsigned char data[MAX_DATA_SIZE];
 unsigned char sha512[64];
 uint16_t length;
 uint16_t flags;
} evlt_block;

typedef struct _evlt_iter evlt_iter;
typedef struct _evlt_act evlt_act;

/* Structure for managing vault files and their segments */
typedef struct _evlt_vault {
 unsigned char name[32];
 unsigned char path[1024];
 unsigned char segments;
 unsigned char segfile[MAX_SEGMENTS][1024];
 unsigned char wrtfile[MAX_SEGMENTS][1024];
 unsigned char rwrfile[MAX_SEGMENTS][1024];
 FILE* rfp[MAX_SEGMENTS];
 FILE* wfp[MAX_SEGMENTS];
 unsigned int blocksize;
 unsigned int datasize;
 unsigned int buffersize;
 unsigned int rwsize;
} evlt_vault;

/* Vault data cryptographic access vector */
typedef struct _evlt_vector {
 crypttale ct1;
 crypttale ct2;
 crypttale ct3;
 crypttale passkey;
 unsigned char stop;
 evlt_act *act;
} evlt_vector;

/* Structure for managing threads in the encryption/decryption process */
typedef struct _evlt_thread {
 evlt_vault *vault;
 evlt_vector *vector;
 evlt_iter *iter;
 evlt_block *block;
 FILE * rfp;
 FILE * wfp;
 unsigned char *outseg;
 pthread_t thr;
 unsigned char nrread;
 size_t datalength;
} evlt_thread;

/* Structure for single iteration of a get or put stream. */
typedef struct _evlt_iter {
 unsigned char data[BUFFER_SIZE];
 unsigned char* block_segment[MAX_SEGMENTS];
 unsigned char segments_read;
 evlt_block eblock[MAX_SEGMENTS];
 evlt_thread thr[MAX_SEGMENTS];
 size_t datalength;
} evlt_iter;

/* Structure for defining an action to be performed on a vault */
typedef struct _evlt_act {
 unsigned char action; // 0=get 1=put 2=del ...
 unsigned char vname[32];
 unsigned char key1[512];
 unsigned char key2[512];
 unsigned char key3[512];
 unsigned char passkey[512];
 unsigned char segments;
 unsigned char verbose;
 unsigned char path[1024];
 unsigned char sftp_host[128];
 unsigned char sftp_user[64];
 unsigned char rsakey[4200];
 uint16_t blocksize; //In KBytes
 uint16_t sftp_port;
 uint64_t read_data_size;
 uint64_t write_data_size;
} evlt_act;

/* Initializes a vault with the given name and number of segments */
int evlt_init(evlt_vault *v,evlt_act *a);

/* Handles input/output operations for a vault */
int evlt_io(evlt_vault *v,FILE *fp,evlt_act *a);

// Data block to FILE* stream
FILE* data2stream(unsigned char* data, size_t size);

size_t evlt_sha_hex(unsigned char *src, unsigned char *tgt, size_t s);
size_t evlt_get_masterkey(unsigned char *path,unsigned char *m);
size_t evlt_put_masterkey(unsigned char *path,unsigned char *m,size_t s);
