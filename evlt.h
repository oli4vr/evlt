/* evlt.h
 */
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
#define MASTER_BLOCK_SIZE 1024
#define MAX_INDEX_SIZE (RW_SIZE * 4)
#define VAULTNAME_SIZE 512
#define VAULTKEY_SIZE 512
#define KPATH_SIZE (VAULTNAME_SIZE + VAULTKEY_SIZE * 3) 
#define RSAKEY_SIZE 4200
#define MAX_INDEX_PER_VAULT 65536

#define LIBSSH_STATIC

void set_master_expire_minutes(int m);

/* Structure for holding a block of data with its SHA-512 hash and metadata */
typedef struct _evlt_block {
 unsigned char data[MAX_DATA_SIZE];
 unsigned char sha512[64];
 uint16_t length;
 uint16_t flags;
} evlt_block;

typedef struct _evlt_iter evlt_iter;
typedef struct _evlt_act evlt_act;
typedef struct _evlt_index_item evlt_index_item;

/* Structure for managing vault files and their segments */
typedef struct _evlt_vault {
 unsigned char name[VAULTNAME_SIZE];
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
 unsigned char status;
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
// unsigned char data[RW_SIZE];
 unsigned char *data;
 unsigned char *block_segment[MAX_SEGMENTS];
 unsigned char segments_read;
 evlt_block eblock[MAX_SEGMENTS];
 evlt_thread thr[MAX_SEGMENTS];
 size_t datalength;
} evlt_iter;

typedef struct _evlt_index_item {
 unsigned char name[256];
 unsigned char type; // 0=file 1=dir ...
 uint64_t flags;
} evlt_index_item;

/* Structure for defining an action to be performed on a vault */
typedef struct _evlt_act {
 unsigned char action; // 0=get 1=put 2=del 3=append 4=ls 5=master 99=delrec ...
 unsigned char kpath[KPATH_SIZE];
 unsigned char vname[VAULTNAME_SIZE];
 unsigned char key1[VAULTKEY_SIZE];
 unsigned char key2[VAULTKEY_SIZE];
 unsigned char key3[VAULTKEY_SIZE];
 unsigned char passkey[VAULTKEY_SIZE];
 unsigned char segments;
 unsigned char verbose;
 unsigned char path[1024];
 unsigned char sftp_host[128];
 unsigned char sftp_user[64];
 unsigned char rsakey[RSAKEY_SIZE];
 uint16_t blocksize; //In KBytes
 uint16_t sftp_port;
 uint64_t read_data_size;
 uint64_t write_data_size;
 unsigned char ieof; //EOF
 unsigned char *restdata;
 size_t restlength;
 unsigned char idxit;
 unsigned char change_hash[64];
 unsigned char *change_data;
 size_t change_size;
 unsigned char encrypt_file;
} evlt_act;

/* Initializes a vault with the given name and number of segments */
int evlt_init(evlt_vault *v,evlt_act *a);
int evlt_exit(evlt_vault *v,evlt_act *a);

/* Handles input/output operations for a vault */
int evlt_io(evlt_vault *v,FILE *fp,evlt_act *a);

// Data block to FILE* stream
FILE* data2stream(unsigned char* data, size_t size);

size_t evlt_sha_hex(unsigned char *src, unsigned char *tgt, size_t s);
size_t evlt_get_masterkey(unsigned char *path,unsigned char *m);
size_t evlt_put_masterkey(unsigned char *path,unsigned char *m,size_t s);

int evlt_index_update(evlt_vault *v,evlt_act *a);

long get_file_size(const char *filename);

void evlt_kpath2keys(evlt_act *a);

int64_t getusecs();
