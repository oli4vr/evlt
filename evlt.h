#define BLOCK_SIZE 65536
//#define BLOCK_DATA (BLOCK_SIZE - 2)
#define MAX_DATA_SIZE (BLOCK_SIZE - 68)   //BLOCK_SIZE - 16bit length - 16bit dpos - sha512
#define MAX_SEGMENTS 32
#define MAX_THREADS 8
#define BUFFER_SIZE (BLOCK_SIZE * MAX_SEGMENTS)
#define RW_SIZE (MAX_DATA_SIZE * MAX_SEGMENTS)
#define THREADS_MINSEG_W 3
#define THREADS_MINSEG_R 2

/* Structure for holding a block of data with its SHA-512 hash and metadata */
typedef struct _evlt_block {
 unsigned char data[MAX_DATA_SIZE];
 unsigned char sha512[64];
 uint16_t length;
 uint16_t dpos;
} evlt_block;

typedef struct _evlt_iter evlt_iter;

/* Structure for managing vault files and their segments */
typedef struct _evlt_vault {
 unsigned char name[32];
 unsigned char segments;
 unsigned char segfile[MAX_SEGMENTS][1024];
 unsigned char wrtfile[MAX_SEGMENTS][1024];
 FILE* rfp[MAX_SEGMENTS];
 FILE* wfp[MAX_SEGMENTS];
} evlt_vault;

/* Vault data cryptographic access vector */
typedef struct _evlt_vector {
 crypttale ct1;
 crypttale ct2;
 crypttale ct3;
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
 unsigned char action; // 0=get 1=put ...
 unsigned char vname[32];
 unsigned char key1[512];
 unsigned char key2[512];
 unsigned char key3[512];
 unsigned char segments;
 unsigned char verbose;
} evlt_act;

/* Initializes a vault with the given name and number of segments */
int evlt_init(evlt_vault *v,unsigned char *name,unsigned char segments);

/* Handles input/output operations for a vault */
int evlt_io(evlt_vault *v,FILE *fp,unsigned char iomode,unsigned char *key1,unsigned char *key2,unsigned char *key3);
