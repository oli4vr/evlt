/* sftp.h
 */
// Get a remote file using ssh and a base64 rsa_key stored in memory
int get_sftp(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *local_path, char *rsa_key);
// Put a file on a remote host using ssh and a base64 rsa_key stored in memory
int put_sftp(char *username, char *hostname, unsigned int tcpport, char *local_path, char *remote_path, char *rsa_key);

// Delete a remote file
int del_sftp(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *rsa_key);

// Struct sftp_thread_data
typedef struct _sftp_thread_data {
 unsigned char action;
 char *user;
 char *host;
 unsigned int tcpport;
 char *rpath;
 char *lpath;
 char *rsa;
 int rc;
} sftp_thread_data;

void* sftp_thread(void *data);

int ssh_cmd(char *username, char *hostname, int port, char *rsa_key, char *command);

int sftp_compare(char *username, char *hostname, unsigned int tcpport, char *local_path, char *remote_path, char *rsa_key);

int sftp_makedir(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *rsa_key);
