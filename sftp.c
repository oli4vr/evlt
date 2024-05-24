/* sftp.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include "sftp.h"

#define SFTP_BUFFER 16384

int get_sftp(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *local_path, char *rsa_key) {
 ssh_session session = ssh_new();
 ssh_key privkey;
 int rc;
 if (session == NULL) {
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  fprintf(stderr, "### ERROR   : Failed to import private key: %s\n", ssh_get_error(session));
  ssh_free(session);
  return -2;
 }


 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_USER, username);
 ssh_options_set(session, SSH_OPTIONS_PORT, &tcpport);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  ssh_key_free(privkey);
  return -3;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -4;
 }

 sftp_session sftp = sftp_new(session);
 if (sftp == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -5;
 }

 rc = sftp_init(sftp);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -6;
 }

 sftp_file remote_file = sftp_open(sftp, remote_path, O_RDONLY, 0);
 if (remote_file == NULL) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -7;
 }

 FILE *local_file = fopen(local_path, "wb");
 if (local_file == NULL) {
  sftp_close(remote_file);
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -8;
 }

 char buffer[SFTP_BUFFER];
 rc=SFTP_BUFFER;
 int nbytes=0;
 while ((nbytes = sftp_read(remote_file, buffer, sizeof(buffer))) > 0 && rc>=nbytes) {
  rc=fwrite(buffer, 1, nbytes, local_file);
 }

 fclose(local_file);
 sftp_close(remote_file);
 sftp_free(sftp);
 ssh_disconnect(session);
 ssh_free(session);
 ssh_key_free(privkey);

 if (rc<nbytes) {return -9;}

 return 0;
}

int put_sftp(char *username, char *hostname, unsigned int tcpport, char *local_path, char *remote_path, char *rsa_key) {
 ssh_session session = ssh_new();
 ssh_key privkey;
 int rc,swlen;
 if (session == NULL) {
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  fprintf(stderr, "### ERROR   : Failed to import private key: %s\n", ssh_get_error(session));
  ssh_free(session);
  return -2;
 }

 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_USER, username);
 ssh_options_set(session, SSH_OPTIONS_PORT, &tcpport);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  ssh_key_free(privkey);
  return -3;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -4;
 }

 sftp_session sftp = sftp_new(session);
 if (sftp == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -5;
 }

 rc = sftp_init(sftp);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -6;
 }

 sftp_file remote_file = sftp_open(sftp, remote_path, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
 if (remote_file == NULL) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -7;
 }

 FILE *local_file = fopen(local_path, "rb");
 if (local_file == NULL) {
  sftp_close(remote_file);
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -8;
 }

 struct stat file_info;
 if (stat(local_path, &file_info) < 0) {
  fclose(local_file);
  sftp_close(remote_file);
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -20;
 }

 char buffer[SFTP_BUFFER];
 rc=65536;
 int nbytes=0;
 while ((nbytes = fread(buffer, 1, sizeof(buffer), local_file)) > 0 && rc >= nbytes) {
  swlen=sftp_write(remote_file, buffer, nbytes);
 }

 fclose(local_file);

 sftp_attributes attrs = sftp_fstat(remote_file);
 if (attrs != NULL) {
  attrs->atime = file_info.st_atime;
  attrs->mtime = file_info.st_mtime;
  rc = sftp_setstat(sftp, remote_path, attrs);
  sftp_attributes_free(attrs);
  if (rc!=SSH_OK) {
   fprintf(stderr,"### ERROR   : FAILED TO SET REMOTE FILE ATTRIBUTES\n");
  }
 } else {
  fprintf(stderr,"### ERROR   : FAILED TO GET REMOTE FILE STATS\n");
 }

 sftp_close(remote_file);
 sftp_free(sftp);
 ssh_disconnect(session);
 ssh_free(session);
 ssh_key_free(privkey);

 if (swlen<nbytes) {return -9;}

 return 0;
}

void* sftp_thread(void *data) {
 int rc;
 sftp_thread_data* td=(sftp_thread_data*)data;
// fprintf(stderr,"%s %s %s %s\n",td->user,td->host,td->rpath,td->lpath);
 switch(td->action) {
 case 0:
   td->rc=get_sftp(td->user,td->host,td->tcpport,td->rpath,td->lpath,td->rsa);
  break;;
 case 1:
   td->rc=put_sftp(td->user,td->host,td->tcpport,td->lpath,td->rpath,td->rsa);
  break;;
 }
}

int ssh_cmd(char *username, char *hostname, int port, char *rsa_key, char *command) {
 ssh_session session;
 ssh_channel channel;
 ssh_key privkey;
 int rc;

 session = ssh_new();
 if (session == NULL) {
  return -1;
 }

 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_PORT, &port);
 ssh_options_set(session, SSH_OPTIONS_USER, username);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  ssh_disconnect(session);
  ssh_free(session);
  return -1;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 ssh_key_free(privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  return -1;
 }

 channel = ssh_channel_new(session);
 if (channel == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  return -1;
 }

 rc = ssh_channel_open_session(channel);
 if (rc != SSH_OK) {
  ssh_channel_free(channel);
  ssh_disconnect(session);
  ssh_free(session);
  return -1;
 }

 rc = ssh_channel_request_exec(channel, command);
 if (rc != SSH_OK) {
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  ssh_disconnect(session);
  ssh_free(session);
  return -1;
 }

 ssh_channel_send_eof(channel);
 ssh_channel_close(channel);
 ssh_channel_free(channel);
 ssh_disconnect(session);
 ssh_free(session);

 return 0;
}

int del_sftp(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *rsa_key) {
 ssh_session session = ssh_new();
 ssh_key privkey;
 int rc;
 if (session == NULL) {
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  fprintf(stderr, "### ERROR   : Failed to import private key: %s\n", ssh_get_error(session));
  ssh_free(session);
  return -2;
 }

 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_USER, username);
 ssh_options_set(session, SSH_OPTIONS_PORT, &tcpport);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  ssh_key_free(privkey);
  return -3;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -4;
 }

 sftp_session sftp = sftp_new(session);
 if (sftp == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -5;
 }

 rc = sftp_init(sftp);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -6;
 }

 rc = sftp_unlink(sftp, remote_path);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -7;
 }

 sftp_free(sftp);
 ssh_disconnect(session);
 ssh_free(session);
 ssh_key_free(privkey);

 return 0;
}

int sftp_compare(char *username, char *hostname, unsigned int tcpport, char *local_path, char *remote_path, char *rsa_key) {
 ssh_session session = ssh_new();
 ssh_key privkey;
 int rc;
 if (session == NULL) {
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  fprintf(stderr, "### ERROR   : Failed to import private key: %s\n", ssh_get_error(session));
  ssh_free(session);
  return -2;
 }

 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_USER, username);
 ssh_options_set(session, SSH_OPTIONS_PORT, &tcpport);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  ssh_key_free(privkey);
  return -3;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -4;
 }

 sftp_session sftp = sftp_new(session);
 if (sftp == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -5;
 }

 rc = sftp_init(sftp);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -6;
 }

 sftp_attributes remote_attrs = sftp_stat(sftp, remote_path);
 if (remote_attrs == NULL) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -7;
 }

 struct stat local_attrs;
 if (stat(local_path, &local_attrs) < 0) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -8;
 }

 int result = 0; // Assume files are the same
 if (local_attrs.st_mtime < remote_attrs->mtime || local_attrs.st_size != remote_attrs->size) {
  result = 1; // Remote file is newer or size differs
 }

 sftp_attributes_free(remote_attrs);
 sftp_free(sftp);
 ssh_disconnect(session);
 ssh_free(session);
 ssh_key_free(privkey);

 return result;
}

int sftp_makedir(char *username, char *hostname, unsigned int tcpport, char *remote_path, char *rsa_key) {
 ssh_session session = ssh_new();
 ssh_key privkey;
 int rc;

 if (session == NULL) {
  return -1;
 }

 rc = ssh_pki_import_privkey_base64(rsa_key, NULL, NULL, NULL, &privkey);
 if (rc != SSH_OK) {
  fprintf(stderr, "### ERROR   : Failed to import private key: %s\n", ssh_get_error(session));
  ssh_free(session);
  return -2;
 }

 ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
 ssh_options_set(session, SSH_OPTIONS_USER, username);
 ssh_options_set(session, SSH_OPTIONS_PORT, &tcpport);

 rc = ssh_connect(session);
 if (rc != SSH_OK) {
  ssh_free(session);
  ssh_key_free(privkey);
  return -3;
 }

 rc = ssh_userauth_publickey(session, NULL, privkey);
 if (rc != SSH_AUTH_SUCCESS) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -4;
 }

 sftp_session sftp = sftp_new(session);
 if (sftp == NULL) {
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -5;
 }

 rc = sftp_init(sftp);
 if (rc != SSH_OK) {
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -6;
 }

 rc = sftp_mkdir(sftp, remote_path, S_IRWXU);
 if (rc != SSH_OK) {
  //fprintf(stderr, "### ERROR   : Failed to create directory: %s\n", ssh_get_error(session));
  sftp_free(sftp);
  ssh_disconnect(session);
  ssh_free(session);
  ssh_key_free(privkey);
  return -7;
 }

 sftp_free(sftp);
 ssh_disconnect(session);
 ssh_free(session);
 ssh_key_free(privkey);

 return 0;
}
