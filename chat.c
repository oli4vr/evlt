#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include "encrypt.h"
#include "hexenc.h"
#include "pipes.h"
#include "sftp.h"
#include "evlt.h"
#include "inifind.h"
#include "chat.h"

volatile sig_atomic_t exitchat = 0;
unsigned char updchat=0;
unsigned char nickname[32]={0};

void signal_handler(int signal) {
 if (signal == SIGINT || signal == SIGTERM) {
  exitchat=1;
 }
}

// Chat feature
void clear_screen() {
 fprintf(stderr,"%s","\e[1;1H\e[2J");
}

unsigned char get_username(unsigned char *username) {
 uid_t uid = geteuid();
 struct passwd *pw = getpwuid(uid);
 if (pw) {
  strcpy((char *)username, pw->pw_name);
  return 1;
 } else {
  strcpy((char *)username, "unknown");
  return 0;
 }
}

void* chat_update_thread(void *p) {
 evlt_chat *c=(evlt_chat *)p;

 while (exitchat!=1) {
  
  sleep(1);
 }

}

int chat_loop(evlt_chat *c) {
 pthread_t updthr;
 struct sigaction sigh={0};
 unsigned char readstr[1024];
 FILE *fp;

 sigh.sa_handler = signal_handler;
 sigh.sa_flags = 0; // or SA_RESTART to restart system calls
 sigemptyset(&sigh.sa_mask);
 sigaction(SIGINT, &sigh, NULL);
 sigaction(SIGTERM, &sigh, NULL);

 pthread_create(&updthr,NULL,chat_update_thread,(void*)c);

 while (exitchat!=1) {
  fgets(readstr, sizeof(readstr), stdin);
  fp=data2stream(readstr,sizeof(readstr));
  usleep(250000);
 }
 
}