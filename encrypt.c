/* encrypt.c
 *
 * An encryption algorithm in c
 * by Olivier Van Rompuy
 *
 * Per iteration/round the following is done to the data :
 * - 1st round only : Starting InvertXOR with 8192bit key
 * - Byte substitution (different translation tables per round)
 * - Leftway bitwise rotation *A (per 64bit words)
 * - InvertXOR with 8192bit key
 * - Rightway bitwise rotation *B (per 64bit words)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "encrypt.h"

void sha_key(unsigned char * src,unsigned char * tgt) {
 unsigned char n=0;
 for (;n<KEY_NRSHA;n++) {
   SHA512(src,64,tgt);
   src+=64;
   tgt+=64;
 }
}

//We explode the keystring into a large key
//Then we obscure it with sha512
int buildkey(crypttale *ct,unsigned char * keystring) {
 int se=strnlen(keystring,1024),n=0;
 int sp1=0;
 int cval;
 unsigned char explode[KEY_SIZE];
 unsigned char * kp=explode;
 unsigned char last,cur1;

 if (keystring==NULL) return -1;

 last=keystring[se-1];
 cval=(last-keystring[0])&255;

 for(;n<KEY_SIZE;n++) {
  cur1=keystring[sp1];
  cval=((n>>8)+(n&255)^last^((n&1)?(cval+cur1+1)&255:(cval-cur1-127)))&255;
  *kp=cval;
  last=cur1;
  sp1=(sp1+1)%se;
  kp++;
 }
 sha_key(explode,ct->key);
 return 0;
}

unsigned char tt_findchar(unsigned char input, int *table) {
 unsigned char found=1;
 unsigned char curr;
 int n;
 curr=input;
 while (found) {
  found=0;
  for(n=0;n<256;n++) {
   if (table[n]==curr) found=1;
  }
  if (found) {curr=(curr+1)&255;}
 }
 return curr;
}

//Build the translation tables for byte substitution
void buildtrans(crypttale *ct) {
 int n,m,kp=0;
 int ctable[256];
 unsigned char cval,curr,fval;
 cval=(ct->key[KEY_DIFF]+ct->key[0]-127);
 for(n=0;n<256;n++) {
  for(m=0;m<256;m++) {ctable[m]=-1;}
  for(m=0;m<256;m++) {
   curr=ct->key[kp];
   cval=((n>>8)+(n&255)^((n&1)?(cval+curr+1)&255:(cval-curr-127)))&255;
   fval=tt_findchar(cval,ctable);
   ct->ttable[n][m]=fval;
   ct->dtable[n][fval]=m;
   ctable[m]=ct->ttable[n][m];
   kp=(kp+1)&KEY_DIFF;
  }
 }
}

//XOR
int xor(crypttale *ct,unsigned char * string, int se) {
 int sp=0,kp=0;
 unsigned char * spp=string;
 uint64_t * sp64=(uint64_t *)spp;

 for(;sp<se-8;sp+=8) {
  *sp64=*sp64^*(uint64_t *)(ct->key+kp);
  sp64++;
  kp=(kp+8)&KEY_DIFF;
 }
 spp=(unsigned char *)sp64;

 for(;sp<se;sp++) {
  *spp=*spp^*(ct->key+kp);
  kp=(kp+1)&KEY_DIFF;
  spp++;
 }

 return 0;
}

//Inverted XOR
int invertxor(crypttale *ct,unsigned char * string, int se) {
 int sp=0,kp=0;
 unsigned char * spp=string;
 uint64_t * sp64=(uint64_t *)spp;

 for(;sp<se-8;sp+=8) {
  *sp64=*sp64^*(uint64_t *)(ct->key+kp)^0xffffffffffffffff;
  sp64++;
  kp=(kp+8)&KEY_DIFF;
 }
 spp=(unsigned char *)sp64;

 for(;sp<se;sp++) {
  *spp=*spp^*(ct->key+kp)^0xff;
  kp=(kp+1)&KEY_DIFF;
  spp++;
 }

 return 0;
}

//Byte substitution forward
void translate_fw(crypttale *ct,unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * tt=ct->ttable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=tt[*sp];
  sp++;
 }
}

//Byte substitution backward
void translate_bw(crypttale *ct,unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * dt=ct->dtable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=dt[*sp];
  sp++;
 }
}

//Bit rotation forward
void obscure_fw(crypttale *ct,unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ct->ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<9) return;
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)<<(tt[sc>>4]&63))|((*bp)>>(64-(tt[sc>>4]&63)));
 }
 bp=(uint64_t *)(str);
 *bp=((*bp)<<(tt[0]&63))|((*bp)>>(64-(tt[0]&63)));
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)<<(tt[1]&63))|((*bp)>>(64-(tt[1]&63)));
}

//Bit rotation backward
void obscure_bw(crypttale *ct,unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ct->ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<9) return;
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)>>(tt[1]&63))|((*bp)<<(64-(tt[1]&63)));
 bp=(uint64_t *)(str);
 *bp=((*bp)>>(tt[0]&63))|((*bp)<<(64-(tt[0]&63)));
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)>>(tt[sc>>4]&63))|((*bp)<<(64-(tt[sc>>4]&63)));
 }
}

//Set up encryption
int init_encrypt(crypttale *ct,unsigned char * keystr,int nr_rounds) {
 unsigned int n=0;
 memset(ct->key,0,KEY_SIZE);
 for (;n<256;n++) {
   memset(ct->ttable[0],0,256);
   memset(ct->dtable[0],0,256);
 }
 ct->rounds=nr_rounds;
 buildkey(ct,keystr);
 buildtrans(ct);
}

//Encrypt a buffer of n bytes
int encrypt_data(crypttale *ct,unsigned char * buffer,int len) {
 int n=0;
 invertxor(ct,buffer,len);
 for(;n<ct->rounds;n++) {
  translate_fw(ct,buffer,len,ct->key[n]);
  obscure_fw(ct,buffer,len,ct->key[n]);
  invertxor(ct,buffer,len);
  obscure_bw(ct,buffer,len,ct->key[(n+512)&KEY_DIFF]);
 }
}

//Decrypt a buffer of n bytes
int decrypt_data(crypttale *ct,unsigned char * buffer,int len) {
 int n=ct->rounds-1;
 for(;n>=0;n--) {
  obscure_fw(ct,buffer,len,ct->key[(n+512)&KEY_DIFF]);
  invertxor(ct,buffer,len);
  obscure_bw(ct,buffer,len,ct->key[n]);
  translate_bw(ct,buffer,len,ct->key[n]);
 }
 invertxor(ct,buffer,len);
}
