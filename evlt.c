#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <sched.h>
#include "encrypt.h"
#include "hexenc.h"
#include "pipes.h"
#include "evlt.h"
#include "sftp.h"

unsigned char master_obscure[]="zAes,1dVi;o5sp^89dkfnB7_xcv&;klnTz:iY&eoO45fPh(ps!4do/Rfj";

long get_file_size(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        return -1;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);
    return size;
}

//Wipe a buffer by replacing it's content with random bytes
void random_wipe(unsigned char *buff,size_t size)
{
 unsigned char * end=buff+size;
 unsigned char * p = buff;
 int * i;
 srand(time(NULL)); 
 for(;p<end;p+=sizeof(int)) {
   i=(int*)p;
   *i=rand();
 }
}

int explode1024(unsigned char *out,unsigned char * keystring) {
 int se=strnlen(keystring,1024),n=0;
 int sp1=0;
 int cval;
 unsigned char explode[1024];
 unsigned char * kp=explode;
 unsigned char last,cur1;

 if (keystring==NULL) return -1;

 last=keystring[se-1];
 cval=(last-keystring[0])&255;

 for(;n<1024;n++) {
  cur1=keystring[sp1];
  cval=((n>>8)+(n&255)^last^((n&1)?(cval+cur1+1)&255:(cval-cur1-127)))&255;
  *kp=cval;
  last=cur1;
  sp1=(sp1+1)%se;
  kp++;
 }
 sha_key(explode,out);
 return 0;
}

int evlt_init(evlt_vault *v,evlt_act *a) {
 unsigned char subname[MAX_SEGMENTS][256];
 unsigned char exploded[1024];
 unsigned char shaout[256];
 unsigned char hexout[256];
 unsigned char *cp;
 unsigned char rempath[1024];
 FILE *fp;
 size_t sz;
 int n;
 memset(v->name,0,sizeof(v->name));
 strncpy(v->name,a->vname,32);
 v->name[31]=0;
 v->segments=a->segments;

 a->data_size=0;

 //Hidden subdir in user home
 if (v->path[0]==0) {
  snprintf(v->path,1024,"%s/.evlt", getpwuid(getuid())->pw_dir);
  v->path[1023]=0;
 }
 mkdir(v->path,S_IRWXU);

 for(n=0;n<a->segments;n++) {
  //Generate vault segment filenames
  sz=64;
  snprintf(subname[n],1024,"%s__%04lx__%04lx",v->name,a->segments,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->segfile[n],1024,"%s/%s.evlt",v->path,hexout);
  //Generate write segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$Wr1T3temp$$__%s__%04lx__%04lx",v->name,a->segments,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->wrtfile[n],1024,"%s/%s.evlt",v->path,hexout);
  //Generate remote write segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$RemoteWr1T3$$__%s__%04lx__%04lx",v->name,a->segments,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->rwrfile[n],1024,".evlt/%s.evlt",hexout);
  //Touch the vault segment files
  fp=fopen(v->segfile[n],"ab");
  if (fp!=NULL) {fclose(fp);}
  else {fprintf(stderr,"Error: Can't open segment file for write.\n");return -1;}
 }
 return 0;
}

int evlt_sha(evlt_block *b) {
 unsigned char shac[64];
 SHA512(b->data,MAX_DATA_SIZE,shac);
 return memcmp(b->sha512,shac,8)==0;
}

void* evlt_put_thread(void *ethr) {
 evlt_thread *t=(evlt_thread *)ethr;
 evlt_iter *i=t->iter;
 evlt_block *eb=t->block;
 evlt_vector *vc=t->vector;
 evlt_vault *v=t->vault;
 int rc;
 unsigned char buffer[BLOCK_SIZE];

 SHA512(eb->data,MAX_DATA_SIZE,eb->sha512);
 memcpy(buffer,(unsigned char *)eb,BLOCK_SIZE);
 encrypt_data(&vc->ct3,buffer,BLOCK_SIZE);
 encrypt_data(&vc->ct2,buffer,BLOCK_SIZE);
 encrypt_data(&vc->ct1,buffer,BLOCK_SIZE);
 if (vc->passkey.key[0]!=0) 
  encrypt_data(&vc->passkey,buffer,BLOCK_SIZE);

 rc=fwrite(buffer,BLOCK_SIZE,1,t->wfp);
 if (rc!=1) {fprintf(stderr,"Error: Write failure to temp segment file.\n");}

 return NULL;
}

int evlt_iter_put(evlt_vault *v, FILE *fp, evlt_vector *vc) {
 evlt_iter i;
 evlt_block *eb;
 unsigned char n=0;
 unsigned char *cp=i.data;
 unsigned char buffer[BLOCK_SIZE];
 uint16_t flags=0;
 int len,llen,lseg,blen,rc;
 int max=MAX_DATA_SIZE*v->segments;
 pthread_t *tp;
 struct sched_param param; 

 if (fp==NULL) return 0;

 random_wipe(i.data,max);

 len=fread(i.data,1,max,fp);
 if (len==0) return 0;
 if (len<0) return -2;
 if (feof(fp)) {
  flags|=FLAG_STOP;
 }
 llen=len%MAX_DATA_SIZE;
 i.segments_read=(len/MAX_DATA_SIZE)+(llen!=0);


 for(n=0;n<v->segments;n++) {
  eb=&(i.eblock[n]);
  blen=MAX_DATA_SIZE;
  if (len<max) {
   if ((n+1)>i.segments_read) {blen=0;}
   else if ((n+1)==i.segments_read) {blen=llen;}
  }
  i.block_segment[n]=cp;

  eb->length=blen;
  eb->flags=flags;
  if (blen>0) {
   memcpy(eb->data,cp,eb->length);
  }

  i.thr[n].vault=v;
  i.thr[n].vector=vc;
  i.thr[n].iter=&i;
  i.thr[n].block=eb;
  i.thr[n].rfp=NULL;
  i.thr[n].wfp=v->wfp[n];

  tp=&(i.thr[n].thr);
  if (v->segments>=THREADS_MINSEG_W) {
   pthread_create(tp,NULL,evlt_put_thread,(void *) &(i.thr[n]));
  } else {
   evlt_put_thread(&(i.thr[n]));
  }

  cp+=MAX_DATA_SIZE;
 }

 if (v->segments>=THREADS_MINSEG_W) {
  for(n=0;n<v->segments;n++) {
   while (pthread_join(i.thr[n].thr,NULL)!=0) {};
  }
 }
 return len;
}

void* evlt_get_thread(void *ethr) {
 evlt_thread* t=(evlt_thread*)ethr;
 evlt_iter *i=t->iter;
 evlt_block *eb=t->block;
 evlt_vector *vc=t->vector;
 evlt_vault *v=t->vault;
 unsigned char buffer[RW_SIZE];
 int rc;
 
 if (t->rfp==NULL) {t->nrread=0;return NULL;}
 if (feof(t->rfp)) {t->nrread=0;return NULL;}
 rc=fread(buffer,BLOCK_SIZE,1,t->rfp);
 t->nrread=rc;
 t->datalength=0;

 if (t->nrread>0 && vc->stop==0) {
  memcpy((unsigned char*)eb,buffer,BLOCK_SIZE);
  if (vc->passkey.key[0]!=0)
   decrypt_data(&vc->passkey,(unsigned char*)eb,BLOCK_SIZE);
  decrypt_data(&vc->ct1,(unsigned char*)eb,BLOCK_SIZE);
  decrypt_data(&vc->ct2,(unsigned char*)eb,BLOCK_SIZE);
  decrypt_data(&vc->ct3,(unsigned char*)eb,BLOCK_SIZE);
  rc=evlt_sha(eb);
  if (rc) {
   //SHA512 Match
   if (eb->flags & FLAG_STOP) {
    vc->stop=1;
   }
   if (t->outseg!=NULL) {
    memcpy(t->outseg,eb->data,MAX_DATA_SIZE);
    t->datalength=eb->length;
   }
  } else {
   if (t->wfp!=NULL) {
    rc=fwrite(buffer,BLOCK_SIZE,1,t->wfp);
   }
  }
 }

 return NULL;
}

int evlt_iter_get(evlt_vault *v, FILE *fp, evlt_vector *vc) {
 int n,rc,len=0,tlen=0;
 evlt_iter i;
 evlt_block *eb;
 unsigned char iomode=1;
 unsigned char *cp=i.data;
 unsigned char buffer[RW_SIZE];
 unsigned char sha512[64];
 uint16_t flags;
 pthread_t *tp;
 int nrread;

 for(n=0;n<v->segments;n++) {
  i.thr[n].vault=v;
  i.thr[n].vector=vc;
  i.thr[n].iter=&i;
  i.thr[n].block=&(i.eblock[n]);
  i.thr[n].rfp=v->rfp[n];
  i.thr[n].wfp=v->wfp[n];
  tp=&(i.thr[n].thr);
  i.block_segment[n]=i.data+((size_t)n*MAX_DATA_SIZE);
  i.thr[n].outseg=i.block_segment[n];

  if (v->segments>=THREADS_MINSEG_R) {
   pthread_create(tp,NULL,evlt_get_thread,(void *) &(i.thr[n]));
  } else {
   evlt_get_thread(&(i.thr[n]));
  }
 }
 nrread=0;
 i.datalength=0;
 for(n=0;n<v->segments;n++) {
  if (v->segments>=THREADS_MINSEG_R) {
   while (pthread_join(i.thr[n].thr,NULL)!=0) {};
  }
  nrread+=i.thr[n].nrread;
  i.datalength+=i.thr[n].datalength;
 }
 vc->act->data_size+=i.datalength;
 if (nrread<(v->segments)) {return 0;} //END OF DATA

 if (i.datalength<1) {return 1;} //NO MATCH

 if (v->wfp[0]==NULL && fp!=NULL) {
  rc=fwrite(i.data,1,i.datalength,fp);
 }

 if (i.eblock[0].flags & FLAG_STOP) {
  return 0; //END OF DATA
 }

 return 2; //MATCH
}


int evlt_io(evlt_vault *v,FILE *fp,evlt_act *a) {
 unsigned char buffer[BUFFER_SIZE];
 unsigned char tmp[65536]={0};
 unsigned char *cp;
 int len=0,clen,lput=MAX_SEGMENTS;
 int n,m,md,rc;
 int bcnt=0;
 unsigned char newvault=0;
 unsigned char rcr=1,rcw=1;
 evlt_block bld[MAX_SEGMENTS];
 evlt_block * bd;
 evlt_vector vc;
 evlt_act getrsa;
 evlt_vault vltrsa;
 FILE *in, *out, *rsafp;
 pipe_buffer pb;
 sftp_thread_data sftp_td[MAX_SEGMENTS];
 pthread_t sftp_th[MAX_SEGMENTS];

 vc.act=a;

 if (fp==NULL && a->action==0) {return -1;}
 if (a->action==0) {
  in=NULL;out=fp;
 } else {
  in=fp;out=NULL;
 }

 // Remote vault code
 if (a->sftp_port!=0 && a->sftp_host[0]!=0 && a->sftp_user[0]!=0) {
  getrsa.action=0;
  strncpy(getrsa.vname,".secrets",16);
  strncpy(getrsa.key1,".remotehosts",16);
  strncpy(getrsa.key2,".privatekey",16);
  if (a->sftp_port!=22)
   sprintf(getrsa.key3,"%s@%s:%d",a->sftp_user,a->sftp_host,a->sftp_port);
  else
   sprintf(getrsa.key3,"%s@%s",a->sftp_user,a->sftp_host);
  strncpy(getrsa.passkey,a->passkey,512);
  strncpy(getrsa.path,a->path,1024);
  getrsa.passkey[511]=0;
  getrsa.path[1023]=0;
  getrsa.segments=1;
  getrsa.verbose=a->verbose;
  getrsa.sftp_host[0]=0;
  getrsa.sftp_user[0]=0;
  getrsa.sftp_port=0;
  rsafp=stream2data(&pb,tmp,4200);
  usleep(1000);
  if (rsafp==NULL) {
   return -19;
  }
  rc=evlt_init(&vltrsa,&getrsa);
  if (rc!=0) {fclose(rsafp); return -20;}
  rc=evlt_io(&vltrsa,rsafp,&getrsa);
//  fprintf(stderr,"### DEBUG : RC=%d /%s/%s/%s/%s size=%llu\n",rc,getrsa.vname,getrsa.key1,getrsa.key2,getrsa.key3,getrsa.data_size);
  fwrite("\0",1,2,rsafp);
  fflush(rsafp);
  fclose(rsafp);
  usleep(100000);
  strncpy(a->rsakey,tmp,4200);
  a->rsakey[4199]=0;
  rc=strnlen(a->rsakey,4200);
//  fprintf(stderr,"RC=%d\n",rc);
  if (rc<=0) {return -21;}
  ssh_cmd(a->sftp_user,a->sftp_host,a->sftp_port,a->rsakey,"echo mkdir ~/.evlt | /bin/bash\n");
  for(n=0;n<v->segments;n++) {
   sftp_td[n].action=0;
   sftp_td[n].user=a->sftp_user;
   sftp_td[n].host=a->sftp_host;
   sftp_td[n].tcpport=a->sftp_port;
   sftp_td[n].lpath=v->segfile[n];
   sftp_td[n].rpath=v->rwrfile[n];
   sftp_td[n].rsa=a->rsakey;
   rc=pthread_create(&(sftp_th[n]),NULL,sftp_thread,&(sftp_td[n]));
  }
  rc=0;
  for(n=0;n<v->segments;n++) {
   pthread_join(sftp_th[n],NULL);
   if (sftp_td[n].rc<0) {rc=sftp_td[n].rc;}
  }
  if (rc<0 && rc!=-7) {return -22;}
 }

 init_encrypt(&vc.ct1,a->key1,1);
 init_encrypt(&vc.ct2,a->key2,1);
 init_encrypt(&vc.ct3,a->key3,1);
 if (a->passkey[0]!=0) {init_encrypt(&vc.passkey,a->passkey,3);}
 else {vc.passkey.key[0]=0;}
 vc.stop=0;

 //fopen all segment files for binary read
 for(n=0;n<v->segments;n++) {
  v->rfp[n]=fopen(v->segfile[n],"rb");
  v->wfp[n]=NULL;
  if (v->rfp[n]==NULL) {fprintf(stderr,"Error: Can't open the segment file for read.\n%s\n",v->segfile[n]); return -2;}
 }
 
 //in case of a->action 1 (write), open write files for binary write
 if (a->action>0) {
  for(n=0;n<v->segments;n++) {
   v->wfp[n]=fopen(v->wrtfile[n],"wb");
   if (v->wfp[n]==NULL) {fprintf(stderr,"Error: Can't open the temp segment file for write.\n%s\n",v->wrtfile[n]); return -2;}
  }
 }

 //Mix write/read
 if (a->action==0) {rcw=0;}
 while (rcw>0 || rcr>0) {
  if (rcw>0 && a->action>0) {rcw=evlt_iter_put(v,in,&vc);}
  if (rcr>0) {rcr=evlt_iter_get(v,out,&vc);}
 }

 //fclose all segment files
 for(n=0;n<v->segments;n++) {
  if (v->rfp[n]!=NULL) {fclose(v->rfp[n]);}
 }

 //in case of mode 1 (write), close write file and overwrite copy to read files
 if (a->action>0) {
  for(n=0;n<v->segments;n++) {
   if (v->wfp[n]!= NULL) {
    fclose(v->wfp[n]);
    rename(v->wrtfile[n],v->segfile[n]);
   }
  }

  sync();
 }

 // Remote vault code
 if (a->sftp_port!=0 && a->action>0) {
  for(n=0;n<v->segments;n++) {
   sftp_td[n].action=1;
   sftp_td[n].user=a->sftp_user;
   sftp_td[n].host=a->sftp_host;
   sftp_td[n].tcpport=a->sftp_port;
   sftp_td[n].lpath=v->segfile[n];
   sftp_td[n].rpath=v->rwrfile[n];
   sftp_td[n].rsa=a->rsakey;
   rc=pthread_create(&(sftp_th[n]),NULL,sftp_thread,&(sftp_td[n]));
   //rc=put_sftp(a->sftp_user,a->sftp_host,a->sftp_port,v->segfile[n],v->segfile[n],a->rsakey);
  }
  rc=0;
  for(n=0;n<v->segments;n++) {
   pthread_join(sftp_th[n],NULL);
   if (sftp_td[n].rc<0) {rc=sftp_td[n].rc;}
  }
  if (rc<0) {return -22;}
 }

 //Remove empty segment files
 for(n=0;n<v->segments;n++) {
  if (get_file_size(v->segfile[n])==0) {
    remove(v->segfile[n]);
  }
 }
 sync();
 return 0;
}

size_t evlt_sha_hex(unsigned char *src, unsigned char *tgt, size_t s) {
 unsigned char sha512[64];
 size_t sz=64;
 SHA512(src,s,sha512);
 data2hex(sha512,tgt,&sz);
 tgt[128]=0;
 return sz;
}

size_t evlt_get_masterkey(unsigned char *path,unsigned char *m) {
 unsigned char hex512[129];
 unsigned char buffer[BLOCK_SIZE];
 unsigned char hostn[256];
 unsigned char filen[1024];
 FILE *fp;
 uint16_t dpos;
 size_t sz;
 crypttale ct;

 //Setup
 random_wipe(buffer,BLOCK_SIZE);
 init_encrypt(&ct,master_obscure,255);
 gethostname(hostn,256);
 sz=evlt_sha_hex(hostn,hex512,strnlen(hostn,256));
 sprintf(filen,"%s/%s.evlt",path,hex512);

 //Read
 fp=fopen(filen,"rb");
 if (fp==NULL) {return 0;}
 sz=fread(buffer,1,BLOCK_SIZE,fp);
 fclose(fp);
 if (sz<BLOCK_SIZE) {return 0;}

 //Process
 decrypt_data(&ct,buffer,BLOCK_SIZE);
 dpos=*(uint16_t *)buffer;
 memcpy(m,buffer+dpos,129);
 if (m[128]!=0) {return 0;}
 return 129;
}

size_t evlt_put_masterkey(unsigned char *path,unsigned char *m,size_t s) {
 unsigned char hex512[129];
 unsigned char buffer[BLOCK_SIZE];
 unsigned char hostn[256];
 unsigned char filen[1024];
 FILE *fp;
 uint16_t dpos;
 size_t sz;
 crypttale ct;

 //Setup
 random_wipe(buffer,BLOCK_SIZE);
 init_encrypt(&ct,master_obscure,255);
 gethostname(hostn,256);
 sz=evlt_sha_hex(hostn,hex512,strnlen(hostn,256));
 sprintf(filen,"%s/%s.evlt",path,hex512);

 //Process
 sz=evlt_sha_hex(m,hex512,s);
 dpos=2+random()%(BLOCK_SIZE-132);
 *(uint16_t *)buffer=dpos;
 memcpy(buffer+dpos,hex512,129);
 encrypt_data(&ct,buffer,BLOCK_SIZE);

 //Write
 fp=fopen(filen,"wb");
 if (fp==NULL) {return 0;}
 sz=fwrite(buffer,1,BLOCK_SIZE,fp);
 fclose(fp);
 if (sz<BLOCK_SIZE) {return 0;}
 return sz;
}
