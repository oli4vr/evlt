/* evlt.c
 */
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

#define SFTP_RETRY 3

unsigned char master_obscure[1024]={0};
unsigned char zerostr[1]={0};

int master_expire_minutes=60;

void set_master_expire_minutes(int m) {
 master_expire_minutes=m;
}

// Return timestamp in microseconds
int64_t getusecs() {
 int64_t tmp;
 int rc;
 struct timeval tv;
 gettimeofday(&tv,NULL);
 tmp=tv.tv_sec;
 tmp*=1000000;
 tmp+=tv.tv_usec;
 return tmp;
}

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

int delete_if_older(const char *filepath, int minutes) {
    struct stat file_stat;
    time_t current_time;
    double diff_minutes;

    // Get the current time
    time(&current_time);

    // Get file statistics
    if (stat(filepath, &file_stat) != 0) {
        return -1;
    }

    // Calculate the difference in minutes
    diff_minutes = difftime(current_time, file_stat.st_mtime) / 60;

    // Check if the file is older than the specified number of minutes
    if (diff_minutes > minutes) {
        if (remove(filepath) != 0) {
            return -1;
        }
        fprintf(stderr,"## Master key expired\n");
    }

    return 0;
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

int evlt_exit(evlt_vault *v,evlt_act *a) {
  free(a->restdata);
}

int evlt_init(evlt_vault *v,evlt_act *a) {
 unsigned char subname[MAX_SEGMENTS][1024];
 unsigned char exploded[1024];
 unsigned char shaout[256];
 unsigned char hexout[256];
 unsigned char *cp;
 unsigned char rempath[1024];
 FILE *fp;
 size_t sz;
 int n;
 memset(v->name,0,sizeof(v->name));
 strncpy(v->name,a->vname,VAULTNAME_SIZE);
 v->name[31]=0;
 a->ieof=0;

 if (strncmp(a->vname,".secrets",9)==0) {
  a->segments=1;
  a->blocksize=8;
  a->sftp_host[0]=0;
  a->sftp_user[0]=0;
  a->sftp_port=0;
 }

 v->segments=a->segments;

 switch (a->blocksize) {
  case 1:
  case 2:
  case 4:
  case 8:
  case 16:
  case 32:
  case 64:
    v->blocksize=a->blocksize<<10;
   break;;
  default:
    v->blocksize=BLOCK_SIZE;
 }

 v->datasize=v->blocksize-META_SIZE;
 v->buffersize=v->blocksize*v->segments;
 v->rwsize=v->datasize*v->segments;
 if (a->verbose) {
  fprintf(stderr,"### VERBOSE : Blocksize=%lu Datasize=%lu Buffersize=%lu RWsize=%lu\n",v->blocksize,v->datasize,v->buffersize,v->rwsize);
 }

 a->read_data_size=0;
 a->write_data_size=0;

 //Hidden subdir in user home
 if (v->path[0]==0) {
  if (a->path[0]!=0) {
   strncpy(v->path,a->path,1024);
  } else {
   snprintf(v->path,1024,"%s/.evlt", getpwuid(getuid())->pw_dir);
  }
  v->path[1023]=0;
 }
 mkdir(v->path,S_IRWXU);

 for(n=0;n<a->segments;n++) {
  //Generate vault segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$V4ulTf1L3$$__%s__%04lx__%04lx__%04lx",v->name,a->segments,a->blocksize,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->segfile[n],1024,"%s/%s.evlt",v->path,hexout);
  //Generate write segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$Wr1T3temp$$__%s__%04lx__%04lx__%04lx",v->name,a->segments,a->blocksize,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->wrtfile[n],1024,"%s/%s.evlt",v->path,hexout);
  //Generate remote write segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$RemoteWrT$$$__%s__%04lx__%04lx_%04lx",v->name,a->segments,a->blocksize,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->rwrfile[n],1024,".evlt/%s.evlt",hexout);
  //Touch the vault segment files
  fp=fopen(v->segfile[n],"ab");
  if (fp!=NULL) {fclose(fp);}
  else {fprintf(stderr,"### ERROR   : Can't open segment file for write.\n");return -1;}
 }
 a->restdata=malloc(sizeof(unsigned char) * v->rwsize);
 if (a->restdata==NULL) {fprintf(stderr,"### Error   : Failed to allocate buffer memory!\n"); exit(-35);}
 a->restlength=0;
 a->restdata[0]=0;
 return 0;
}

int evlt_sha_check(evlt_vault *v,unsigned char *buffer) {
 unsigned char shac[64];
 unsigned char *shap=buffer+v->blocksize-64;
 SHA512(buffer,v->blocksize-64,shac);
 return memcmp(shap,shac,64)==0;
}

void* evlt_put_thread(void *ethr) {
 evlt_thread *t=(evlt_thread *)ethr;
 evlt_iter *i=t->iter;
 evlt_block *eb=t->block;
 evlt_vector *vc=t->vector;
 evlt_vault *v=t->vault;
 int rc;
 //unsigned char buffer[BLOCK_SIZE];
 unsigned char *buffer=NULL;
 unsigned char *cp;

 while (buffer==NULL) {
  buffer=(unsigned char *)malloc(v->blocksize);
 }
 cp=buffer;


 *(uint16_t *)cp=eb->length;
 cp+=2;
 *(uint16_t *)cp=eb->flags;
 cp+=2;
 memcpy(cp,eb->data,v->datasize);
 cp+=v->datasize;
 SHA512(buffer,v->blocksize-64,cp);

// memcpy(buffer,(unsigned char *)eb,v->blocksize);
 encrypt_data(&vc->ct3,buffer,v->blocksize);
 encrypt_data(&vc->ct2,buffer,v->blocksize);
 encrypt_data(&vc->ct1,buffer,v->blocksize);
 if (vc->passkey.key[0]!=0) 
  encrypt_data(&vc->passkey,buffer,v->blocksize);

 rc=fwrite(buffer,v->blocksize,1,t->wfp);
 if (rc!=1) {fprintf(stderr,"### ERROR   : Write failure to temp segment file.\n");}

 free(buffer);
 return NULL;
}

int evlt_iter_put(evlt_vault *v, FILE *fp, evlt_vector *vc) {
 evlt_iter i;
 evlt_block *eb;
 unsigned char n=0;
 unsigned char *cp;
 uint16_t flags=0;
 int len,llen,lseg,blen,rc;
 pthread_t *tp;
 struct sched_param param; 

 //i.data=vc->act->restdata;
 if (fp==NULL || vc->act->ieof==1) return 0;

 i.data=NULL;
 while (i.data==NULL) {
  i.data=(unsigned char *)malloc(v->rwsize);
 }

 random_wipe(i.data,v->rwsize);


 len=0;
 cp=i.data;
 if (vc->act->restlength>0) {
  fprintf(stderr,"### VERBOSE : DATA REMAINDER FOUND, APPENDING TO IT\n");
  memcpy(i.data,vc->act->restdata,vc->act->restlength);
  cp+=vc->act->restlength;
  len=vc->act->restlength;
  vc->act->restlength=0;
 }

 //if (feof(fp)) {len=0; return 0;}
 rc=0;
 if (feof(fp)==0)
  rc=fread(cp,1,v->rwsize-len,fp);
 if (rc>0) len+=rc;
 cp=i.data;
 if (len<v->rwsize) {vc->act->ieof=1;}
 if (len==0) {free(i.data);return 0;}
 if (rc<0) {free(i.data);return -2;}
 if (feof(fp)) {
  flags|=FLAG_STOP;
 }
 llen=len%v->datasize;
 i.segments_read=(len/v->datasize)+(llen!=0);


 for(n=0;n<v->segments;n++) {
  eb=&(i.eblock[n]);
  blen=v->datasize;
  if (len<v->rwsize) {
   if ((n+1)>i.segments_read) {blen=0;}
   else if ((n+1)==i.segments_read) {blen=llen;}
  }
  i.block_segment[n]=cp;

  eb->length=blen;
  eb->flags=flags;
  memcpy(eb->data,cp,v->datasize);

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

  vc->act->write_data_size+=blen;

  cp+=v->datasize;
 }

 if (v->segments>=THREADS_MINSEG_W) {
  for(n=0;n<v->segments;n++) {
   while (pthread_join(i.thr[n].thr,NULL)!=0) {};
  }
 }
 free(i.data);
 return len;
}

void* evlt_get_thread(void *ethr) {
 evlt_thread* t=(evlt_thread*)ethr;
 evlt_iter *i=t->iter;
 evlt_block *eb=t->block;
 evlt_vector *vc=t->vector;
 evlt_vault *v=t->vault;
// unsigned char buffer[BLOCK_SIZE];
// unsigned char ordata[BLOCK_SIZE];
 unsigned char *buffer,*ordata;
 unsigned char *cp;
 int rc;

 if (t->rfp==NULL) {t->nrread=0;return NULL;}
 if (feof(t->rfp)) {
  t->nrread=0;
  return NULL;
 }

 while (buffer==NULL) {
  buffer=malloc(v->blocksize);
 }
 while (ordata==NULL) {
  ordata=malloc(v->blocksize);
 }

 cp=buffer;
 rc=fread(buffer,v->blocksize,1,t->rfp);
 t->nrread=rc;
 t->datalength=0;
 memcpy(ordata,buffer,v->blocksize);

 if (t->nrread>0 && vc->status==0) {
  if (vc->passkey.key[0]!=0)
   decrypt_data(&vc->passkey,buffer,v->blocksize);
  decrypt_data(&vc->ct1,buffer,v->blocksize);
  decrypt_data(&vc->ct2,buffer,v->blocksize);
  decrypt_data(&vc->ct3,buffer,v->blocksize);
  rc=evlt_sha_check(v,buffer);
  if (rc) {
   //SHA512 Match
   eb->length=*(uint16_t *)cp;
   cp+=2;
   eb->flags=*(uint16_t *)cp;
   cp+=2;
   memcpy(eb->data,cp,v->datasize);
   cp+=v->datasize;
   memcpy(eb->sha512,cp,64);
   if (eb->flags & FLAG_STOP) {
    vc->status=1;
   }
   if (t->outseg!=NULL) {
    memcpy(t->outseg,eb->data,v->datasize);
    t->datalength=eb->length;
   }
   if (vc->act->action==3 && t->wfp!=NULL) {
    if (eb->flags & FLAG_STOP) {
     cp=buffer+2;
     *(uint16_t *)cp&=~FLAG_STOP; // Remove stop flag
     cp=buffer+v->blocksize-64;
     SHA512(buffer,v->blocksize-64,cp);
     encrypt_data(&vc->ct3,buffer,v->blocksize);
     encrypt_data(&vc->ct2,buffer,v->blocksize);
     encrypt_data(&vc->ct1,buffer,v->blocksize);
     if (vc->passkey.key[0]!=0) 
      encrypt_data(&vc->passkey,buffer,v->blocksize);
     //rc=fwrite(buffer,v->blocksize,1,t->wfp);
    } else {
     rc=fwrite(ordata,v->blocksize,1,t->wfp);
     vc->act->write_data_size+=v->datasize;
    }
   }
  } else {
   if (t->wfp!=NULL) {
    rc=fwrite(ordata,v->blocksize,1,t->wfp);
   }
  }
 }

 free(ordata);
 free(buffer);
 return NULL;
}

int evlt_iter_get(evlt_vault *v, FILE *fp, evlt_vector *vc) {
 int n,rc,len=0,tlen=0;
 evlt_iter i;
 evlt_block *eb;
 unsigned char iomode=1;
 unsigned char *cp=i.data;
 unsigned char sha512[64];
 uint16_t flags;
 pthread_t *tp;
 int nrread;
 
 i.data=NULL;
 while (i.data==NULL) {
  i.data=(unsigned char *)malloc(v->rwsize);
 }

 for(n=0;n<v->segments;n++) {
  i.thr[n].vault=v;
  i.thr[n].vector=vc;
  i.thr[n].iter=&i;
  i.thr[n].block=&(i.eblock[n]);
  i.thr[n].rfp=v->rfp[n];
  i.thr[n].wfp=v->wfp[n];
  tp=&(i.thr[n].thr);
  i.block_segment[n]=i.data+((size_t)n*v->datasize);
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
   while (pthread_join(i.thr[n].thr,NULL)!=0) {}; //join all threads
  }
  nrread+=i.thr[n].nrread;
  i.datalength+=i.thr[n].datalength;
 }

 if (vc->act->action==3) {
  if (vc->status==1 || nrread<(v->segments)) {
   memcpy(vc->act->restdata,i.data,i.datalength);
   vc->act->restlength=i.datalength;
   vc->act->action=1;
  }
 }

 vc->act->read_data_size+=i.datalength;
 if (nrread<(v->segments)) {free(i.data);return 0;} //END OF DATA

 if (i.datalength<1) {free(i.data);return 1;} //NO MATCH

 if (v->wfp[0]==NULL && fp!=NULL) {
  rc=fwrite(i.data,1,i.datalength,fp);
 }

 free(i.data);
 if (i.eblock[0].flags & FLAG_STOP) {
  return 0; //END OF DATA
 }

 return 2; //MATCH
}

unsigned char * path_string_up(unsigned char *str) {
 if (str == NULL || *str == '\0') return zerostr;

 unsigned char *last_slash = strrchr(str, '/');
 if (last_slash != NULL) {
  *last_slash = '\0';
  return last_slash+1;
 }
 return zerostr;
}

void remove_line_with_string(unsigned char *str, unsigned char *target) {
 unsigned char *start = str;
 unsigned char *end;
 unsigned char *write_ptr = str;
 size_t target_len = strlen(target);

 while ((end = (unsigned char *)strchr((char *)start, '\n')) != NULL) {
  size_t line_len = end - start + 1;
  if (strncmp((char *)start, (char *)target, target_len) != 0 || (start[target_len] != '\n' && start[target_len] != '\0')) {
   memmove(write_ptr, start, line_len);
   write_ptr += line_len;
  }
  start = end + 1;
 }

 // Handle the last line if it doesn't end with a newline
 if (*start != '\0' && (strncmp((char *)start, (char *)target, target_len) != 0 || (start[target_len] != '\0'))) {
  strcpy((char *)write_ptr, (char *)start);
 } else {
  *write_ptr = '\0';
 }
}

int add_line_to_string(unsigned char *str, unsigned char *add) {
 size_t l1 = strnlen((char *)str, MAX_INDEX_SIZE);
 size_t l2 = strnlen((char *)add, 256);
 unsigned char *cp = str + l1;
 if (l1 + l2 > MAX_INDEX_SIZE) return -1;
 strncpy((char *)cp, (char *)add, 256);
 cp += l2;
 if (*(cp - 1) != '\n') {
  *cp = '\n';
  cp++;
 }
 *cp = '\0';
 return 0;
}

int evlt_index_update(evlt_vault *v,evlt_act *a) {
 evlt_vault vi;
 if (a==NULL || v==NULL) {return -99;}
 if (a->idxit==0) {return 0;}

 int n;
 unsigned char *ibuff;
 unsigned char *fname=zerostr;
 unsigned char tfname[256]={0};
 unsigned char vname[VAULTNAME_SIZE];
 uint64_t tstamp=getusecs();
// evlt_index_item it;
 FILE * fp;
 int rc;

// memcpy(&vi,v,sizeof(evlt_vault));


 ibuff=malloc(MAX_INDEX_SIZE);
 memset(ibuff,0,MAX_INDEX_SIZE);
 if (ibuff==NULL) {
  fprintf(stderr,"### ERROR   : Failed to allocate memory for index buffer\n");
  return -1;
 }
 evlt_act *b;
 b=malloc(sizeof(evlt_act));
 if (b==NULL) {
  free(ibuff);
  fprintf(stderr,"### ERROR   : Failed to allocate memory for evlt_act\n");
  return -1;
 }

 memcpy(b,a,sizeof(evlt_act));

 if (b->kpath[0]!='/') {
  b->kpath[0]='/';
  strncpy(b->kpath+1,a->kpath,KPATH_SIZE);
  b->kpath[KPATH_SIZE-1]=0;
 }


 if ((b->kpath[0]=='/' && b->kpath[1]=='\0') || b->kpath[0]=='\0') {
  free(ibuff);
  free(b);
  return -2;
 }

 fname=path_string_up(b->kpath);
 if (fname[0]=='\0') {
  free(ibuff);
  free(b);
  return -3;
 }
 evlt_kpath2keys(b);

 strncpy(vname,b->vname,VAULTNAME_SIZE);
 vname[VAULTNAME_SIZE-1]=0;
 sprintf(b->vname,"$$INDEX$$__%s",vname);

 b->action=0;
 b->idxit=0;
 b->ieof=0;
 b->write_data_size=0;
 b->read_data_size=0;

 snprintf(tfname,256,"/tmp/%llx",(unsigned long long)tstamp);

 fp=fopen(tfname,"wb");
 if (fp==NULL) {
  free(ibuff);
  free(b);
  return -4;
 }
 if (a->verbose) {
  fprintf(stderr,"### VERBOSE : IDX UPDATE Action=%d\n### VERBOSE : Vault=%s\n### VERBOSE : Segments=%d\n### VERBOSE : Key1=%s\n### VERBOSE : Key2=%s\n### VERBOSE : Key3=%s\n",b->action,b->vname,b->segments,b->key1,b->key2,b->key3);
  fprintf(stderr,"### VERBOSE : KPATH=%s\n",b->kpath);
 }
 evlt_init(&vi,b);
 rc=evlt_io(&vi,fp,b);
 evlt_exit(&vi,b);
 fclose(fp);
 fp=fopen(tfname,"rb");
 if (fp==NULL) {
  free(ibuff);
  free(a);
  return -5;
 }
 fread(ibuff,1,MAX_INDEX_SIZE,fp);
 fclose(fp);

 remove_line_with_string(ibuff,fname);
 if (a->action!=2) add_line_to_string(ibuff,fname);

 fp=fopen(tfname,"wb");
 if (fp==NULL) {
  free(ibuff);
  free(b);
  return -6;
 }
 fwrite(ibuff,1,strnlen(ibuff,MAX_INDEX_SIZE),fp);
 fclose(fp);
 fp=fopen(tfname,"rb");
 if (fp==NULL) {
  free(ibuff);
  free(b);
  return -7;
 }
 b->action=1;
 b->idxit=0;
 b->ieof=0;
 b->write_data_size=0;
 b->read_data_size=0;
 if (a->verbose) {
  fprintf(stderr,"### VERBOSE : IDX UPDATE Action=%d\n### VERBOSE : Vault=%s\n### VERBOSE : Segments=%d\n### VERBOSE : Key1=%s\n### VERBOSE : Key2=%s\n### VERBOSE : Key3=%s\n",b->action,b->vname,b->segments,b->key1,b->key2,b->key3);
  fprintf(stderr,"### VERBOSE : KPATH=%s\n",b->kpath);
 }
 evlt_init(&vi,b);
 rc=evlt_io(&vi,fp,b);
 evlt_exit(&vi,b);
 fclose(fp);

 remove(tfname);

 free(ibuff);
 free(b);
 return 0;
}

int evlt_io(evlt_vault *v,FILE *fp,evlt_act *a) {
 unsigned char buffer[BUFFER_SIZE];
 unsigned char tmp[65536]={0};
 unsigned char *cp;
 int rn,len=0,clen,lput=MAX_SEGMENTS;
 int n,m,md,rc;
 int bcnt=0;
 unsigned char newvault=0;
 unsigned char rcr=1,rcw=1;
 evlt_block bld[MAX_SEGMENTS];
 evlt_block * bd;
 evlt_vector vc;
 evlt_act subact;
 evlt_vault subvlt;
 FILE *in, *out, *rsafp;
 pipe_buffer pb;
 sftp_thread_data sftp_td[MAX_SEGMENTS];
 pthread_t sftp_th[MAX_SEGMENTS];

 vc.act=a;

 if (a->action==0) {
  in=NULL;out=fp;
 } else {
  in=fp;out=NULL;
 }

 // Remote vault code
 if (a->sftp_port!=0 && a->sftp_host[0]!=0 && a->sftp_user[0]!=0) {
  subact.action=0;
  strncpy(subact.vname,".secrets",16);
  strncpy(subact.key1,".remotehosts",16);
  strncpy(subact.key2,".privatekey",16);
  if (a->sftp_port!=22)
   sprintf(subact.key3,"%s@%s:%d",a->sftp_user,a->sftp_host,a->sftp_port);
  else
   sprintf(subact.key3,"%s@%s",a->sftp_user,a->sftp_host);
  strncpy(subact.passkey,a->passkey,VAULTKEY_SIZE);
  strncpy(subact.path,a->path,1024);
  subact.passkey[511]=0;
  subact.path[1023]=0;
  subact.verbose=a->verbose;
  subact.segments=1;
  subact.blocksize=8;
  subact.sftp_host[0]=0;
  subact.sftp_user[0]=0;
  subact.sftp_port=0;
  subact.ieof=0;
  if (a->verbose)
   fprintf(stderr,"### VERBOSE : Checking for RSA key in /%s/%s/%s/%s\n",subact.vname,subact.key1,subact.key2,subact.key3);
  rsafp=stream2data(&pb,tmp,RSAKEY_SIZE);
  usleep(1000);
  if (rsafp==NULL) {
   return -19;
  }
  rc=evlt_init(&subvlt,&subact);
  if (rc!=0) {fclose(rsafp); return -20;}
  rc=evlt_io(&subvlt,rsafp,&subact);
  if (a->verbose)
   fprintf(stderr,"### VERBOSE : Get rsa key data RC=%d size=%llu\n",rc,subact.read_data_size);
  fwrite("\0",1,2,rsafp);
  fflush(rsafp);
  fclose(rsafp);
  usleep(100000);
  strncpy(a->rsakey,tmp,RSAKEY_SIZE);
  evlt_exit(&subvlt,&subact);
  a->rsakey[4199]=0;
  rc=strnlen(a->rsakey,RSAKEY_SIZE);
  if (a->verbose)
   fprintf(stderr,"### VERBOSE : Actual key size in memory buffer = %d\n",rc);
  if (rc<=0) {
   fprintf(stderr,"### ERROR   : Failed to acquire RSA key for this remote connection\n");
   fprintf(stderr,"  -> Suggested action : evlt put /%s/%s/%s/%s -f private_keyfile\n",subact.vname,subact.key1,subact.key2,subact.key3);
   fprintf(stderr,"  ->                    Make sure the public key is added to the remote authorized_keys.\n");
   return -21;
  }
  rc=-99;
  for(rn=0;rn<SFTP_RETRY && rc<0 && rc!=-7;rn++) {
   rc=sftp_makedir(a->sftp_user,a->sftp_host,a->sftp_port,".evlt",a->rsakey);
  }
  if (rc!=0 && rc!=-7) {
   fprintf(stderr,"### WARNING : Could not create remote dir\n");
  }
  //ssh_cmd(a->sftp_user,a->sftp_host,a->sftp_port,a->rsakey,"echo mkdir ~/.evlt | /bin/bash\n");

  if (a->verbose) fprintf(stderr,"### VERBOSE : Check whether remote files have changed\n");
  rc=-99;
  for(rn=0;rn<SFTP_RETRY && rc<0 && rc!=-7;rn++) {
   if (rn>0 && a->verbose) fprintf(stderr,"### WARNING : Local/remote compare retry\n");
   rc=sftp_compare(a->sftp_user,a->sftp_host,a->sftp_port,v->segfile[0],v->rwrfile[0],a->rsakey);
  }
  if (rc==0) {
   if (a->verbose) fprintf(stderr,"### VERBOSE : Remote file unchanged\n");
  }
  if (rc==-7) {
   if (a->verbose) fprintf(stderr,"### VERBOSE : Remote files do not yet exist\n");
   rc=0;
  }
  if (rc==-8) {
   if (a->verbose) fprintf(stderr,"### VERBOSE : Local files do not yet exist\n");
   rc=1;
  }
  if (rc<0) {
   fprintf(stderr,"### ERROR   : Failed to compare remote file stats\n");
   return -23;
  }
  if (rc<0) {
   fprintf(stderr,"### ERROR   : Failed to compare remote file stats\n");
   return -23;
  }
  if (rc==1) {
   if (a->verbose) fprintf(stderr,"### VERBOSE : sftp get remote vault\n");
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
   if (a->verbose) fprintf(stderr,"### VERBOSE : sftp get remote vault\n");
   rc=-22;
   for(rn=0;rn<SFTP_RETRY && rc<0 && rc!=-7;rn++) {
    if (rc>0 && a->verbose) {fprintf(stderr,"### WARNING : Retry failed sftp get\n");}
    rc=0;
    for(n=0;n<v->segments;n++) {
     pthread_join(sftp_th[n],NULL);
     if (sftp_td[n].rc<0) {rc=sftp_td[n].rc;}
    }
   }
   if (rc<0 && rc!=-7) {
    fprintf(stderr,"### ERROR   : get remote vault failed\n");
    return -22;
   }
   if (rc==-7 && a->verbose) {fprintf(stderr,"### VERBOSE : Vault files not found on remote host, start from [new] local one.\n");}
  }
 }
 if (out==NULL && a->action==0) {sync();return -1;}

 init_encrypt(&vc.ct1,a->key1,1);
 init_encrypt(&vc.ct2,a->key2,1);
 init_encrypt(&vc.ct3,a->key3,1);
 if (a->passkey[0]!=0) {init_encrypt(&vc.passkey,a->passkey,3);}
 else {vc.passkey.key[0]=0;}
 vc.status=0;

 //fopen all segment files for binary read
 for(n=0;n<v->segments;n++) {
  v->rfp[n]=fopen(v->segfile[n],"rb");
  v->wfp[n]=NULL;
  if (v->rfp[n]==NULL) {fprintf(stderr,"### ERROR   : Can't open the segment file for read.\n%s\n",v->segfile[n]); return -2;}
 }
 
 //in case of a->action 1 (write), open write files for binary write
 if (a->action>0) {
  for(n=0;n<v->segments;n++) {
   v->wfp[n]=fopen(v->wrtfile[n],"wb");
   if (v->wfp[n]==NULL) {fprintf(stderr,"### ERROR   : Can't open the temp segment file for write.\n%s\n",v->wrtfile[n]); return -2;}
  }
 }

 //Mix write/read
 if (a->verbose) fprintf(stderr,"### VERBOSE : R/W IO ON LOCAL VAULT %s\n",a->vname);
 if (a->action==0) {rcw=0;}
 while (rcw>0 || rcr>0) {
  if (rcw>0 && a->action>0 && a->action!=3) {
   rcw=evlt_iter_put(v,in,&vc);
  }
  if (rcr>0) {rcr=evlt_iter_get(v,out,&vc);}
 }
 if (a->restlength>0 && a->action > 0) {
  FILE * tfp = data2stream(a->restdata,a->restlength);
  evlt_iter_put(v,tfp,&vc);
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
  //Index update
  evlt_index_update(v,a);
 }

 //Remove empty segment files
 unsigned char del=0;
 for(n=0;n<v->segments;n++) {
  if (get_file_size(v->segfile[n])==0) {
    remove(v->segfile[n]);
    if (a->sftp_port!=0) {
     rc=-99;
     for(rn=0;rn<SFTP_RETRY && rc<0;rn++) {
      rc=del_sftp(a->sftp_user,a->sftp_host,a->sftp_port,v->rwrfile[n],a->rsakey);
     }
    }
    del=1;
  }
 }
 if (del==1) return 0;

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
  if (a->verbose) fprintf(stderr,"### VERBOSE : sftp put remote vault\n");
  rc=-22;
  for(rn=0;rn<SFTP_RETRY && rc<0;rn++) {
   if (rc>0 && a->verbose) {fprintf(stderr,"### WARNING : Retry failed sftp put\n");}
   rc=0;
   for(n=0;n<v->segments;n++) {
    pthread_join(sftp_th[n],NULL);
    if (sftp_td[n].rc<0) {rc=sftp_td[n].rc;}
   }
  }
  if (rc<0) {
   fprintf(stderr,"### ERROR  : Put remote vault failed\n");
   return -22;
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
 unsigned char buffer[MASTER_BLOCK_SIZE];
 unsigned char hostn[256];
 unsigned char filen[1024];
 unsigned char uhash[64];
 FILE *fp;
 uint16_t dpos;
 size_t sz;
 crypttale ct;

 //Create a local unique master obscuring key
 if (*master_obscure==0) {
  get_unique_hash(uhash); sz=64;
  data2hex(uhash,master_obscure,&sz);
 }

 //Setup
 random_wipe(buffer,MASTER_BLOCK_SIZE);
 init_encrypt(&ct,master_obscure,0);
 gethostname(hostn,256);
 sz=evlt_sha_hex(hostn,hex512,strnlen(hostn,256));
 sprintf(filen,"%s/%s.evlt",path,hex512);

 //Delete if expired
 delete_if_older(filen,master_expire_minutes);

 //Read
 fp=fopen(filen,"rb");
 if (fp==NULL) {return 0;}
 sz=fread(buffer,1,MASTER_BLOCK_SIZE,fp);
 fclose(fp);
 if (sz<MASTER_BLOCK_SIZE) {return 0;}

 //Process
 decrypt_data(&ct,buffer,MASTER_BLOCK_SIZE);
 dpos=*(uint16_t *)buffer;
 memcpy(m,buffer+dpos,129);
 if (m[128]!=0) {return 0;}
 return 129;
}

size_t evlt_put_masterkey(unsigned char *path,unsigned char *m,size_t s) {
 unsigned char hex512[129];
 unsigned char buffer[MASTER_BLOCK_SIZE];
 unsigned char hostn[256];
 unsigned char filen[1024];
 unsigned char uhash[64];
 FILE *fp;
 uint16_t dpos;
 size_t sz;
 crypttale ct;

 //Create a local unique master obscuring key
 if (*master_obscure==0) {
  get_unique_hash(uhash); sz=64;
  data2hex(uhash,master_obscure,&sz);
 }

 //Setup
 random_wipe(buffer,MASTER_BLOCK_SIZE);
 init_encrypt(&ct,master_obscure,0);
 gethostname(hostn,256);
 sz=evlt_sha_hex(hostn,hex512,strnlen(hostn,256));
 sprintf(filen,"%s/%s.evlt",path,hex512);
 mkdir(path,S_IRWXU);

 //Process
 sz=evlt_sha_hex(m,hex512,s);
 dpos=2+random()%(MASTER_BLOCK_SIZE-132);
 *(uint16_t *)buffer=dpos;
 memcpy(buffer+dpos,hex512,129);
 encrypt_data(&ct,buffer,MASTER_BLOCK_SIZE);

 //Write
 fp=fopen(filen,"wb");
 if (fp==NULL) {return 0;}
 sz=fwrite(buffer,1,MASTER_BLOCK_SIZE,fp);
 fclose(fp);
 if (sz<MASTER_BLOCK_SIZE) {return 0;}
 return sz;
}

void evlt_kpath2keys(evlt_act *a) {
 unsigned char tmp[KPATH_SIZE];
 unsigned char *cp, *sp;
 int n,l,kp=0;
 strncpy(tmp,a->kpath,KPATH_SIZE);
 tmp[1023]=0;
 l=strnlen(tmp,KPATH_SIZE)+1;
 cp=tmp;
 if (*cp=='/') {cp++;}
 sp=cp;
 a->key1[0]=0;
 a->key2[0]=0;
 a->key3[0]=0;
 for(n=0;n<l && kp<4;n++) {
  if (*cp=='/' || *cp==0) {
   switch (kp) {
    case 0:
      *cp=0;
      strncpy(a->vname,sp,VAULTNAME_SIZE);
      a->vname[31]=0;
     break;;
    case 1:
      *cp=0;
      strncpy(a->key1,sp,VAULTKEY_SIZE);
      a->key1[511]=0;
     break;;
    case 2:
      *cp=0;
      strncpy(a->key2,sp,VAULTKEY_SIZE);
      a->key2[511]=0;
     break;;
    case 3:
      strncpy(a->key3,sp,VAULTKEY_SIZE);
      a->key3[511]=0;
     break;;
   }
   kp++;
   sp=cp+1;
  }
  cp++;
 }
 if (a->key1[0]==0) evlt_sha_hex(a->vname,a->key1,strnlen(a->vname,32));
 if (a->key2[0]==0) evlt_sha_hex(a->key1,a->key2,strnlen(a->key1,32));
 if (a->key3[0]==0) evlt_sha_hex(a->key2,a->key3,strnlen(a->key2,32));

 if (a->action==4) {
  strncpy(tmp,a->vname,VAULTNAME_SIZE);
  tmp[VAULTNAME_SIZE-1]=0;
  sprintf(a->vname,"$$INDEX$$__%s",tmp);
  a->action=0;
 }
}
