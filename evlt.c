#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>
#include "sha512.h"
#include "encrypt.h"
#include "hexenc.h"
#include "evlt.h"

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

int evlt_init(evlt_vault *v,unsigned char *name,unsigned char segments) {
 unsigned char subname[MAX_SEGMENTS][256];
 unsigned char exploded[1024];
 unsigned char shaout[256];
 unsigned char hexout[256];
 unsigned char evlt_path[256]={0};
 unsigned char *cp;
 FILE *fp;
 size_t sz;
 int n;
 memset(v->name,0,sizeof(v->name));
 strncpy(v->name,name,32);
 v->name[31]=0;
 v->segments=segments;

 //Hidden subdir in user home
 snprintf(evlt_path,256,"%s/.evlt", getpwuid(getuid())->pw_dir);
 mkdir(evlt_path,S_IRWXU);

 for(n=0;n<segments;n++) {
  //Generate vault segment filenames
  sz=64;
  snprintf(subname[n],1024,"%s__%04lx__%04lx",v->name,segments,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->segfile[n],1024,"%s/%s.evlt",evlt_path,hexout);
  //Generate write segment filenames
  sz=64;
  snprintf(subname[n],1024,"$$Wr1T3temp$$__%s__%04lx__%04lx",v->name,segments,n);
  explode1024(exploded,subname[n]);
  SHA512(exploded,1024,shaout);
  data2hex(shaout,hexout,&sz);
  snprintf(v->wrtfile[n],1024,"%s/%s.evlt",evlt_path,hexout);
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
 if (nrread<(v->segments)) {return 0;}

 if (i.datalength<1) {return 1;}

 if (v->wfp[0]==NULL && fp!=NULL) {
  rc=fwrite(i.data,1,i.datalength,fp);
 }

 if (i.eblock[0].flags & FLAG_STOP) {
  return 0;
 }

 return 2;
}

int evlt_io(evlt_vault *v,FILE *fp,unsigned char iomode,unsigned char *key1,unsigned char *key2,unsigned char *key3) {
 unsigned char buffer[BUFFER_SIZE];
 unsigned char *cp;
 int len=0,clen,lput=MAX_SEGMENTS;
 int n,m,md,rc;
 unsigned char newvault=0;
 unsigned char rcr=1,rcw=1;
 evlt_block bld[MAX_SEGMENTS];
 evlt_block * bd;
 evlt_vector vc;
 FILE *in, *out;

 if (fp==NULL) {return -1;}
 if (iomode==0) {
  in=NULL;out=fp;
 } else {
  in=fp;out=NULL;
 }

 init_encrypt(&vc.ct1,key1,2);
 init_encrypt(&vc.ct2,key2,2);
 init_encrypt(&vc.ct3,key3,2);
 vc.stop=0;

 //fopen all segment files for binary read
 for(n=0;n<v->segments;n++) {
  v->rfp[n]=fopen(v->segfile[n],"rb");
  v->wfp[n]=NULL;
  if (v->rfp[n]==NULL) {fprintf(stderr,"Error: Can't open the segment file for read.\n%s\n",v->segfile[n]); return -2;}
 }
 
 //in case of iomode 1 (write), open write files for binary write
 if (iomode>0) {
  for(n=0;n<v->segments;n++) {
   v->wfp[n]=fopen(v->wrtfile[n],"wb");
   if (v->wfp[n]==NULL) {fprintf(stderr,"Error: Can't open the temp segment file for write.\n%s\n",v->wrtfile[n]); return -2;}
  }
 }

 //Mix write/read
 if (iomode==0) {rcw=0;}
 while (rcw>0 || rcr>0) {
  if (rcw>0 && iomode>0) {rcw=evlt_iter_put(v,in,&vc);}
  if (rcr>0) {rcr=evlt_iter_get(v,out,&vc);}
 }

 //fclose all segment files
 for(n=0;n<v->segments;n++) {
  if (v->rfp[n]!=NULL) {fclose(v->rfp[n]);}
 }

 //in case of mode 1 (write), close write file and overwrite copy to read files
 if (iomode>0) {
  for(n=0;n<v->segments;n++) {
   if (v->wfp[n]!= NULL) {
    fclose(v->wfp[n]);
    rename(v->wrtfile[n],v->segfile[n]);
   }
  }
 }
}