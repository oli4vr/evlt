#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include "sha512.h"
#include "encrypt.h"
#include "hexenc.h"
#include "evlt.h"
#include "main.h"

unsigned char hiddenout=0;
unsigned char runascmd=0;

//Process option parameters
int proc_opt(evlt_act *a,int argc,char ** argv) {
 int rc=0,n,l;
 char *opt;
 char optc;
 unsigned char tmp[1024]={0};
 unsigned char *cp,*sp;
 unsigned char kp=0;
 unsigned char *sp0=NULL,*sp1=NULL,*sp2=NULL,*sp3=NULL;
 argc--;argv++;

 if (argc<2) {//Bad nr arguments 
  return -1;
 }

 if (argv[0][0]=='-') {return -2;}

 if (strncmp(argv[0],"get",3)==0) {
  a->action=0;
  argc--;argv++;
 } else if (strncmp(argv[0],"put",3)==0) {
  a->action=1;
  argc--;argv++;
 }

 a->segments=8;
 a->verbose=0;

 strncpy(tmp,argv[0],1024);
 tmp[1023]=0;
 l=strnlen(tmp,1024);
 cp=tmp;
 if (*cp=='/') {cp++;}
 sp=cp;
 strncpy(a->key1,".default",512);
 strncpy(a->key2,".default",512);
 strncpy(a->key3,".default",512);
 for(n=0;n<l && kp<4;n++) {
  if (*cp=='/' || *cp==0) {
   switch (kp) {
    case 0:
      *cp=0;
      strncpy(a->vname,sp,32);
      a->key3[31]=0;
     break;;
    case 1:
      *cp=0;
      strncpy(a->key1,sp,512);
      a->key1[511]=0;
     break;;
    case 2:
      *cp=0;
      strncpy(a->key2,sp,512);
      a->key2[511]=0;
     break;;
    case 3:
      strncpy(a->key3,sp,512);
      a->key3[511]=0;
     break;;
   }
   kp++;
   sp=cp+1;
  }
  cp++;
 }

 argc--;argv++;

 while (argc>0 && rc>=0) {
  opt=argv[0];
  if (*opt=='-') {
   optc=opt[1];
   switch (optc) {
    case 'n':
     argc--;argv++;
     if (argc<1) {return -5;}
     else {
      a->segments=atoi(argv[0]);
      if (a->segments<1 || a->segments>32) {a->segments=8;}
     }
    break;;
    case 'v':
      a->verbose=1;
     break;;
    case 'i':
      hiddenout=1;
     break;;
    case 'c':
      runascmd=1;
     break;;
   }
  }
  argc--;argv++;
 }
 return rc;
}

//Print standard help text to stderr
int print_help(unsigned char *cmd) {
 if (cmd==NULL) {return -1;}
 fprintf(stderr,"evlt     -> Entropy Vault\n");
 fprintf(stderr,"            by Olivier Van Rompuy\n\n");
 fprintf(stderr," Syntax  -> evlt put /vaultname/key1/key2/key3 [-v] [-n NR_SEGMENTS]\n");
 fprintf(stderr,"         -> evlt get /vaultname/key1/key2/key3 [-v] [-n NR_SEGMENTS]\n\n");
 fprintf(stderr," put/get -> Store/Recall data. Uses stdin/stdout by default\n\n");
 fprintf(stderr," -v      -> Verbose mode\n\n");
 fprintf(stderr," -n NR   -> Use NR number of parallel vault file segments\n");
 fprintf(stderr,"            Default = 8\n\n");
 fprintf(stderr," -i      -> Invisible copy/pasteable output between >>> and <<<\n");
 fprintf(stderr,"            Good for passwords and keys.\n\n");
 fprintf(stderr," -c      -> Run content as a script or command\n\n");
 return 0;
}

//Main function for evlt
int main(int argc,char ** argv) {
 evlt_vault v;
 evlt_act a;
 int optrc;
 optrc=proc_opt(&a,argc,argv);
 unsigned char fname[1024]={0};
 FILE *fpo=stdout;
 FILE *fpi=stdin;

 if (optrc<0) {
  print_help(argv[0]);
  return -1;
 }

 srand(time(NULL)); 

 if (runascmd) {
  sprintf(fname,"/tmp/.%08lx%08lx.tmp",random(),random());
  fpo=fopen(fname,"wb");
  chmod(fname,S_IRWXU);
 }

 if (a.verbose) {
  fprintf(stderr,"Action: %d\nVault: %s\nSegments: %d\nKey1: %s\nKey2: %s\nKey3: %s\n",a.action,a.vname,a.segments,a.key1,a.key2,a.key3);
 }
 evlt_init(&v,a.vname,a.segments);
 switch (a.action) {
  case 0:
    if (hiddenout==1) fprintf(stdout,"Copy/Paste between >>>%c[8m",27);
    evlt_io(&v,fpo,0,a.key1,a.key2,a.key3);
    if (hiddenout==1) fprintf(stdout,"%c[m<<<\n\n",27);
   break;;
  case 1:
    evlt_io(&v,fpi,1,a.key1,a.key2,a.key3);
   break;;
 }

 if (runascmd) {
  fclose(fpo);
  system(fname);
  remove(fname);
 }

 return 0;
}