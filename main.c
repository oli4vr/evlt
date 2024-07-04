/* main.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <time.h>
#include <inttypes.h>
#include <pwd.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/sha.h>
#include "encrypt.h"
#include "hexenc.h"
#include "pipes.h"
#include "sftp.h"
#include "evlt.h"
#include "inifind.h"

unsigned char hiddenout=0;
unsigned char runascmd=0;
unsigned char *evlt_path=NULL;
unsigned char *opt_fname=NULL;
unsigned char passcont=0;

int default_segments=8;
int default_blocksize=64;
unsigned char default_path[1024]={0};
unsigned char cfgfile_path[1024]={0};

unsigned char *evlt_getpass(const unsigned char *prompt,unsigned char *buf,size_t size) {
 strncpy(buf,getpass(prompt),80);
 buf[79]=0;
 return buf;
}

int process_rhoststring(unsigned char *s,evlt_act *a) {
 size_t n,l;
 unsigned char tmp[256];
 unsigned char *s1=NULL;
 unsigned char *s2=NULL;
 unsigned char *s3=NULL;
 unsigned char *sp=NULL;
 unsigned char *cp;
 if (s==NULL) return 0;
 if (*s==0) return 0;
 strncpy(tmp,s,256);
 tmp[255]=0;
 cp=tmp;
 sp=tmp;
 l=strnlen(tmp,256);
 for(n=0;n<l && *cp!=0 && *cp!='@';n++) {cp++;}
 if (*cp=='@') {
  *cp=0;
  sp=cp+1;
  strncpy(a->sftp_user,tmp,64);
  a->sftp_user[63]=0;
 } else {
  sp=tmp;
//  gethostname(a->sftp_user,64);
  strncpy(a->sftp_user,getlogin(),64);
  a->sftp_user[63]=0;
 }
 cp=tmp+l-1;
 for(n=l;n>0 && *cp!=0 && *cp!=':';n--) {cp--;}
 if (*cp==':') {
  *cp=0;
  a->sftp_port=atoi(cp+1);
 } else {
  a->sftp_port=22;
 }
 strncpy(a->sftp_host,sp,128);
 a->sftp_host[127]=0;

 if (a->sftp_host[0]==0) return 0;

// fprintf(stderr,"%s %s %d\n",a->sftp_user,a->sftp_host,a->sftp_port);

 return 1;
}

//Process option parameters
int proc_opt(evlt_act *a,int argc,char ** argv) {
 int rc=0,n,l;
 char *opt;
 char optc;
 unsigned char tmp[1024]={0};
 unsigned char passchk[VAULTKEY_SIZE]={0};
 unsigned char *cp,*sp;
 unsigned char kp=0;
 unsigned char *sp0=NULL,*sp1=NULL,*sp2=NULL,*sp3=NULL;
 unsigned char manpass=0;
 unsigned char hexkey[129];
 argc--;argv++;

 a->encrypt_file=0;

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
 } else if (strncmp(argv[0],"del",3)==0) {
  a->action=2;
  argc--;argv++;
 } else if (strncmp(argv[0],"append",3)==0) {
  a->action=3;
  argc--;argv++;
 } else if (strncmp(argv[0],"ls",3)==0) {
  a->action=4;
  argc--;argv++;
 }

 a->segments=default_segments;
 a->verbose=0;

 strncpy(a->kpath,argv[0],KPATH_SIZE);
 argc--;argv++;

 evlt_kpath2keys(a);

 while (argc>0 && rc>=0) {
  opt=argv[0];
  if (*opt=='-') {
   optc=opt[1];
   switch (optc) {
    case 'n':
      argc--;argv++;
      if (argc<1) {return -5;}
      else {
       if (argv[0][0]=='-') {return -5;}
       a->segments=atoi(argv[0]);
       if (a->segments<1 || a->segments>32) {a->segments=default_segments;}
      }
     break;;
    case 'b':
      argc--;argv++;
      if (argc<1) {return -8;}
      else {
       if (argv[0][0]=='-') {return -8;}
       a->blocksize=atoi(argv[0]);
       switch (a->blocksize) {
        case 1:
        case 2:
        case 4:
        case 8:
        case 16:
        case 32:
        case 64:
         break;;
        default:
          fprintf(stderr,"### ERROR   : Incorrect KB blocksize value. Allowed=1 2 4 8 16 32 64\n");
          return -8;
         break;;
       }
      }
     break;;
    case 'S':
      a->idxit=0;
     break;;
    case 'd':
      argc--;argv++;
      if (argc<1) {return -6;}
      else {
        evlt_path=argv[0];
      }
     break;;
    case 'f':
      argc--;argv++;
      if (argc<1) {return -7;}
      else {
        if (argv[0][0]=='-') {return -7;}
        opt_fname=argv[0];
      }
     break;;
    case 'm':
      argc--;argv++;
      if (argc<1) {manpass=1;}
      else {
       if (argv[0][0]=='-') {manpass=1;argc++;argv--;}
       else {
        if (strncmp(argv[0],"prompt",7)==0) {
         manpass=1;
        }
       }
      }
      if (manpass) {
       tmp[0]=0;
       if (a->action==0) {
        evlt_getpass("Master Key : ",tmp,VAULTKEY_SIZE);
       } else {
        evlt_getpass("Master Key 1st : ",tmp,VAULTKEY_SIZE);
        evlt_getpass("Master Key 2nd : ",passchk,VAULTKEY_SIZE);
        if (strncmp(tmp,passchk,VAULTKEY_SIZE)!=0) {
         fprintf(stderr,"### ERROR   : Password entries do not match!\n");
         return -4;
        }
       }
      } else {
       strncpy(tmp,argv[0],VAULTKEY_SIZE);
       tmp[511]=0;
      }
      if (tmp[0]!=0) {
       evlt_sha_hex(tmp,a->passkey,strnlen(tmp,VAULTKEY_SIZE));
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
    case 'p':
      passcont=1;
      a->segments=1;
      a->blocksize=1;
      hiddenout=1;
     break;;
    case 'R':
      argc--;argv++;
      if (argc<1) {return -13;}
      else {
        if (argv[0][0]=='-') {return -13;}
        process_rhoststring(argv[0],a);
      }
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
 fprintf(stderr,"evlt             Entropy Vault\n");
 fprintf(stderr,"                 by Olivier Van Rompuy\n\n");
 fprintf(stderr," Syntax          evlt put /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]\n");
 fprintf(stderr,"                 evlt get /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]\n");
 fprintf(stderr,"                 evlt del /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]\n\n");
 fprintf(stderr," put/get         Store/Recall a data blob. Uses stdin/stdout by default\n");
 fprintf(stderr," append          Append the input data to the end of an existing data blob\n");
 fprintf(stderr," del             Delete a data blob\n");
 fprintf(stderr," ls              List data entries in a path\n\n");
 fprintf(stderr," -v              Verbose mode\n");
 fprintf(stderr," -S              Secret mode -> Do not index entry -> Invisible to ls command\n");
 fprintf(stderr," -n NR           Use NR number of parallel vault file segments between 1 and 32. Default=8\n");
 fprintf(stderr," -b KBsize       Blocksize in KB Default=64KB Allowed=1 2 4 8 16 32 64\n");
 fprintf(stderr," -p              Password content -> Put: enter value using a password prompt\n");
 fprintf(stderr,"                                  -> Get: Invisible copy/paste output\n");
 fprintf(stderr," -i              Invisible copy/paste output. Good for keys.\n");
 fprintf(stderr," -c              Run content as a script or command\n");
 fprintf(stderr," -d path         Use an alternate dir path for the vault files\n");
 fprintf(stderr," -f file         Use file for input or output instead of stdin or stdout\n");
 fprintf(stderr," -m [masterkey]  Use a custom master key.\n");
 fprintf(stderr,"                 If not provided you need to enter it manually via a password prompt.\n");
 fprintf(stderr," -m prompt       Prompt for the default masterkey and store/change the value.\n");
 fprintf(stderr," -R [username@]host[:port]\n");
 fprintf(stderr,"                 Work on a remote vault via ssh. The rsa public key must be in ~/.ssh/authorized_keys on the remote host.\n");
 fprintf(stderr,"                 You can store RSA private keys in vault location /.secrets/.remotehosts/.privatekey/user@host[:port]\n\n");
 return 0;
}

//Main function for evlt
int main(int argc,char ** argv) {
 evlt_vault v;
 evlt_act a;
 int optrc,rc,vali;
 unsigned char fname[1024]={0};
 unsigned char tmp[1024];
 unsigned char val[64];
 unsigned char pass1[81];
 unsigned char pass2[81];
 FILE *fpo=stdout;
 FILE *fpi=stdin;
 size_t sz;

 snprintf(default_path,1024,"%s/.evlt", getpwuid(getuid())->pw_dir);
 memset(a.passkey,0,VAULTKEY_SIZE);
 a.passkey[0]=0;
 a.sftp_host[0]=0;
 a.sftp_user[0]=0;
 a.sftp_port=0;
 a.rsakey[0]=0;
 a.idxit=1;

 if (file_exists(".evlt.cfg")) {
  strncpy(cfgfile_path,".evlt.cfg",1024);
 } else {
  snprintf(cfgfile_path,1024,"%s/.evlt.cfg",default_path);
 }
 if (file_exists(cfgfile_path)) {
  val[0]=0;
  rc=findini(cfgfile_path,"evlt","DefaultSegments",val);
  if (rc>0) {
   vali=atoi(val);
   if (vali>0 && vali<33) default_segments=vali;
  }
  val[0]=0;
  rc=findini(cfgfile_path,"evlt","DefaultBlocksize",val);
  if (rc>0) {
   vali=atoi(val);
   if (vali==1 || vali==2 || vali==4 || vali==8 || vali==16 || vali==32 || vali==64) default_blocksize=vali;
  }
  tmp[0]=0;
  rc=findini(cfgfile_path,"evlt","DefaultPath",tmp);
  if (rc>0) {
   if (tmp[0]!=0) {tmp[1023]=0;strncpy(default_path,tmp,1024);}
  }
  tmp[0]=0;
  rc=findini(cfgfile_path,"evlt","RemoteHost",tmp);
  if (rc>0) {
   if (tmp[0]!=0) {tmp[1023]=0;process_rhoststring(tmp,&a);}
  }
 }
 tmp[0]=0;

 a.blocksize=default_blocksize;

 optrc=proc_opt(&a,argc,argv);

 setvbuf(stdin, NULL, _IONBF, 0);
 setvbuf(stdout, NULL, _IONBF, 0);

 if (optrc<0) {
  if (optrc!=-4) print_help(argv[0]);
  return -1;
 }

 if (passcont && a.action==1) {
  evlt_getpass("Password 1st : ",pass1,80);
  pass1[80]=0;
  evlt_getpass("Password 2nd : ",pass2,80);
  pass2[80]=0;
  if (strncmp(pass1,pass2,80)!=0) {
   fprintf(stderr,"### ERROR   : Password content does not match\n");
   return -11;
  }
  fpi=data2stream(pass1,strnlen(pass1,81));
 }

 srand(time(NULL)); 

 if (runascmd && a.action==0) {
  sprintf(fname,"/tmp/.%08lx%08lx.tmp",random(),random());
 }

 if (opt_fname!=NULL) {
  strncpy(fname,opt_fname,1024);
 }

 if (fname[0]!=0) {
  switch (a.action) {
    case 0:
      fpo=NULL;
      fpo=fopen(fname,"wb");
      if (fpo==NULL) {
        fprintf(stderr,"### ERROR   : Failed to open file %s for write\n",fname);
        return -2;
      }
     break;;
    case 1:
    case 3:
      fpi=NULL;
      fpi=fopen(fname,"rb");
      if (fpi==NULL) {
        fprintf(stderr,"### ERROR   : Failed to open file %s for read\n",fname);
        return -3;
      }
     break;;
  }
 }

 if (a.verbose) {
  fprintf(stderr,"### VERBOSE : Action=%d\n### VERBOSE : Vault=%s\n### VERBOSE : Segments=%d\n### VERBOSE : Key1=%s\n### VERBOSE : Key2=%s\n### VERBOSE : Key3=%s\n",a.action,a.vname,a.segments,a.key1,a.key2,a.key3);
  fprintf(stderr,"### VERBOSE : KPATH=%s\n",a.kpath);
 }

 v.path[0]=0;
 a.path[0]=0;
 if (evlt_path!=NULL) {
  strncpy(v.path,evlt_path,1024);
  strncpy(a.path,evlt_path,1024);
 } else {
//  snprintf(v.path,1024,"%s/.evlt", getpwuid(getuid())->pw_dir);
  strncpy(v.path,default_path,1024);
  v.path[1023]=0;
  strncpy(a.path,v.path,1024);
 }

 evlt_init(&v,&a);

 if (a.passkey[0]==0 && v.path[0]!=0) {
  sz=evlt_get_masterkey(v.path,tmp);
  if (sz==129) {
   memcpy(a.passkey,tmp,129);
  } else {
   evlt_getpass("Master Key : ",tmp,VAULTKEY_SIZE);
   sz=evlt_put_masterkey(v.path,tmp,strnlen(tmp,VAULTKEY_SIZE));
   if (sz>0) {
    sz=evlt_get_masterkey(v.path,tmp);
    if (sz==129) {
     memcpy(a.passkey,tmp,129);
    }
   }
  }
 }
 if (a.verbose) {
  fprintf(stderr,"### VERBOSE : MASTER=%s\n",a.passkey);
 }

 rc=-999;
 switch (a.action) {
  case 0:
    if (hiddenout==1) {
     if (passcont) fprintf(stdout,"Copy/Paste between >>>%c[8m",27);
     else fprintf(stdout,"### Payload Start ###\n%c[8m",27);
    }
    rc=evlt_io(&v,fpo,&a);
    if (hiddenout==1) {
     if (passcont) fprintf(stdout,"%c[m<<<\n\n",27);
     else fprintf(stdout,"%c[m\n### Payload End   ###\n",27);
    }
   break;;
  case 1:
  case 3:
    rc=evlt_io(&v,fpi,&a);
   break;;
  case 2:
    rc=evlt_io(&v,NULL,&a);
   break;
 }
 evlt_exit(&v,&a);
 if (a.verbose) {
  fprintf(stderr,"### VERBOSE : IO RC=%d\n### VERBOSE : Original_Read_Data_Size=%llu\n### VERBOSE : New_Write_Data_size=%llu\n",rc,a.read_data_size,a.write_data_size);
 }

 if (fname[0]!=0) {
  switch (a.action) {
    case 0:
      fclose(fpo);
     break;;
    case 1:
      fclose(fpi);
     break;;
  }
 }

 if (runascmd && a.action==0) {
  chmod(fname,S_IRWXU);
  system(fname);
  remove(fname);
 }

 return 0;
}
