/* inifind.c
Functions to work with ini-files of syntax
[Section]
Field = Value

by Olivier Van Rompuy
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned char validchar(unsigned char c) {
 return ((c>='a' && c<='z')||(c>='A' && c<='Z')||(c>='0' && c<='9')||(c=='_')||(c=='.')||(c==':')||(c=='/')||(c=='-')||(c=='@'));
}

int findini(unsigned char *fname,unsigned char *section, unsigned char *field, unsigned char *value) {
 FILE *f;
 unsigned char tsec[128];
 unsigned char tfld[128];
 unsigned char *sp, *fp, *vp;
 unsigned char c;
 unsigned char found=0;
 unsigned char mode=0;
 unsigned char skip=0;

 sp=tsec;
 fp=tfld;
 vp=value;

 f=fopen(fname,"r");
 if (f==NULL) return -1;

 c=fgetc(f);
 while(!feof(f) && found==0) {
  if (c=='\n') skip=0;
  if (!skip) {
   switch (c) {
    case '#':
     skip=1;
     break;
    case '[':
      mode=1;
     break;
    case ']':
      if (mode!=1) return -2;
      mode=2;
      *sp=0;
      sp=tsec;
     break;
    case '=':
      if (mode!=3) return -2;
      *fp=0;
      fp=tfld;
      mode=4;
     break;
    case '\t':
    case ' ':
     if (mode==4 && vp>value) {
      *vp=' ';vp++;
     }
     break;
    default:
     switch (mode) {
      case 1:
        if (!validchar(c)) return -3;
        *sp=c;
        sp++;
       break;
      case 2:
        if (validchar(c)) {mode=3;*fp=c;fp++;}
	else {fp=tfld;}
       break;
      case 3:
        if (!validchar(c)) return -4;
        *fp=c;fp++;
       break;
      case 4:
        if (c=='\n') {
	 *vp=0;vp=value;mode=2;
	 if (strncmp(section,tsec,128)==0 && strncmp(field,tfld,128)==0) {
	  return strnlen(value,128);
	 }
	} else {
	 if (!validchar(c)) return -5;
         *vp=c;vp++;
	}
       break;
     }
     break;
    }
   }
  c=fgetc(f);
 }
 fclose(f);
 return 0;

}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file) {
        fclose(file);
        return 1;
    }
    return 0;
}
