#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//Ascii hexadecimal translation table
unsigned char hextranstab[17]="0123456789abcdef";

unsigned char data2hex(unsigned char *src,unsigned char *dest, size_t *len) {
 int n=0;
 unsigned char b1,b2;
 unsigned char *sp=src;
 unsigned char *dp=dest;

 for(;n<*len;n++) {
  b1=*sp>>4;
  b2=*sp&15;
  *dp=hextranstab[b1];dp++;
  *dp=hextranstab[b2];dp++;
  sp++;
 }
 *dp=0;
 *len<<=1;
}

//Return number/position in array of found character
unsigned char findchar(unsigned char *s,unsigned char c) {
 unsigned char n=0;
 unsigned char *sp=s;
 for(;n<16;n++) {
  if (*sp==c) {return n;}
  sp++;
 }
 return 0;
}

unsigned char hex2data(unsigned char *src,unsigned char *dest, size_t *len) {
 int n=0;
 unsigned char b1,b2;
 unsigned char *sp=src;
 unsigned char *dp=dest;

 for(;n<*len;n++) {
  b1=findchar(hextranstab,*sp);
  sp++;
  b2=findchar(hextranstab,*sp);
  sp++;
  *dp=(b1<<4)|b2;
  dp++;
 }
 *len>>=1;
}

