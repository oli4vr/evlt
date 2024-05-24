/* hexenc.h
 */
//Convert binary data to an ascii hexadecimal string
unsigned char data2hex(unsigned char *src,unsigned char *dest, size_t *len);

//Convert ascii hexadecimal string to binary data
unsigned char hex2data(unsigned char *src,unsigned char *dest, size_t *len);

