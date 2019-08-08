#ifndef _GZINJECT_H_
#define _GZINJECT_H_

#include <stddef.h>

#define REVERSEENDIAN32(X)  (((X) >> 24) & 0xff) | (((X)<<8) & 0xFF0000) | (((X) >> 8) & 0xff00) | (((X)<<24) & 0xff000000)
#define REVERSEENDIAN16(X) (((X)>>8) & 0xff) | (((X)<<8) & 0xFF00)

#define W_TIK 0x00
#define W_TMD 0x01
#define GZINJECT_VERSION "0.3.0"

typedef enum{
    FILE_DIRECTORY,
    FILE_NORMAL
}filetype_t;

uint16_t be16(const uint8_t *p);
uint32_t be32(const uint8_t *p);

uint32_t getcontentlength(uint8_t *, unsigned int);
uint32_t addpadding(unsigned int, unsigned int);
void truchasign(uint8_t *, uint8_t, size_t);
void removefile(const char *);
void removedir(const char *);
char *removeext(char *);
void genkey();
void do_extract();
void do_pack(const char*,const char*);
void print_usage();
void print_version();
#endif
