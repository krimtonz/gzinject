#ifndef _GZINJECT_H_
#define _GZINJECT_H_

#include <stddef.h>

#define REVERSEENDIAN32(X)  (((X) >> 24) & 0xff) | (((X)<<8) & 0xFF0000) | (((X) >> 8) & 0xff00) | (((X)<<24) & 0xff000000)
#define REVERSEENDIAN16(X) (((X)>>8) & 0xff) | (((X)<<8) & 0xFF00)

#define W_TIK 0x00
#define W_TMD 0x01
#define GZINJECT_VERSION "0.3.0"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef struct {
	u16 type;
	u16 name_offset;
	u32 data_offset;
	u32 size;
}u8_node;

typedef struct
{
	u32 tag;
	u32 rootnode_offset;
	u32 header_size;
	u32 data_offset;
	u8 padding[16];
} u8_header;

typedef struct {
	u8_header header;
	u8_node root_node;
	u8 *string_table;
	size_t table_size;
	u8_node *nodes;
	u32 nodec;
}u8_meta;

typedef struct {
	u32 certsize;
	u32 tiksize;
	u32 tmdsize;
	u32 datasize;

	u32 certpos;
	u32 tikpos;
	u32 tmdpos;
	u32 datapos;

	u8* cert;
	u8* tik;
	u8 *tmd;
	u8* data;

	u16 contentcount;
}wad_t;

u16 be16(const u8 *p);
u32 be32(const u8 *p);

u32 getcontentlength(u8 *, unsigned int);
u32 addpadding(unsigned int, unsigned int);
void truchasign(u8 *, u8, size_t);
void removefile(const char *);
void removedir(const char *);
char *removeext(char *);
void genkey();
void do_extract(u8*,wad_t*);
void do_pack(const char*,const char*);
void print_usage();
void print_version();
void extract_u8_archive(u8*,const char*);
void pack_u8_archive(u8*,u8*,size_t);
void get_u8_meta(u8*, u8_meta*);
void replace_rom(u8*, u8*, size_t);
u32 getcontentpos(u8*, wad_t*, unsigned int);
#endif
