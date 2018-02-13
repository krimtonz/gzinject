#include <stddef.h>

#define REVERSEENDIAN32(X)  ((X >> 24) & 0xff) | ((X<<8) & 0xFF0000) | ((X >> 8) & 0xff00) | ((X<<24) & 0xff000000)
#define REVERSEENDIAN16(X) ((X>>8) & 0xff) | ((X<<8) & 0xFF00)

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
	u8 zeroes[16];
} u8_header;

u16 be16(const u8 *p);
u32 be32(const u8 *p);

u32 getcontentlength(u8 *tmd, unsigned int contentnum);
u32 addpadding(unsigned int inp, unsigned int padding);
