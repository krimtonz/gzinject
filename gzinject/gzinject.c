#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gzinject.h"
#include "aes.h"

#define GETLONGLONG(X,Y) (X[Y]<<52) | (X[Y+1]<<44) | (X[Y+2]<<36) | (X[Y+3]<<32) | (X[Y+4]<<24) | (X[Y+5]<<16)| (X[Y+6]<<8) | X[Y+7]
#define GETLONG(X,Y) (X[Y]<<24) | (X[Y+1]<<16) | (X[Y+2]<<8) | (X[Y+3])
#define GETINT(X,Y) (X[Y]<<8) | X[Y+1]
#define ADDPADDING(X) X+(64-(X%64))

unsigned char key[16] = {
	0xEB,
	0xE4,
	0x2A,
	0x22,
	0x5E,
	0x85,
	0x93,
	0xE4,
	0x48,
	0xD9,
	0xC5,
	0x45,
	0x73,
	0x81,
	0xAA,
	0xF7
};

typedef struct {
	size_t headersize;
	size_t certsize;
	size_t tiksize;
	size_t tmdsize;
	size_t datasize;
	size_t footersize;

	unsigned long certpos;
	unsigned long tikpos;
	unsigned long tmdpos;
	unsigned long datapos;
	unsigned long footerpos;
	unsigned int contentcount;

	size_t wadsize;
	unsigned char *data;
}WAD;

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


int addpadding(unsigned int inp, unsigned int padding) {
	int ret = inp;
	if (inp % padding != 0) {
		ret = inp + (padding - (inp % padding));
	}
	return ret;
}
unsigned long long getcontentlength(WAD *wad, unsigned int offset) {
	return GETLONGLONG(wad->data, wad->tmdpos + 0x1ec + (36 * offset));
}

u16 be16(const u8 *p)
{
	return (p[0] << 8) | p[1];
}

u32 be32(const u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

u64 be64(const u8 *p)
{
	return ((u64)be32(p) << 32) | be32(p + 4);
}

u64 be34(const u8 *p)
{
	return 4 * (u64)be32(p);
}

int main(int argc, char **argv) {

	WAD* wad = (WAD*)malloc(sizeof(WAD));

	FILE *wadfile = fopen("C:\\users\\andy\\Desktop\\gz.wad", "r");
	fseek(wadfile, 0, SEEK_END);
	wad->wadsize = ftell(wadfile);
	fseek(wadfile, 0, SEEK_SET);
	wad->data = (unsigned char*)malloc(wad->wadsize);
	fread(wad->data, 1, wad->wadsize, wadfile);
	fclose(wadfile);

	wad->certsize = GETLONG(wad->data, 8);

	wad->tiksize = GETLONG(wad->data, 0x10);

	wad->tmdsize = GETLONG(wad->data, 0x14);

	wad->datasize = GETLONG(wad->data, 0x18);

	wad->footersize = GETLONG(wad->data, 0x1C);

	wad->certpos = 0x40;
	wad->tikpos = 0x40 + addpadding(wad->certsize, 64);
	wad->tmdpos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64);
	wad->datapos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64) + addpadding(wad->tmdsize, 64);
	wad->footerpos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64) + addpadding(wad->tmdsize, 64) + addpadding(wad->datasize, 64);

	FILE *testFile = fopen("C:\\users\\andy\\Desktop\\TestExtract\\cert.cert", "w");
	unsigned char *buffer = (unsigned char*)malloc(wad->certsize);
	memcpy(buffer, wad->data + wad->certpos, wad->certsize);
	fwrite(buffer, 1, wad->certsize, testFile);
	fclose(testFile);
	free(buffer);

	testFile = fopen("C:\\users\\andy\\Desktop\\TestExtract\\ticket.tik", "w");
	buffer = (unsigned char*)malloc(wad->tiksize);
	memcpy(buffer, wad->data + wad->tikpos, wad->tiksize);
	fwrite(buffer, 1, wad->tiksize, testFile);
	fclose(testFile);
	free(buffer);

	testFile = fopen("C:\\users\\andy\\Desktop\\TestExtract\\metadata.tmd", "w");
	buffer = (unsigned char*)malloc(wad->tmdsize);
	memcpy(buffer, wad->data + wad->tmdpos, wad->tmdsize);
	fwrite(buffer, 1, wad->tmdsize, testFile);
	free(buffer);
	fclose(testFile);

	testFile = fopen("C:\\users\\andy\\Desktop\\TestExtract\\footer.footer", "w");
	buffer = (unsigned char*)malloc(wad->footersize);
	memcpy(buffer, wad->data + wad->footerpos, wad->footersize);
	fwrite(buffer, 1, wad->footersize, testFile);
	fclose(testFile);
	free(buffer);

	wad->contentcount = GETINT(wad->data, wad->tmdpos + 0x1de);

	unsigned char encryptedkey[16], iv[16];

	int i, j;
	for (i = 0; i < 16; i++) {
		encryptedkey[i] = *(wad->data + wad->tikpos + 0x1bf + i);
	}
	for (i = 0; i < 8; i++) {
		iv[i] = *(wad->data + wad->tikpos + 0x1dc + i);
		iv[i + 8] = 0x00;
	}


	struct AES_ctx *aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_decrypt_buffer(aes, encryptedkey, 16);
	free(aes);

	iv[2] = 0x00;
	iv[3] = 0x00;
	iv[4] = 0x00;
	iv[5] = 0x00;
	iv[6] = 0x00;
	iv[7] = 0x00;
	iv[8] = 0x00;
	iv[9] = 0x00;
	iv[10] = 0x00;
	iv[11] = 0x00;
	iv[12] = 0x00;
	iv[13] = 0x00;
	iv[14] = 0x00;
	iv[15] = 0x00;

	for (i = 0; i < wad->contentcount; i++) {
		unsigned long long contentpos = wad->datapos;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(wad, j), 64);
		}

		iv[0] = wad->data[wad->tmdpos + 0x1e8 + (0x24 * i)];
		iv[1] = wad->data[wad->tmdpos + 0x1e9 + (0x24 * i)];

		aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, encryptedkey, iv);

		char *filename = (char*)malloc(200);
		snprintf(filename, 200, "C:\\users\\andy\\Desktop\\TestExtract\\content%d.app", i);
		testFile = fopen(filename, "w");

		uint32_t size = addpadding(getcontentlength(wad, i), 16), size2 = getcontentlength(wad, i);

		char *buffer2 = (char*)malloc(size);

		memcpy(buffer2, wad->data + contentpos, size);
		AES_CBC_decrypt_buffer(aes, buffer2, size);
		fwrite(buffer2, 1, size, testFile);

		fclose(testFile);
		free(filename);
		free(aes);
		
		if (i == 5) {
			// buffer2 contains content5.app at this point
			u8_header header;
			
			memcpy(&header, buffer2, sizeof(header));

			int curpos = sizeof(header);

			u8_node root_node;
			memcpy(&root_node, buffer2 + curpos, sizeof(u8_node));
			curpos += sizeof(u8_node);

			u32 nodec = be32((u8*)&root_node.size) - 1;

			u8_node *nodes = malloc(sizeof(u8_node)*nodec);
			memcpy(nodes, buffer2 + curpos, sizeof(u8_node)*nodec);
			curpos += sizeof(u8_node)*nodec;
			u8_node *node;
			for (j = 0; j < nodec; j++) {
				node = &nodes[j];
				u16 nameoffset = be16((u8*)&node->name_offset);
				u32 doffset = be32((u8*)&node->data_offset);
				u32 dsize = be32((u8*)&node->size);
				
				if (dsize == 33554432) {
					char* name = (char*)&buffer2[nameoffset + curpos];
					printf("%s\t%d\r\n", name,doffset);
					FILE *atest = fopen("C:\\users\\andy\\desktop\\test.z64", "w");
					fwrite(buffer2 + doffset, 1, dsize, atest);
					fclose(atest);
				}
			}
		}
		free(buffer2);
	}



	free(wad);
	return 0;
}

