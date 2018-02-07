#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "gzinject.h"
#include "aes.h"
#include "sha1.h"

unsigned char key[16];

unsigned char newkey[16] = {
	0x47, 0x5a, 0x49, 0x73, 0x4c, 0x69, 0x66, 0x65, 0x41, 0x6e, 0x64, 0x42, 0x65, 0x65, 0x72, 0x21
};

u32 addpadding(unsigned int inp, unsigned int padding) {
	int ret = inp;
	if (inp % padding != 0) {
		ret = inp + (padding - (inp % padding));
	}
	return ret;
}

u32 getcontentlength(WAD *wad, unsigned int contentnum) {
	u32 off = wad->tmdpos + 0x1ec + (36 * contentnum);
	return wad->data[off + 4] << 24 |
		wad->data[off + 5] << 16 |
		wad->data[off + 6] << 8 |
		wad->data[off + 7];
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

u32 toppc32(u32 in) {
	u32 d;
	u32 *dst = (u32*)&d;
	u32 *src = (u32*)&in;
	dst[0] = src[7];
	dst[1] = src[6];
	dst[2] = src[5];
	dst[3] = src[4];
}

void print_usage() {
	printf("gzinject extract|pack|genkey \
	extract: DonorWad - Extracts DonorWad to wadextract \
	pack: OutWad - Packs wadextact into OutWad \
	genkey: generates common-key.bin");
}

void do_extract(const char *inwad) {

	mkdir("wadextract",0755);

	chdir("wadextract");

	WAD* wad = (WAD*)malloc(sizeof(WAD));
	FILE *wadfile = fopen(inwad, "rb");
	fseek(wadfile, 0, SEEK_END);
	wad->wadsize = ftell(wadfile);
	fseek(wadfile, 0, SEEK_SET);
	wad->data = (u8*)malloc(wad->wadsize);
	fread(wad->data, 1, wad->wadsize, wadfile);
	fclose(wadfile);


	wad->certsize = be32(wad->data + 0x08);
	wad->tiksize = be32(wad->data + 0x10);
	wad->tmdsize = be32(wad->data + 0x14);
	wad->datasize = be32(wad->data + 0x18);
	wad->footersize = be32(wad->data + 0x1C);

	wad->certpos = 0x40;
	wad->tikpos = 0x40 + addpadding(wad->certsize, 64);
	wad->tmdpos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64);
	wad->datapos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64) + addpadding(wad->tmdsize, 64);
	wad->footerpos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64) + addpadding(wad->tmdsize, 64) + addpadding(wad->datasize, 64);

	wad->contentcount = be16(wad->data + wad->tmdpos + 0x1de);

	FILE* outfile = fopen("cert.cert", "wb");
	fwrite(wad->data + wad->certpos, 1, wad->certsize, outfile);
	fclose(outfile);

	outfile = fopen("tiket.tik", "wb");
	fwrite(wad->data + wad->tikpos, 1, wad->tiksize, outfile);
	fclose(outfile);

	outfile = fopen("metadata.tmd", "wb");
	fwrite(wad->data + wad->tmdpos, 1, wad->tmdsize, outfile);
	fclose(outfile);

	outfile = fopen("footer.footer", "wb");
	fwrite(wad->data + wad->footerpos, 1, wad->footersize, outfile);
	fclose(outfile);

	unsigned char encryptedkey[16], iv[16];

	u16 i, j;
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
		u32 contentpos = wad->datapos;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(wad, j), 64);
		}

		iv[0] = wad->data[wad->tmdpos + 0x1e8 + (0x24 * i)];
		iv[1] = wad->data[wad->tmdpos + 0x1e9 + (0x24 * i)];

		aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, encryptedkey, iv);



		u32 size = addpadding(getcontentlength(wad, i), 16);
		AES_CBC_decrypt_buffer(aes, wad->data + contentpos, size);


		free(aes);

		if (i == 1) {
			// Memory fix 
			wad->data[contentpos + 0x2EB0] = 0x60;
			wad->data[contentpos + 0x2EB1] = 0x00;
			wad->data[contentpos + 0x2EB3] = 0x00;

			// Mapping fix
			// DUP
			wad->data[contentpos + 0x16BAF0] = 0x08;
			wad->data[contentpos + 0x16BAF1] = 0x00;

			// DDown
			wad->data[contentpos + 0x16BAF4] = 0x04;
			wad->data[contentpos + 0x16BAF5] = 0x00;

			// DLEFT
			wad->data[contentpos + 0x16BAF8] = 0x02;
			wad->data[contentpos + 0x16BAF9] = 0x00;

			// DRIGHT
			wad->data[contentpos + 0x16BAFC] = 0x01;
			wad->data[contentpos + 0x16BAFD] = 0x00;

			// CStick Down -> L
			wad->data[contentpos + 0x16BB05] = 0x20;
		}

		// Main rom content file
		if (i == 5) {
			mkdir("content5",0755);
			chdir("content5");
			u8_header header;
			u32 data_offset;
			/*u16 dir_stack[16];
			int dir_index = 0;*/
			u8 *string_table;
			size_t rest_size;

			memcpy(&header, wad->data + contentpos, sizeof(header));

			int curpos = contentpos + sizeof(header);

			u8_node root_node;
			memcpy(&root_node, wad->data + curpos, sizeof(u8_node));
			curpos += sizeof(u8_node);

			u32 nodec = be32((u8*)&root_node.size) - 1;

			u8_node *nodes = malloc(sizeof(u8_node)*nodec);
			memcpy(nodes, wad->data + curpos, sizeof(u8_node)*nodec);
			curpos += sizeof(u8_node)*nodec;

			data_offset = be32((u8*)&header.data_offset);
			rest_size = data_offset - sizeof(header) - (nodec + 1) * sizeof(u8_node);
			string_table = malloc(rest_size);
			memcpy(string_table, wad->data + curpos, rest_size);

			u8_node *node;
			for (j = 0; j < nodec; j++) {
				node = &nodes[j];
				u32 doffset = be32((u8*)&node->data_offset);
				u32 dsize = be32((u8*)&node->size);
				u16 name_offset = be16((u8*)&node->name_offset);
				u16 type = be16((u8*)&node->type);
				char *name = (char*)&string_table[name_offset];

				u8* file_data;

				printf("%d %s\r\n", type, name);
				/*if (type == 0x0100) {
					mkdir(name, 0777);
					chdir(name);
					dir_stack[++dir_index] = size;
				}
				*/
				if (type == 0x00) {
					file_data = malloc(dsize);
					outfile = fopen(name, "wb");
					fwrite(wad->data + doffset, 1, dsize, outfile);
					fclose(outfile);
					free(file_data);
				}
				/*while (dir_stack[dir_index] == j + 2 && dir_index > 0) {
					chdir("..");
					dir_index--;
				}*/
			}
			chdir("..");
		}
		
		char *contentname = malloc(100);
		snprintf(contentname, 100, "content%d.app", i);
		outfile = fopen(contentname, "wb");
		fwrite(wad->data + contentpos, 1, getcontentlength(wad, i), outfile);
		fclose(outfile);
		free(contentname);
	}
	free(wad->data);
	free(wad);

}

void do_pack(const char *outwad) {

	chdir("wadextract");
	WAD *wad = malloc(sizeof(WAD));
	
	struct stat sbuffer;
	stat("cert.cert", &sbuffer);
	wad->certsize = sbuffer.st_size;
	wad->certpos = 0x40;

	stat("tiket.tik", &sbuffer);
	wad->tiksize = sbuffer.st_size;
	wad->tikpos = 0x40 + addpadding(wad->certsize, 64);
	
	stat("metadata.tmd", &sbuffer);
	wad->tmdsize = sbuffer.st_size;
	wad->tmdpos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64);

	stat("footer.footer", &sbuffer);
	wad->footersize = sbuffer.st_size;

	wad->datapos = 0x40 + addpadding(wad->certsize, 64) + addpadding(wad->tiksize, 64) + addpadding(wad->tmdsize, 64);

	FILE *infile = fopen("cert.cert", "rb");
	u8 *cert = malloc(addpadding(wad->certsize, 64));
	fread(cert, 1, wad->certsize, infile);
	fclose(infile);
	
	infile = fopen("tiket.tik", "rb");
	u8 *tik = malloc(addpadding(wad->tiksize, 64));
	fread(tik, 1, wad->tiksize, infile);
	fclose(infile);

	infile = fopen("metadata.tmd", "rb");
	u8 *tmd = malloc(addpadding(wad->tmdsize, 64));
	fread(tmd, 1, wad->tmdsize, infile);
	fclose(infile);

	infile = fopen("footer.footer", "rb");
	u8 *footer = malloc(addpadding(wad->footersize, 64));
	fread(footer, 1, wad->footersize, infile);
	fclose(infile);

	u16 contentsc = be16(tmd + 0x1DE);
	int i;
	char *cfname = malloc(16);
	u32 paddedsize = 0;
	for (i = 0; i < contentsc; i++) {
		snprintf(cfname, 16, "content%d.app", i);
		stat(cfname, &sbuffer);
		wad->datasize += sbuffer.st_size;
		paddedsize += addpadding(sbuffer.st_size, 64);
	}
	u8 *contents = malloc(paddedsize);
	u32 dpos = 0;

	// New key
	memcpy(tik + 0x1bf, &newkey, 16);

	// Decrypt the new key
	char newenc[16];
	u8 iv[16];

	for (i = 0; i < 16; i++) {
		newenc[i] = *(tik + 0x1bf + i);
	}
	for (i = 0; i < 8; i++) {
		iv[i] = *(tik + 0x1dc + i);
		iv[i + 8] = 0x00;
	}


	struct AES_ctx *aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_decrypt_buffer(aes, newenc, 16);
	free(aes);
	


	for (i = 0; i < contentsc; i++) {
		snprintf(cfname, 16, "content%d.app", i);
		stat(cfname, &sbuffer);
		infile = fopen(cfname, "rb");
		fread(contents + dpos, 1, sbuffer.st_size, infile);
		fclose(infile);
		

		

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

		AES_CBC_encrypt_buffer(aes, contents + dpos, sbuffer.st_size);

		char digest[20];
		SHA1_CTX *sha1 = malloc(sizeof(SHA1_CTX));
		SHA1Init(sha1);
		SHA1Update(sha1, contents + dpos, sbuffer.st_size);
		SHA1Final(digest, sha1);

		memcpy(tmd + 0x1f4 + (36 * i), &digest, 20);
		free(sha1);

		dpos += addpadding(sbuffer.st_size, 64);
	}

	

	// Build Content5 into a .app file first
	DIR *dir;
	struct dirent *ent;

	u8 nodec = 0;

	chdir("content5");

	if ((dir = opendir(".")) != NULL) {
		/* print all the files and directories within directory */
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_type == DT_REG) {
				nodec++;
			}
		}
		closedir(dir);
	}

	u8 *string_table = malloc(nodec * 100 * sizeof(u8)); // Assume max 100 char per filename
	memset(string_table, 0,(nodec * 100 * sizeof(u8)));
	strcpy(string_table, "~.~");
	if ((dir = opendir(".")) != NULL) {
		/* print all the files and directories within directory */
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_type == DT_REG) {
				strcat(string_table, ent->d_name);
				strcat(string_table, "~"); // no filename should have ~ right? RIGHT? 
			}
		}
		closedir(dir);
	}
	int k;
	u8 prevchar = 1;
	for (k = 0; k < nodec * 100; k++) {
		printf("%d %d %d\r\n", prevchar, string_table[k],k);
		if (prevchar == 0 && string_table[k] == 0) {
			break;
		}
		prevchar = string_table[k];
	}
	int l;
	for (l = 0; l < k; l++) {
		if (string_table[l] == 0x7e) string_table[l] = 0x00;
	}

	

	u8_node rootnode;
	rootnode.size = be32(nodec);
	rootnode.name_offset = 0x00;
	rootnode.data_offset = 0x00;
	rootnode.size = nodec + 1;

	u8_header header;
	header.tag = 0x2d38AA55; // 0x55AA382D 
	header.rootnode_offset = 0x00002000; // 0x00000020
	header.header_size = 0x20 + sizeof(u8_node) + k + 3;

	FILE *tfile = fopen("C:\\users\\Dell T3600\\Desktop\\test.bin", "w");
	fwrite(&header, 1, sizeof(header), tfile);
	fclose(tfile);
	
}

int main(int argc, char **argv) {


	u32 interesting = 0x55AA382D;
	u32 interesting2 = topcc32(interesting);


	FILE *ftest = fopen("C:\\users\\Dell T3600\\Desktop\\test.bin", "w");
	fwrite(&interesting2, 1, 4, ftest);
	fclose(ftest);

	FILE *fkey = fopen("C:\\Users\\Dell T3600\\Downloads\\ShowMiiWads 1.4 x64\\common-key.bin", "rb");
	fread(&key, 1, 16, fkey);
	fclose(fkey);

	do_pack("xd.wad");
	//do_extract("C:\\users\\Dell T3600\\downloads\\oot.wad");
	/*
	if (argc == 2) {

	}

	if (argc < 4) {
		printf("Usage: gzinject DonorWad rom OutputWad [Channel ID]\r\n");
		exit(1);
	}

	struct stat sbuffer;

	char *keyfile;

	if (stat("key.bin", &sbuffer) != 0) {
		if (stat("common-key.bin", &sbuffer) != 0) {
			printf("(common-)key.bin not found in current directory!\r\n");
			exit(1);
		}
		else {
			keyfile = "common-key.bin";
		}

	}
	else {
		keyfile = "key.bin";
	}

	if (stat(argv[1], &sbuffer) != 0) {
		printf("donor wad doesn't exist!\r\n");
		exit(1);
	}

	if (stat(argv[2], &sbuffer) != 0) {
		printf("rom to inject doesn't exist!\r\n");
		exit(1);
	}


	for(int i=0;;){
		// VC content file



		}

	}

	// Change Title ID
	if (argc == 5) {
		wad->data[0x1e0 + wad->tikpos] = argv[4][0];
		wad->data[0x1e1 + wad->tikpos] = argv[4][1];
		wad->data[0x1e2 + wad->tikpos] = argv[4][2];
		wad->data[0x1e3 + wad->tikpos] = argv[4][3];

		wad->data[0x190 + wad->tmdpos] = argv[4][0];
		wad->data[0x191 + wad->tmdpos] = argv[4][1];
		wad->data[0x192 + wad->tmdpos] = argv[4][2];
		wad->data[0x193 + wad->tmdpos] = argv[4][3];
	}

	// Region Free
	wad->data[wad->tmdpos + 0x19d] = 0x03;

	// New key
	memcpy(wad->data + wad->tikpos + 0x1bf, &newkey, 16);

	// Decrypt the new key
	char newenc[16];

	for (i = 0; i < 16; i++) {
		newenc[i] = *(wad->data + wad->tikpos + 0x1bf + i);
	}
	for (i = 0; i < 8; i++) {
		iv[i] = *(wad->data + wad->tikpos + 0x1dc + i);
		iv[i + 8] = 0x00;
	}


	aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_decrypt_buffer(aes, newenc, 16);
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

	// Reencrypt contents;
	for (i = 0; i < wad->contentcount; i++) {

		u32 contentpos = wad->datapos;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(wad, j), 64);
		}

		iv[0] = wad->data[wad->tmdpos + 0x1e8 + (0x24 * i)];
		iv[1] = wad->data[wad->tmdpos + 0x1e9 + (0x24 * i)];

		u32 size = addpadding(getcontentlength(wad, i), 16);

		// Generate a sigature for changed contents
		if (i == 5 || i == 1) {
			char digest[20];
			SHA1_CTX *sha1 = malloc(sizeof(SHA1_CTX));
			SHA1Init(sha1);
			SHA1Update(sha1, wad->data + contentpos, size);
			SHA1Final(digest, sha1);

			memcpy(wad->data + wad->tmdpos + 0x1f4 + (36 * i), &digest, 20);
			free(sha1);
		}

		aes = malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, newenc, iv);



		AES_CBC_encrypt_buffer(aes, wad->data + contentpos, size);
		free(aes);

	}





	FILE *outwad = fopen(argv[3], "wb");
	fwrite(wad->data, 1, wad->wadsize, outwad);
	fclose(outwad);

	free(wad->data);
	free(wad);
	*/

	return 0;
}



/* Copy the new rom into the content, it would be more accurate to determine if the filename is "rom", but at this point checking for 32MB file should be fine.
if (dsize == 33554432) {
FILE *gz = fopen(argv[2], "rb");
u8* gzbuffer = (u8*)malloc(dsize);
fread(gzbuffer, 1, dsize, gz);
fclose(gz);

memcpy(wad->data + doffset + contentpos, gzbuffer, dsize);
free(gzbuffer);

}*/