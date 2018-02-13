#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include "gzinject.h"
#include "aes.h"
#include "sha1.h"

unsigned char key[16];

const unsigned char newkey[16] = {
	0x47, 0x5a, 0x49, 0x73, 0x4c, 0x69, 0x66, 0x65, 0x41, 0x6e, 0x64, 0x42, 0x65, 0x65, 0x72, 0x21
};

u32 addpadding(unsigned int inp, unsigned int padding) {
	int ret = inp;
	if (inp % padding != 0) {
		ret = inp + (padding - (inp % padding));
	}
	return ret;
}

u32 getcontentlength(u8 *tmd, unsigned int contentnum) {
	u32 off = 0x1ec + (36 * contentnum);
	return tmd[off + 4] << 24 |
		tmd[off + 5] << 16 |
		tmd[off + 6] << 8 |
		tmd[off + 7];
}

u16 be16(const u8 *p)
{
	return (p[0] << 8) | p[1];
}

u32 be32(const u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

void print_usage() {
	printf("gzinject extract|pack|genkey\r\n\textract: DonorWad - Extracts DonorWad to wadextract\r\n\tpack: OutWad - Packs wadextact into OutWad\r\n\tgenkey: generates common-key.bin\r\n");
}

void do_extract(const char *inwad) {

	mkdir("wadextract", 0755);
	FILE *wadfile = fopen(inwad, "rb");
	fseek(wadfile, 0, SEEK_END);
	size_t wadsize = ftell(wadfile);
	fseek(wadfile, 0, SEEK_SET);
	u8 *data = (u8*)malloc(wadsize);
	fread(data, 1, wadsize, wadfile);
	fclose(wadfile);

	chdir("wadextract");

	u32 certsize = be32(data + 0x08);
	u32 tiksize = be32(data + 0x10);
	u32 tmdsize = be32(data + 0x14);
	u32 datasize = be32(data + 0x18);
	u32 footersize = be32(data + 0x1C);

	u32 certpos = 0x40;
	u32 tikpos = 0x40 + addpadding(certsize, 64);
	u32 tmdpos = tikpos + addpadding(tiksize, 64);
	u32 datapos = tmdpos + addpadding(tmdsize, 64);
	u32 footerpos = addpadding(datasize, 64);

	u16 contentcount = be16(data + tmdpos + 0x1de);

	FILE* outfile = fopen("cert.cert", "wb");
	fwrite(data + certpos, 1, certsize, outfile);
	fclose(outfile);

	outfile = fopen("tiket.tik", "wb");
	fwrite(data + tikpos, 1, tiksize, outfile);
	fclose(outfile);

	outfile = fopen("metadata.tmd", "wb");
	fwrite(data + tmdpos, 1, tmdsize, outfile);
	fclose(outfile);

	unsigned char encryptedkey[16], iv[16];

	u8 i, j;
	for (i = 0; i < 16; i++) {
		encryptedkey[i] = data[tikpos + 0x1bf + i];
	}
	for (i = 0; i < 8; i++) {
		iv[i] = data[tikpos + 0x1dc + i];
		iv[i + 8] = 0x00;
	}

	struct AES_ctx *aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_decrypt_buffer(aes, encryptedkey, 16);
	free(aes);

	for (j = 2; j < 16; j++) iv[j] = 0x00;

	for (i = 0; i < contentcount; i++) {
		u32 contentpos = datapos;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(data + tmdpos, j), 64);
		}

		iv[0] = data[tmdpos + 0x1e8 + (0x24 * i)];
		iv[1] = data[tmdpos + 0x1e9 + (0x24 * i)];

		aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, encryptedkey, iv);



		u32 size = addpadding(getcontentlength(data + tmdpos, i), 16);
		AES_CBC_decrypt_buffer(aes, data + contentpos, size);


		free(aes);

		// Main rom content file
		if (i == 5) {
			mkdir("content5", 0755);
			chdir("content5");
			u8_header header;
			u32 data_offset;
			u8 *string_table;
			size_t rest_size;

			memcpy(&header, data + contentpos, sizeof(header));

			int curpos = contentpos + sizeof(header);

			u8_node root_node;
			memcpy(&root_node, data + curpos, sizeof(u8_node));
			curpos += sizeof(u8_node);

			u32 nodec = be32((u8*)&root_node.size) - 1;

			u8_node *nodes = malloc(sizeof(u8_node)*nodec);
			memcpy(nodes, data + curpos, sizeof(u8_node)*nodec);
			curpos += sizeof(u8_node)*nodec;

			data_offset = be32((u8*)&header.data_offset);
			rest_size = data_offset - sizeof(header) - (nodec + 1) * sizeof(u8_node);
			string_table = malloc(rest_size);
			memcpy(string_table, data + curpos, rest_size);

			u8_node *node;
			for (j = 0; j < nodec; j++) {
				node = &nodes[j];
				u32 doffset = be32((u8*)&node->data_offset);
				u32 dsize = be32((u8*)&node->size);
				u16 name_offset = be16((u8*)&node->name_offset);
				u16 type = be16((u8*)&node->type);
				char *name = (char*)&string_table[name_offset];

				if (type == 0x00) {
					outfile = fopen(name, "wb");
					fwrite(data + contentpos + doffset, 1, dsize, outfile);
					fclose(outfile);
				}
			}
			chdir("..");
			free(string_table);
			free(nodes);
		}

		char *contentname = malloc(100);
		snprintf(contentname, 100, "content%d.app", i);
		outfile = fopen(contentname, "wb");
		fwrite(data + contentpos, 1, getcontentlength(data + tmdpos, i), outfile);
		fclose(outfile);
		free(contentname);
	}
	free(data);

}

void do_pack(const char *outwad, const char *titleid) {
	chdir("wadextract");

	u32 datasize = 0;
	struct stat sbuffer;
	stat("cert.cert", &sbuffer);
	u32 certsize = sbuffer.st_size;
	u32 certpos = 0x40;

	stat("tiket.tik", &sbuffer);
	u32 tiksize = sbuffer.st_size;
	u32 tikpos = certpos + addpadding(certsize, 64);

	stat("metadata.tmd", &sbuffer);
	u32 tmdsize = sbuffer.st_size;
	u32 tmdpos = tikpos + addpadding(tiksize, 64);

	u32 datapos = tmdpos + addpadding(tmdsize, 64);

	FILE *infile = fopen("cert.cert", "rb");
	u8 *cert = malloc(addpadding(certsize, 64));
	fread(cert, 1, certsize, infile);
	fclose(infile);

	infile = fopen("tiket.tik", "rb");
	u8 *tik = malloc(addpadding(tiksize, 64));
	fread(tik, 1, tiksize, infile);
	fclose(infile);

	infile = fopen("metadata.tmd", "rb");
	u8 *tmd = malloc(addpadding(tmdsize, 64));
	fread(tmd, 1, tmdsize, infile);
	fclose(infile);

	u8 *footer = malloc(0x40);
	memset(footer, 0, 0x40);
	footer[0] = 0x47;
	footer[1] = 0x5A;
	time_t curtime = time(NULL);
	memcpy(footer + 2, &curtime, sizeof(time_t));
	u32 footersize = 0x40;

	// Build Content5 into a .app file first
	DIR *dir;
	struct dirent *ent;

	u8 nodec = 0;
	
	chdir("content5");

	if ((dir = opendir(".")) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_type == DT_REG) {
				nodec++;
			}
		}
		closedir(dir);
	}

	u8_node *nodes = malloc(sizeof(u8_node)*nodec);

	u8 *string_table = malloc(nodec * 100 * sizeof(u8)); // Assume max 100 char per filename
	memset(string_table, 0, (nodec * 100 * sizeof(u8)));
	string_table[0] = 0x00;
	string_table[1] = 0x2e;
	string_table[2] = 0x00;
	u16 j = 1;

	// Root Directory node. 
	u8_node *node = &nodes[0];
	node->data_offset = 0x00;
	node->name_offset = 0x0100;
	node->data_offset = 0x00;
	node->size = 0x61000000;
	node->type = 0x0001;

	u16 noff = 3;
	u32 doff = 0;
	if ((dir = opendir(".")) != NULL) {
		/* print all the files and directories within directory */
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_type == DT_REG) {
				
				node = &nodes[j];
				node->type = 0x0000;
				node->name_offset = noff;

				size_t nlen = strlen(ent->d_name) + 1;
				memcpy(string_table + noff, ent->d_name, nlen);
				noff += nlen;

				stat(ent->d_name, &sbuffer);

				node->data_offset = doff;
				node->size = sbuffer.st_size;

				doff += addpadding(sbuffer.st_size, 32);

				j++;
			}
		}
		closedir(dir);
	}
	u16 k;
	u8 prevchar = 1;
	for (k = 0; k < nodec * 100; k++) {
		if (prevchar == 0 && string_table[k] == 0) {
			break;
		}
		prevchar = string_table[k];
	}

	u8 *data = malloc(sizeof(u8) * doff);
	u32 curpos = 0;
	if ((dir = opendir(".")) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_type == DT_REG) {
				stat(ent->d_name, &sbuffer);
				FILE *fle = fopen(ent->d_name, "rb");
				fread(data + curpos, 1, sbuffer.st_size, fle);
				fclose(fle);
				curpos += addpadding(sbuffer.st_size, 32);
			}
		}
		closedir(dir);
	}


	chdir("..");

	u8_node *rootnode = malloc(sizeof(u8_node));
	rootnode->name_offset = 0x00;
	rootnode->data_offset = 0x00;
	rootnode->size = nodec + 2;
	rootnode->type = 0x0001;

	u8_header *header = malloc(sizeof(u8_header));
	header->tag = 0x2D38AA55; // 0x55AA382D 
	header->rootnode_offset = 0x20; // 0x00000020
	header->header_size = k + ((nodec + 2) * sizeof(u8_node));
	header->data_offset = addpadding(header->rootnode_offset + header->header_size, 0x20);
	memset(header->zeroes, 0, 16);

	u32 dataoffset = header->data_offset;
	u16 padcount = header->data_offset - (header->header_size + header->rootnode_offset);
	char *padding = malloc(padcount);
	memset(padding, 0, padcount);

	header->header_size = REVERSEENDIAN32(header->header_size);
	header->data_offset = REVERSEENDIAN32(header->data_offset);
	header->rootnode_offset = REVERSEENDIAN32(header->rootnode_offset);

	rootnode->size = REVERSEENDIAN32(rootnode->size);

	for (j = 1; j <= nodec; j++) {
		node = &nodes[j];
		node->data_offset = REVERSEENDIAN32(node->data_offset + dataoffset);
		node->size = REVERSEENDIAN32(node->size);
		node->name_offset = REVERSEENDIAN16(node->name_offset);
	}

	FILE *foutfile = fopen("content5.app", "wb");

	fwrite(header, 1, sizeof(u8_header), foutfile);
	fwrite(rootnode, 1, sizeof(u8_node), foutfile);
	fwrite(nodes, 1, sizeof(u8_node) * (nodec + 1), foutfile);
	fwrite(string_table, 1, k, foutfile);
	fwrite(padding, 1, padcount, foutfile);
	fwrite(data, 1, doff, foutfile);
	fclose(foutfile);


	u16 contentsc = be16(tmd + 0x1DE);
	int i;
	
	u32 paddedsize = 0;
	char *cfname = malloc(16);
	for (i = 0; i < contentsc; i++) {
		snprintf(cfname, 16, "content%d.app", i);
		stat(cfname, &sbuffer);
		datasize += addpadding(sbuffer.st_size, 64);
		paddedsize += addpadding(sbuffer.st_size, 64);
		u32 size = REVERSEENDIAN32(sbuffer.st_size);
		memcpy(tmd + 0x1f0 + (36 * i), &size, 4);
	};

	u8 *contents = malloc(paddedsize);
	memset(contents, 0, paddedsize);
	u32 dpos = 0;


	// Change Title ID
	if (titleid != NULL) {
		memcpy(tik + 0x1e0, titleid, 4);
		memcpy(tmd + 0x190, titleid, 4);
	}

	// Region Free
	tmd[0x19d] = 0x03;

	// New key
	memcpy(tik + 0x1bf, &newkey, 16);

	//Decrypt the new key
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

	for (j = 2; j < 15; j++) {
		iv[j] = 0x00;
	}

	for (i = 0; i < contentsc; i++) {

		u32 contentpos = 0;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(tmd, j), 64);
		}

		u32 size = addpadding(getcontentlength(tmd, i), 16);

		snprintf(cfname, 16, "content%d.app", i);
		FILE *cfile = fopen(cfname, "rb");
		fread(contents + contentpos, 1, size, cfile);
		fclose(cfile);

		if (i == 1) {
			// Memory fix 
			contents[contentpos + 0x2EB0] = 0x60;
			contents[contentpos + 0x2EB1] = 0x00;
			contents[contentpos + 0x2EB3] = 0x00;

			// Mapping fix
			// DUP
			contents[contentpos + 0x16BAF0] = 0x08;
			contents[contentpos + 0x16BAF1] = 0x00;

			// DDown
			contents[contentpos + 0x16BAF4] = 0x04;
			contents[contentpos + 0x16BAF5] = 0x00;

			// DLEFT
			contents[contentpos + 0x16BAF8] = 0x02;
			contents[contentpos + 0x16BAF9] = 0x00;

			// DRIGHT
			contents[contentpos + 0x16BAFC] = 0x01;
			contents[contentpos + 0x16BAFD] = 0x00;

			// CStick Down -> L
			contents[contentpos + 0x16BB05] = 0x20;
		}

		iv[0] = tmd[0x1e8 + (0x24 * i)];
		iv[1] = tmd[0x1e9 + (0x24 * i)];



		// Generate a SHA signature incase any files are changes 1 and 5 will most likely be the only one changed. 
		char digest[20];
		SHA1_CTX *sha1 = malloc(sizeof(SHA1_CTX));
		SHA1Init(sha1);
		SHA1Update(sha1, contents + contentpos, getcontentlength(tmd, i));
		SHA1Final(digest, sha1);


		memcpy(tmd + 0x1f4 + (36 * i), &digest, 20);
		free(sha1);


		aes = malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, newenc, iv);



		AES_CBC_encrypt_buffer(aes, contents + contentpos, size);
		free(aes);

	}
	free(cfname);

	chdir("..");

	FILE *outwadfile = fopen(outwad, "wb");
	char wadheader[8] = {
		0x00, 0x00, 0x00, 0x20, 0x49, 0x73, 0x00, 0x00
	};
	char zeroes[4];
	memset(&zeroes, 0, 4);

	u32 certsizer = REVERSEENDIAN32(certsize);
	u32 tiksizer = REVERSEENDIAN32(tiksize);
	u32 tmdsizer = REVERSEENDIAN32(tmdsize);
	u32 datasizer = REVERSEENDIAN32(datasize);
	u32 footersizer = REVERSEENDIAN32(footersize);

	fwrite(&wadheader, 1, 8, outwadfile);
	fwrite(&certsizer, 1, 4, outwadfile);
	fwrite(&zeroes, 1, 4, outwadfile);
	fwrite(&tiksizer, 1, 4, outwadfile);
	fwrite(&tmdsizer, 1, 4, outwadfile);
	fwrite(&datasizer, 1, 4, outwadfile);
	fwrite(&footersizer, 1, 4, outwadfile);

	char headerpadding[32];
	memset(&headerpadding, 0, 32);
	fwrite(&headerpadding, 1, 32, outwadfile);

	fwrite(cert, 1, addpadding(certsize, 64), outwadfile);
	fwrite(tik, 1, addpadding(tiksize, 64), outwadfile);
	fwrite(tmd, 1, addpadding(tmdsize, 64), outwadfile);
	fwrite(contents, 1, addpadding(datasize, 64), outwadfile);
	fwrite(footer, 1, 0x40, outwadfile);
	fclose(outwadfile);

	
	free(cert);
	free(tik);
	free(tmd);
	free(contents);
	free(footer);

}

void genkey() {
	printf("Enter 45e and press enter: ");
	char *line = malloc(4);
	fgets(line, 4, stdin);

	char outkey[16] = { 0x26 ,0xC2 ,0x12 ,0xB3 ,0x60 ,0xDD ,0x2E ,0x04 ,0xCF ,0x9C ,0x12 ,0x51 ,0xAF ,0x99 ,0x88 ,0xE4 };

	char iv[16];
	iv[0] = line[0];
	iv[1] = line[1];
	iv[2] = line[2];

	int i;
	for (i = 3; i < 16; i++) iv[i] = 0x00;

	struct AES_ctx *aes = malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, newkey, iv);
	AES_CBC_decrypt_buffer(aes, outkey, 16);

	free(line);
	free(aes);

	FILE *keyf = fopen("common-key.bin", "wb");
	fwrite(&outkey, 1, 16, keyf);
	fclose(keyf);

	printf("common-key.bin successfully generated!\r\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		
		print_usage();
		exit(0);
	}

	if (strcmp(argv[1],"genkey")==0) {
		
		genkey();
		return 0;
	}

	if (argc < 3) {
		
		print_usage();
		exit(0);
	}

	if (strcmp(argv[1],"extract")==0 && strcmp(argv[1],"pack")==0) {

		print_usage();
		exit(0);
	}

	struct stat sbuffer;
	char *keyfile;
	if (stat("key.bin", &sbuffer) == 0) {
		keyfile = "key.bin";
	}
	else if (stat("common-key.bin", &sbuffer) == 0) {
		keyfile = "common-key.bin";
	}
	else {
		printf("Cannot find key.bin or common-key.bin.");
		exit(1);
	}

	FILE *fkeyfile = fopen(keyfile, "rb");
	fread(&key, 1, 16, fkeyfile);
	fclose(fkeyfile);


	if (strcmp(argv[1],"extract")==0) {
		do_extract(argv[2]);
	}
	else if (strcmp(argv[1],"pack")==0) {
		if (argc < 4)
			do_pack(argv[2],NULL);
		else
			do_pack(argv[2], argv[3]);
	}



	return 0;
}