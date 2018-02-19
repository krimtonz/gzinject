#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include "gzinject.h"
#include "aes.h"
#include "sha1.h"
#include "md5.h"

#if _WIN32
#define mkdir(X,Y) mkdir(X)
#define getcwd(X,Y) _getcwd(X,Y);
#endif

unsigned char key[16];
u8 region = 0x03;
int verbose = 0;
char *wad = NULL, *directory = NULL, *keyfile = NULL,
	*workingdirectory = NULL;

static struct option cmdoptions[] = {
	{ "action",required_argument,0,'a' },
{ "wad",required_argument,0,'w' },
{ "channelid",required_argument,0,'i' },
{ "channeltitle",required_argument,0,'t' },
{ "help",no_argument,0,'?' },
{ "key",required_argument,0,'k' },
{ "region",required_argument,0,'r' },
{ "verbose",no_argument,&verbose,1 },
{ "directory",required_argument,0,'d' }
};

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
	char *usage = "Usage: gzinject -a,--action=(genkey | extract | pack) [options]\r\n  options:\r\n    -a, --action(genkey | extract | pack)\tDefines the action to run\r\n      genkey : generates a common key\r\n      extract : extracts contents of wadfile specified by --wad to --directory\r\n      pack : packs contents --directory  into wad specified by --wad\r\n    -w, --wad wadfile\t\t\t\tDefines the wadfile to use Input wad for extracting, output wad for packing\r\n    -d, --directory directory\t\t\tDefines the output directory for extract operations, or the input directory for pack operations\r\n    -i, --channelid channelid\t\t\tChanges the channel id during packing(4 characters)\r\n    -t, --channeltitle channeltitle\t\tChanges the channel title during packing(max 20 characters)\r\n    -r, --region[0 - 3]\t\t\t\tChanges the WAD region during packing 0 = JP, 1 = US, 2 = Europe, 3 = FREE\r\n    -k, --key keyfile\t\t\t\tUses the specified common key file\r\n    -v, --verbose\t\t\t\tPrints verbose information\r\n    -? , --help\t\t\t\t\tPrints this help message";
	printf("%s\r\n", usage);
}

void do_extract() {
	struct stat sbuffer;
	if (stat(wad, &sbuffer) != 0) {
		printf("Could not open %s\r\n", wad);
		exit(1);
	}

	if (verbose == 1) {
		printf("Extracting %s to %s\r\n", wad, directory);
	}
	mkdir(directory, 0755);
	FILE *wadfile = fopen(wad, "rb");
	fseek(wadfile, 0, SEEK_END);
	size_t wadsize = ftell(wadfile);
	fseek(wadfile, 0, SEEK_SET);
	u8 *data = (u8*)malloc(wadsize);
	fread(data, 1, wadsize, wadfile);
	fclose(wadfile);
	chdir(directory);

	u32 certsize = be32(data + 0x08);
	u32 tiksize = be32(data + 0x10);
	u32 tmdsize = be32(data + 0x14);

	u32 certpos = 0x40;
	u32 tikpos = 0x40 + addpadding(certsize, 64);
	u32 tmdpos = tikpos + addpadding(tiksize, 64);
	u32 datapos = tmdpos + addpadding(tmdsize, 64);

	u16 contentcount = be16(data + tmdpos + 0x1de);

	if (verbose == 1) {
		printf("Writing cert.cert.\r\n");
	}
	FILE* outfile = fopen("cert.cert", "wb");
	fwrite(data + certpos, 1, certsize, outfile);
	fclose(outfile);

	if (verbose == 1) {
		printf("Writing ticket.tik.\r\n");
	}
	outfile = fopen("ticket.tik", "wb");
	fwrite(data + tikpos, 1, tiksize, outfile);
	fclose(outfile);

	if (verbose == 1) {
		printf("Writing metadata.tmd.\r\n");
	}
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

		if (verbose == 1) {
			printf("Decrypting contents %d.\r\n", i);
		}

		u32 size = addpadding(getcontentlength(data + tmdpos, i), 16);
		AES_CBC_decrypt_buffer(aes, data + contentpos, size);


		free(aes);

		// Main rom content file
		if (i == 5) {
			if (verbose == 1) {
				printf("Extracting content 5 U8 Archive.\r\n");
			}
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
					if (verbose == 1) {
						printf("Extracting and writing content5/%s.\r\n", name);
					}
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
		if (verbose == 1) {
			printf("Writing %s.\r\n", contentname);
		}
		outfile = fopen(contentname, "wb");
		fwrite(data + contentpos, 1, getcontentlength(data + tmdpos, i), outfile);
		fclose(outfile);
		free(contentname);
	}
	free(data);

}

void do_pack(const char *titleid, const char *channelname) {

	DIR *testdir = opendir(directory);
	if (testdir) {
		closedir(testdir);
	}
	else {
		printf("%s doesn't exit, or is not a directory!\r\n", directory);
		exit(1);
	}

	if (verbose == 1) {
		printf("Packing %s into %s", directory, wad);
		if (titleid != NULL) printf(", changing Channel ID to %s", titleid);
		if (channelname != NULL) printf(", changing Channel Name to %s", channelname);
		printf("\r\n");
	}
	chdir(directory);

	if (verbose == 1) {
		printf("Gathering WAD Header Information\r\n");
	}
	u32 datasize = 0;
	struct stat sbuffer;
	stat("cert.cert", &sbuffer);
	u32 certsize = sbuffer.st_size;

	stat("ticket.tik", &sbuffer);
	u32 tiksize = sbuffer.st_size;

	stat("metadata.tmd", &sbuffer);
	u32 tmdsize = sbuffer.st_size;

	if (verbose == 1) {
		printf("Reading cert.cert\r\n");
	}
	FILE *infile = fopen("cert.cert", "rb");
	u8 *cert = malloc(addpadding(certsize, 64));
	fread(cert, 1, certsize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Reading ticket.cert\r\n");
	}
	infile = fopen("ticket.tik", "rb");
	u8 *tik = malloc(addpadding(tiksize, 64));
	fread(tik, 1, tiksize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Reading metadata.tmd\r\n");
	}
	infile = fopen("metadata.tmd", "rb");
	u8 *tmd = malloc(addpadding(tmdsize, 64));
	fread(tmd, 1, tmdsize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Generating Fooder signature\r\n");
	}
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
	if (verbose == 1) {
		printf("Generating content5 U8 Archive information\r\n");
	}
	if ((dir = opendir(".")) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			stat(ent->d_name, &sbuffer);
			if ((sbuffer.st_mode & S_IFMT) == S_IFREG) {
				nodec++;
			}
		}
		closedir(dir);
	}

	u8_node *nodes = malloc(sizeof(u8_node)* (nodec + 1));

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
			stat(ent->d_name, &sbuffer);
			if ((sbuffer.st_mode & S_IFMT) == S_IFREG) {

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

	if (verbose == 1) {
		printf("Reading U8 Archive Files\r\n");
	}
	if ((dir = opendir(".")) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			stat(ent->d_name, &sbuffer);
			if ((sbuffer.st_mode & S_IFMT) == S_IFREG) {
				if (verbose == 1) {
					printf("Reading wadextract/content5/%s\r\n", ent->d_name);
				}
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

	if (verbose == 1) {
		printf("Exporting new U8 Archive to content5.app\r\n");
	}
	
	
	
	u8_header header;
	header.tag = 0x2D38AA55; // 0x55AA382D 
	header.rootnode_offset = 0x20; // 0x00000020
	header.header_size = k + ((nodec + 2) * sizeof(u8_node));
	header.data_offset = addpadding(header.rootnode_offset + header.header_size, 0x20);
	memset(header.zeroes, 0, 16);

	u32 dataoffset = header.data_offset;
	u16 padcount = header.data_offset - (header.header_size + header.rootnode_offset);
	
	
	FILE *foutfile = fopen("content5.app", "wb");

	header.header_size = REVERSEENDIAN32(header.header_size);
	header.data_offset = REVERSEENDIAN32(header.data_offset);
	header.rootnode_offset = REVERSEENDIAN32(header.rootnode_offset);
	fwrite(&header, 1, sizeof(u8_header), foutfile);

	u8_node rootnode;
	rootnode.name_offset = 0x00;
	rootnode.data_offset = 0x00;
	rootnode.size = nodec + 2;
	rootnode.type = 0x0001;
	rootnode.size = REVERSEENDIAN32(rootnode.size);
	fwrite(&rootnode, 1, sizeof(u8_node), foutfile);

	for (j = 1; j <= nodec; j++) {
		node = &nodes[j];
		node->data_offset = REVERSEENDIAN32(node->data_offset + dataoffset);
		node->size = REVERSEENDIAN32(node->size);
		node->name_offset = REVERSEENDIAN16(node->name_offset);
	}
	fwrite(nodes, 1, sizeof(u8_node) * (nodec + 1), foutfile);
	free(nodes);
	
	fwrite(string_table, 1, k, foutfile);
	free(string_table);

	u8 *padding = calloc(padcount, sizeof(u8));
	fwrite(padding, 1, padcount, foutfile);
	free(padding);

	fwrite(data, 1, doff, foutfile);
	free(data);

	fclose(foutfile);

	if (verbose == 1) {
		printf("Modifying content metadata in the TMD\r\n");
	}
	u16 contentsc = be16(tmd + 0x1DE);
	int i;

	u32 paddedsize = 0;
	char *cfname = malloc(20);
	for (i = 0; i < contentsc; i++) {
		snprintf(cfname, 20, "content%d.app", i);
		stat(cfname, &sbuffer);
		datasize += addpadding(sbuffer.st_size, 64);
		paddedsize += addpadding(sbuffer.st_size, 64);
		u32 size = REVERSEENDIAN32(sbuffer.st_size);
		memcpy(tmd + 0x1f0 + (36 * i), &size, 4);
	};

	u8 *contents = calloc(paddedsize, sizeof(u8));

	// Change Title ID
	if (titleid != NULL) {
		if (verbose == 1) {
			printf("Changing Channel ID\r\n");
		}
		memcpy(tik + 0x1e0, titleid, 4);
		memcpy(tmd + 0x190, titleid, 4);
	}

	if (verbose == 1) {
		printf("Changing region in the TMD\r\n");
	}
	// Change the Region
	tmd[0x19d] = region;

	if (verbose == 1) {
		printf("Changing encryption key in the ticket\r\n");
	}
	// New key
	memcpy(tik + 0x1bf, &newkey, 16);

	//Decrypt the new key
	u8 newenc[16];
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

		snprintf(cfname, 20, "content%d.app", i);
		FILE *cfile = fopen(cfname, "rb");
		fread(contents + contentpos, 1, size, cfile);
		fclose(cfile);

		if (i == 0) {
			if (channelname != NULL) {
				if (verbose == 1) {
					printf("Changing the Channel Name in content0.app\r\n");
				}

				u16 imetpos = 0;
				for (j = 0; j < 400; j++) {
					if (contents[contentpos + j] == 0x49 && contents[contentpos + 1 + j] == 0x4D && contents[contentpos + 2 + j] == 0x45 && contents[contentpos + 3 + j] == 0x54) {
						imetpos = j;
						break;
					}
				}
				u16 count = 0;
				size_t cnamelen = strlen(channelname);
				for (j = imetpos; j < imetpos + 40; j += 2) {


					if (count < cnamelen) {
						contents[contentpos + j + 29] = channelname[count];
						contents[contentpos + j + 113] = channelname[count];
						contents[contentpos + j + 197] = channelname[count];
						contents[contentpos + j + 281] = channelname[count];
						contents[contentpos + j + 365] = channelname[count];
						contents[contentpos + j + 449] = channelname[count];
						contents[contentpos + j + 533] = channelname[count];
						contents[contentpos + j + 785] = channelname[count];

					}
					else {
						contents[contentpos + j + 29] = 0x00;
						contents[contentpos + j + 113] = 0x00;
						contents[contentpos + j + 197] = 0x00;
						contents[contentpos + j + 281] = 0x00;
						contents[contentpos + j + 365] = 0x00;
						contents[contentpos + j + 449] = 0x00;
						contents[contentpos + j + 533] = 0x00;
						contents[contentpos + j + 785] = 0x00;
					}

					contents[contentpos + j + 28] = 0x00;
					contents[contentpos + j + 112] = 0x00;
					contents[contentpos + j + 196] = 0x00;
					contents[contentpos + j + 280] = 0x00;
					contents[contentpos + j + 364] = 0x00;
					contents[contentpos + j + 448] = 0x00;
					contents[contentpos + j + 532] = 0x00;
					contents[contentpos + j + 784] = 0x00;

					count++;
				}
			}

			if (verbose == 1) {
				printf("Signing the new Channel Name\r\n");
			}

			memset(&contents[contentpos + 0x630], 0x00, 0x10);

			MD5_CTX *md5 = malloc(sizeof(MD5_CTX));
			u8 md5digest[16];
			MD5_Init(md5);
			MD5_Update(md5, contents + contentpos + 64, 1536);
			MD5_Final(md5digest, md5);
			for (j = 0; j < 16; j++) {
				contents[contentpos + 0x630 + j] = md5digest[j];
			}
			free(md5);
		}

		if (i == 1) {
			if (verbose == 1) {
				printf("Applying GZ Fixes\r\n\tMemory\r\n");
			}


			// Memory fix 
			contents[contentpos + 0x2EB0] = 0x60;
			contents[contentpos + 0x2EB1] = 0x00;
			contents[contentpos + 0x2EB3] = 0x00;

			if (verbose == 1) {
				printf("\tController D-Pad Up\r\n");
			}
			// Mapping fix
			// DUP
			contents[contentpos + 0x16BAF0] = 0x08;
			contents[contentpos + 0x16BAF1] = 0x00;

			if (verbose == 1) {
				printf("\tController D-Pad Down\r\n");
			}
			// DDown
			contents[contentpos + 0x16BAF4] = 0x04;
			contents[contentpos + 0x16BAF5] = 0x00;
			if (verbose == 1) {
				printf("\tController D-Pad Left\r\n");
			}
			// DLEFT
			contents[contentpos + 0x16BAF8] = 0x02;
			contents[contentpos + 0x16BAF9] = 0x00;
			if (verbose == 1) {
				printf("\tController D-Pad Right\r\n");
			}
			// DRIGHT
			contents[contentpos + 0x16BAFC] = 0x01;
			contents[contentpos + 0x16BAFD] = 0x00;
			if (verbose == 1) {
				printf("\tController C-Stick-Down to L\r\n");
			}
			// CStick Down -> L
			contents[contentpos + 0x16BB05] = 0x20;
		}

		iv[0] = tmd[0x1e8 + (0x24 * i)];
		iv[1] = tmd[0x1e9 + (0x24 * i)];


		if (verbose == 1) {
			printf("Generating signature for the content %d, and copying signature to the TMD\r\n", i);
		}
		// Generate a SHA signature incase any files are changes 1 and 5 will most likely be the only one changed. 
		u8 digest[20];
		SHA1_CTX *sha1 = malloc(sizeof(SHA1_CTX));
		SHA1Init(sha1);
		SHA1Update(sha1, contents + contentpos, getcontentlength(tmd, i));
		SHA1Final(digest, sha1);


		memcpy(tmd + 0x1f4 + (36 * i), &digest, 20);
		free(sha1);

		if (verbose == 1) {
			printf("Encrypting content %d\r\n", i);
		}
		aes = malloc(sizeof(struct AES_ctx));
		AES_init_ctx_iv(aes, newenc, iv);



		AES_CBC_encrypt_buffer(aes, contents + contentpos, size);
		free(aes);

	}
	free(cfname);

	chdir(workingdirectory);

	if (verbose == 1) {
		printf("Generating WAD Header, and flipping endianness\r\n");
	}

	FILE *outwadfile = fopen(wad, "wb");
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

	if (verbose == 1) {
		printf("Writing certificate\r\n");
	}
	fwrite(cert, 1, addpadding(certsize, 64), outwadfile);
	if (verbose == 1) {
		printf("Writing ticket\r\n");
	}
	fwrite(tik, 1, addpadding(tiksize, 64), outwadfile);
	if (verbose == 1) {
		printf("Writing medatadata\r\n");
	}
	fwrite(tmd, 1, addpadding(tmdsize, 64), outwadfile);
	if (verbose == 1) {
		printf("Writing data\r\n");
	}
	fwrite(contents, 1, addpadding(datasize, 64), outwadfile);
	if (verbose == 1) {
		printf("Writing footer\r\n");
	}
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

	u8 outkey[16] = { 0x26 ,0xC2 ,0x12 ,0xB3 ,0x60 ,0xDD ,0x2E ,0x04 ,0xCF ,0x9C ,0x12 ,0x51 ,0xAF ,0x99 ,0x88 ,0xE4 };

	u8 iv[16];
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
	if (keyfile == NULL)  keyfile = "common-key.bin";
	FILE *keyf = fopen(keyfile, "wb");
	fwrite(&outkey, 1, 16, keyf);
	fclose(keyf);

	printf("%s successfully generated!\r\n",keyfile);
}

int main(int argc, char **argv) {
	int opt;

	char *action = NULL,
		*channelid = NULL,
		*channeltitle = NULL;

	while (1) {
		int oi = 0;

		opt = getopt_long(argc, argv, "a:w:i:t:?k:r:d:", cmdoptions, &oi);
		if (opt == -1) break;
		switch (opt) {
		case 'a':
			action = optarg;
			break;
		case 'w':
			wad = optarg;
			break;
		case 'i':
			channelid = optarg;
			break;
		case 't':
			channeltitle = optarg;
			break;
		case '?':
			print_usage();
			exit(0);
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'r':
			if (optarg[0] == '0') region = 0;
			else if (optarg[0] == '1') region = 1;
			else if (optarg[0] == '2') region = 2;
			else region = 3;
			break;
		case 'd':
			directory = optarg;
			break;
		default:
			break;
		}

	}

	if (action == NULL) {
		print_usage();
		exit(1);
	}

	if (strcmp(action, "genkey") == 0) {

		genkey();
		return 0;
	}

	if (strcmp(action, "extract") != 0 && strcmp(action, "pack") != 0) {

		print_usage();
		exit(0);
	}


	if (wad == NULL) {
		print_usage();
		exit(1);
	}

	if (directory == NULL) directory = "wadextract";

	struct stat sbuffer;
	if (keyfile == NULL) {
		if (stat("key.bin", &sbuffer) == 0) {
			keyfile = "key.bin";
		}
		else if (stat("common-key.bin", &sbuffer) == 0) {
			keyfile = "common-key.bin";
		}
		else {
			printf("Cannot find key.bin or common-key.bin.\r\n");
			exit(1);
		}
	}
	else {
		if (stat(keyfile, &sbuffer) != 0) {
			printf("Cannot find keyfile specified.\r\n");
			exit(1);
		}
	}

	FILE *fkeyfile = fopen(keyfile, "rb");
	fread(&key, 1, 16, fkeyfile);
	fclose(fkeyfile);

	workingdirectory = malloc(200);
	workingdirectory = getcwd(workingdirectory, 200);

	if (strcmp(action, "extract") == 0) {
		do_extract();
	}
	else if (strcmp(action, "pack") == 0) {
		do_pack(channelid, channeltitle);
	}

	free(workingdirectory);


	return 0;
}
