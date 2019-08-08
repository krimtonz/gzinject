#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include "gzinject.h"
#ifdef _USE_LIBCRYPTO
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
#include "aes.h"
#include "sha1.h"
#include "md5.h"
#endif
#include "lz77.h"
#include "u8.h"
#include "gzi.h"

#if _WIN32
#define mkdir(X,Y) mkdir(X)
#define getcwd(X,Y) _getcwd(X,Y)
#endif

unsigned char key[16];
u8 region = 0x03;

int cleanup = 0, verbose = 0, raphnet = 0,
	remap_cstick_down = 1, remap_dpad_up = 1, remap_dpad_down = 1, remap_dpad_right = 1, remap_dpad_left = 1;
char *wad = NULL, *directory = NULL, *keyfile = NULL,
	*workingdirectory = NULL, *rom = NULL, *outwad = NULL, *patch = NULL;

static struct option cmdoptions[] = {
	{ "action",required_argument,0,'a' },
	{ "wad",required_argument,0,'w' },
	{ "channelid",required_argument,0,'i' },
	{ "channeltitle",required_argument,0,'t' },
	{ "help",no_argument,0,'h' },
	{ "key",required_argument,0,'k' },
	{ "region",required_argument,0,'r' },
	{ "verbose",no_argument,&verbose,1 },
	{ "directory",required_argument,0,'d' },
	{ "cleanup", no_argument,&cleanup,1},
	{"version",no_argument,0,'v'},
	{"raphnet",no_argument,&raphnet,1},
	{"disable-controller-remappings",no_argument,0,'z'},
	{ "disable-cstick-d-remapping",no_argument,&remap_cstick_down,0},
	{"disable-dpad-u-remapping",no_argument,&remap_dpad_up,0},
	{ "disable-dpad-d-remapping",no_argument,&remap_dpad_down,0},
	{ "disable-dpad-r-remapping",no_argument,&remap_dpad_right,0},
	{ "disable-dpad-l-remapping",no_argument,&remap_dpad_left,0},
	{"rom",required_argument,0,'m'},
	{"outputwad",required_argument,0,'o'},
    {"patch-file",required_argument,0,'p'},
	{0,0,0,0}
};

unsigned char newkey[16] = {
	0x47, 0x5a, 0x49, 0x73, 0x4c, 0x69, 0x66, 0x65, 0x41, 0x6e, 0x64, 0x42, 0x65, 0x65, 0x72, 0x21
};

#ifdef _USE_LIBCRYPTO
inline void do_encrypt(u8 *input, size_t size, u8 *key, u8* iv) {
	u8 *encrypted = malloc(size * 2);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(ctx, encrypted, &len, input, size);
	EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	memcpy(input, encrypted, size);
	free(encrypted);
}

inline void do_decrypt(u8 *input, size_t size, u8 *key, u8* iv) {
	u8 *decrypted = malloc(size);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;
	EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, decrypted, &len, input, size);
	EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	memcpy(input, decrypted, size);
	free(decrypted);
}

inline void do_sha1(u8 *input, u8 *output, size_t size) {
	SHA1(input, size, output);
}

inline void do_md5(u8 *input, u8 *output, size_t size) {
	MD5(input, size, output);
}
#else

 void do_encrypt(u8 *input, size_t size, u8 *key, u8* iv) {
	struct AES_ctx *aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_encrypt_buffer(aes, input, size);
	free(aes);
}

 void do_decrypt(u8 *input, size_t size, u8 *key, u8* iv) {
	struct AES_ctx *aes = (struct AES_ctx*)malloc(sizeof(struct AES_ctx));
	AES_init_ctx_iv(aes, key, iv);
	AES_CBC_decrypt_buffer(aes, input, size);
	free(aes);
}

 void do_sha1(u8 *input, u8 *output, size_t size) {
	SHA1_CTX *sha1 = malloc(sizeof(SHA1_CTX));
	SHA1Init(sha1);
	SHA1Update(sha1, input, size);
	SHA1Final(output, sha1);
	free(sha1);
}

 void do_md5(u8 *input, u8 *output, size_t size) {
	MD5_CTX *md5 = malloc(sizeof(MD5_CTX));
	MD5_Init(md5);
	MD5_Update(md5, input, size);
	MD5_Final(output, md5);
	free(md5);
}
#endif

int main(int argc, char **argv) {

	setbuf(stdout, NULL);

	int opt;

	char *action = NULL,
		*channelid = NULL,
		*channeltitle = NULL;

	while (1) {
		int oi = 0;

		opt = getopt_long(argc, argv, "a:w:i:t:?k:r:d:vm:o:p:", cmdoptions, &oi);
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
		case 'h':
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
		case 'v':
			print_version(argv[0]);
			exit(0);
			break;
		case 'm':
			rom = optarg;
			break;
		case 'o':
			outwad = optarg;
			break;
		case 'z':
			remap_cstick_down = 0;
			remap_dpad_down = 0;
			remap_dpad_left = 0;
			remap_dpad_right = 0;
			remap_dpad_up = 0;
			break;
        case 'p':
            patch = optarg;
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

	if (strcmp(action, "extract") != 0 && strcmp(action, "pack") != 0 && strcmp(action, "inject") != 0) {

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
	else if (strcmp(action, "inject") == 0) {
		if (rom == NULL) {
			printf("-a inject specified, but no rom to inject!\n");
			free(workingdirectory);
			exit(1);

		}
		do_extract();

		if (verbose == 1) {
			printf("Copying %s to %s/content5/rom\r\n", rom, directory);
		}
		FILE *from = fopen(rom, "rb");
		fseek(from, 0, SEEK_END);
		size_t fromlen = ftell(from);
		fseek(from, 0, SEEK_SET);
		u8 *inrom = malloc(fromlen);
		fread(inrom, 1, fromlen, from);
		fclose(from);

		char *orom = malloc(200);
		snprintf(orom, 200, "%s/content5/rom", directory);
		from = fopen(orom, "wb");
		fwrite(inrom, 1, fromlen, from);
		fclose(from);
		free(inrom);
		free(orom);


		char *wadname = removeext(wad),
			*outname = malloc(strlen(wadname) + 12);

		sprintf(outname, "%s-inject.wad", wadname);
		free(wadname);
		if (outwad == NULL) {
			wad = outname;
		}
		else {
			wad = outwad;
		}

		do_pack(channelid, channeltitle);
		free(outname);
	}

	free(workingdirectory);


	return 0;
}

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

void setcontentlength(u8 *tmd, unsigned int contentnum, unsigned int size){
    u32 off = 0x1ec + (36 * contentnum);
	*((uint32_t*)tmd + off) = REVERSEENDIAN32(size);
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
	char *usage = "Usage: gzinject -a,--action=(genkey | extract | pack | inject) [options]\r\n  options:\r\n    -a, --action(genkey | extract | pack | inject)\tDefines the action to run\r\n      genkey : generates a common key\r\n      extract : extracts contents of wadfile specified by --wad to --directory\r\n      pack : packs contents --directory  into wad specified by --wad\r\n      inject: does the extract and pack operations in one pass, requires the --rom option for the rom to inject, wad will be created as wadfile-inject.wad\r\n    -w, --wad wadfile\t\t\t\tDefines the wadfile to use Input wad for extracting, output wad for packing\r\n    -d, --directory directory\t\t\tDefines the output directory for extract operations, or the input directory for pack operations\r\n    -m, --rom rom\t\t\t\tDefines the rom to inject using -a inject\r\n    -o, --outputwad wad\t\t\t\tDefines the filename to output to when using -a inject\r\n    -i, --channelid channelid\t\t\tChanges the channel id during packing(4 characters)\r\n    -t, --channeltitle channeltitle\t\tChanges the channel title during packing(max 20 characters)\r\n    -r, --region[0 - 3]\t\t\t\tChanges the WAD region during packing 0 = JP, 1 = US, 2 = Europe, 3 = FREE\r\n    --raphnet\t\t\t\t\tMaps L to Z for raphnet adapters\r\n    --disable-controller-remappings\t\tDisables all controller remappings during packing\r\n    --disable-cstick-d-remapping\t\tDisables c-stick down remapping\r\n    --disable-dpad-d-remapping\t\t\tDisables dpad-down remapping\r\n    --disable-dpad-u-remapping\t\t\tDisables dpad-up remapping\r\n    --disable-dpad-l-remapping\t\t\tDisables dpad-left remapping\r\n    --disable-dpad-r-remapping\t\t\tDisables dpad-right remapping\r\n    -k, --key keyfile\t\t\t\tUses the specified common key file\r\n    --cleanup\t\t\t\t\tCleans up the wad directory before extracting or after packing\r\n    -v, --verbose\t\t\t\tPrints verbose information\r\n    -v , --version\t\t\t\tPrints Version information\r\n    -? , --help\t\t\t\t\tPrints this help message";
	printf("%s\r\n", usage);
}

void print_version(const char* prog) {
	printf("%s Version ", prog);
	printf(GZINJECT_VERSION);
	printf("\r\n");
}

void truchasign(u8 *data, u8 type, size_t len) {
	u16 pos = 0x1f2;
	if (type == W_TMD) {
		pos = 0x1d4;
	}

	u8 digest[20];
	do_sha1(data + pos + 0x140, digest, len - 0x140);

	u16 i;
	if (digest[0] != 0x00) {
		for (i = 4; i < 260; i++) {
			data[i] = 0x00;
		}
		for (i = 0; i < 0xFFFF; i++) {
			u16 revi = REVERSEENDIAN16(i);
			memcpy(data + pos, &revi, 2);

			do_sha1(data + pos + 0x140, digest, len - 0x140);

			if (digest[0] == 0x00) {
				break;
			}
		}
	}
}

void removefile(const char* file) {
	struct stat sbuffer;
	if (stat(file, &sbuffer) == 0) {
		if ((sbuffer.st_mode & S_IFMT) == S_IFDIR) {
			removedir(file);
		}
		else if ((sbuffer.st_mode & S_IFMT) == S_IFREG) {
			if (verbose == 1) {
				printf("Removing %s\r\n", file);
			}
			remove(file);
		}

	}
}

void removedir(const char *file) {
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir(file)) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;
			char *path = malloc(1000);
			snprintf(path, 1000, "%s/%s", file, ent->d_name);
			removefile(path);
			free(path);
		}
		if (verbose == 1) {
			printf("Removing %s\r\n", file);
		}
		rmdir(file);
	}

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

	FILE *wadfile = fopen(wad, "rb");
	fseek(wadfile, 0, SEEK_END);
	size_t wadsize = ftell(wadfile);
	fseek(wadfile, 0, SEEK_SET);
	u8 *data = (u8*)malloc(wadsize);
	fread(data, 1, wadsize, wadfile);
	fclose(wadfile);
	if (be32(&data[3]) != 0x20497300) {
		printf("%s does not appear to be a valid WAD, would you like to continue? (y/n) ", wad);
		char ans;
		scanf("%c", &ans);
		while (ans != 'y' && ans != 'n') {
			printf("\r\n %s does not appear to be a valid WAD, would you like to continue? (y/n) ", wad);
			scanf("%c", &ans);
		}
		printf("\r\n");
		if (ans == 'n') {
			free(data);
			return;
		}
	}

	u32 certsize = be32(data + 0x08);
	u32 tiksize = be32(data + 0x10);
	u32 tmdsize = be32(data + 0x14);

	u32 certpos = 0x40;
	u32 tikpos = 0x40 + addpadding(certsize, 64);
	u32 tmdpos = tikpos + addpadding(tiksize, 64);
	u32 datapos = tmdpos + addpadding(tmdsize, 64);

	if (cleanup == 1) removedir(directory);

	mkdir(directory, 0755);
	chdir(directory);

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
	;
	do_decrypt(encryptedkey, 16, key, iv);

	for (j = 2; j < 16; j++) iv[j] = 0x00;

	for (i = 0; i < contentcount; i++) {
		u32 contentpos = datapos;
		for (j = 0; j < i; j++) {
			contentpos = contentpos + addpadding(getcontentlength(data + tmdpos, j), 64);
		}

		iv[0] = data[tmdpos + 0x1e8 + (0x24 * i)];
		iv[1] = data[tmdpos + 0x1e9 + (0x24 * i)];

		u32 size = addpadding(getcontentlength(data + tmdpos, i), 16);

		if (verbose == 1) {
			printf("Decrypting contents %d.\r\n", i);
		}

		do_decrypt(data + contentpos, size, encryptedkey, iv);

		// Main rom content file
		if (i == 5) {
			if (verbose == 1) {
				printf("Extracting content 5 U8 Archive.\r\n");
			}

			extract_u8_archive(data + contentpos,"content5");
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
	chdir("..");
	free(data);

}

void do_pack(const char *titleid, const char *channelname) {

	DIR *testdir = opendir(directory);
	if (testdir) {
		closedir(testdir);
	}
	else {
		printf("%s doesn't exist, or is not a directory!\r\n", directory);
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
	u8 *cert = calloc(addpadding(certsize, 64), sizeof(u8));
	fread(cert, 1, certsize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Reading ticket.cert\r\n");
	}
	infile = fopen("ticket.tik", "rb");
	u8 *tik = calloc(addpadding(tiksize, 64), sizeof(u8));
	fread(tik, 1, tiksize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Reading metadata.tmd\r\n");
	}
	infile = fopen("metadata.tmd", "rb");
	u8 *tmd = calloc(addpadding(tmdsize, 64), sizeof(u8));
	fread(tmd, 1, tmdsize, infile);
	fclose(infile);

	if (verbose == 1) {
		printf("Generating Footer signature\r\n");
	}
	u8 *footer = calloc(0x40, sizeof(u8));
	footer[0] = 0x47;
	footer[1] = 0x5A;
	u32 footersize = 0x40;

	// Build Content5 into a .app file first

    int content5len = create_u8_archive("content5","content5.app");
    
    setcontentlength(tmd,5,content5len);

	if (verbose == 1) {
		printf("Modifying content metadata in the TMD\r\n");
	}
	u16 contentsc = be16(tmd + 0x1DE);
	int i;    

	u32 paddedsize = 0;
	char *cfname = malloc(20);
    
	if(patch){
		uint8_t **fileptrs = malloc(sizeof(*fileptrs) * contentsc);
		uint32_t *filesizes = malloc(sizeof(*filesizes) * contentsc);
		FILE *contentfile;
		for (i = 0; i < contentsc; i++) {
			snprintf(cfname, 20, "content%d.app", i);
			stat(cfname, &sbuffer);
			fileptrs[i] = malloc(sbuffer.st_size);
			filesizes[i] = sbuffer.st_size;
			contentfile = fopen(cfname,"rb");
			fread(fileptrs[i],1,sbuffer.st_size,contentfile);
			fclose(contentfile);
		};
		
		gzi_ctxt_t gzi;
		gzi_init(&gzi,fileptrs,filesizes,contentsc);
		gzi_parse_file(&gzi,patch);
		gzi_run(&gzi);

		for(int i=0;i<contentsc;i++){
			snprintf(cfname, 20, "content%d.app", i);
			contentfile = fopen(cfname,"wb");
			fwrite(gzi.file_ptrs[i],1,gzi.file_sizes[i],contentfile);
			fclose(contentfile);
			setcontentlength(tmd,i,gzi.file_sizes[i]);
		}

		gzi_destroy(&gzi);
		free(fileptrs);
		free(filesizes);
	}

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

	do_decrypt(newenc, 16, key, iv);

    int j;

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


			u8 md5digest[16];
			do_md5(contents + contentpos + 64, md5digest, 1536);

			for (j = 0; j < 16; j++) {
				contents[contentpos + 0x630 + j] = md5digest[j];
			}
		}
        
		if (i == 1) {

/*
			// Memory fix 
			contents[contentpos + 0x2EB0] = 0x60;
			contents[contentpos + 0x2EB1] = 0x00;
			contents[contentpos + 0x2EB3] = 0x00;

			if (remap_dpad_up) {
				if (verbose == 1) {
					printf("\tController D-Pad Up\r\n");
				}
				// Mapping fix
				// DUP
				contents[contentpos + 0x16BAF0] = 0x08;
				contents[contentpos + 0x16BAF1] = 0x00;
			}if (remap_dpad_down) {
				if (verbose == 1) {
					printf("\tController D-Pad Down\r\n");
				}
				// DDown
				contents[contentpos + 0x16BAF4] = 0x04;
				contents[contentpos + 0x16BAF5] = 0x00;
			}if (remap_dpad_left) {
				if (verbose == 1) {
					printf("\tController D-Pad Left\r\n");
				}
				// DLEFT
				contents[contentpos + 0x16BAF8] = 0x02;
				contents[contentpos + 0x16BAF9] = 0x00;
			}if (remap_dpad_right) {
				if (verbose == 1) {
					printf("\tController D-Pad Right\r\n");
				}
				// DRIGHT
				contents[contentpos + 0x16BAFC] = 0x01;
				contents[contentpos + 0x16BAFD] = 0x00;
			}
			if (remap_cstick_down) {

				if (raphnet == 1) {
					if (verbose == 1) {
						printf("\tController Z to L For Raphnet\r\n");
					}
					contents[contentpos + 0x16BAD9] = 0x20;
				}
				else {
					if (verbose == 1) {
						printf("\tController C-Stick-Down to L\r\n");
					}
					// CStick Down -> L
					contents[contentpos + 0x16BB05] = 0x20;
				}

			}*/
		}
		iv[0] = tmd[0x1e8 + (0x24 * i)];
		iv[1] = tmd[0x1e9 + (0x24 * i)];


		if (verbose == 1) {
			printf("Generating signature for the content %d, and copying signature to the TMD\r\n", i);
		}

		u8 digest[20];
		do_sha1(contents + contentpos, digest, getcontentlength(tmd, i));

		memcpy(tmd + 0x1f4 + (36 * i), &digest, 20);

		if (verbose == 1) {
			printf("Encrypting content %d\r\n", i);
		}

		do_encrypt(contents + contentpos, size, newenc, iv);

	}
	free(cfname);

	chdir(workingdirectory);

	truchasign(tmd, W_TMD, tmdsize);
	truchasign(tik, W_TIK, tiksize);


	if (verbose == 1) {
		printf("Generating WAD Header, and flipping endianness\r\n");
	}

	FILE *outwadfile = fopen(wad, "wb");
	char wadheader[8] = {
		0x00, 0x00, 0x00, 0x20, 0x49, 0x73, 0x00, 0x00
	};
	char hpadding[4];
	memset(&hpadding, 0, 4);

	u32 certsizer = REVERSEENDIAN32(certsize);
	u32 tiksizer = REVERSEENDIAN32(tiksize);
	u32 tmdsizer = REVERSEENDIAN32(tmdsize);
	u32 datasizer = REVERSEENDIAN32(datasize);
	u32 footersizer = REVERSEENDIAN32(footersize);

	fwrite(&wadheader, 1, 8, outwadfile);
	fwrite(&certsizer, 1, 4, outwadfile);
	fwrite(&hpadding, 1, 4, outwadfile);
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

	if (cleanup == 1) removedir(directory);

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

	do_decrypt(outkey, 16, newkey, iv);

	free(line);

	if (keyfile == NULL)  keyfile = "common-key.bin";
	FILE *keyf = fopen(keyfile, "wb");
	fwrite(&outkey, 1, 16, keyf);
	fclose(keyf);

	printf("%s successfully generated!\r\n", keyfile);
}

char *removeext(char* mystr) {
	char *retstr;
	char *lastdot;
	if (mystr == NULL)
		return NULL;
	if ((retstr = malloc(strlen(mystr) + 1)) == NULL)
		return NULL;
	strcpy(retstr, mystr);
	lastdot = strrchr(retstr, '.');
	if (lastdot != NULL)
		*lastdot = '\0';
	return retstr;
}
