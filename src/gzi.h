#ifndef _PATCH_H_
#define _PATCH_H_

#include <stdint.h>

typedef struct {
    uint8_t command;
    uint8_t len;
    uint32_t offset;
    uint32_t data;
}gzi_code;

typedef struct{
    gzi_code *codes;
    int codecnt;
    int8_t curfile;
    uint8_t **file_ptrs;
    uint32_t *file_sizes;
    uint8_t filecnt;
}gzi_ctxt_t;

int gzi_parse_file(gzi_ctxt_t *ctxt, const char *file);
int gzi_parse_embedded(gzi_ctxt_t *ctxt, const char *data, size_t len);
int gzi_run(gzi_ctxt_t *ctxt);
int gzi_init(gzi_ctxt_t *ctxt, uint8_t **files, uint32_t *filesizes, int filecnt);
int gzi_destroy(gzi_ctxt_t *ctxt);

#endif