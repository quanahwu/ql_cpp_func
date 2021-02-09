#ifndef __QL_CPP_FUNC_H__
#define __QL_CPP_FUNC_H__
#include <stddef.h>
/* buffer */
typedef struct buf_s {
    size_t len;
    char buf[0];
} buf_t;
buf_t *buf_create(char *buf, size_t len);
void buf_destroy(buf_t *b);
void buf_print(buf_t *b);
#endif
