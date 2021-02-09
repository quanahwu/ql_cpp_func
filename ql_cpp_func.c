#include "ql_cpp_func.h"
#include <stdio.h>

buf_t *buf_create(char *buf, size_t len)
{
    buf_t *b;
    if (buf == NULL || len == 0) {
        return NULL;
    }
    b = (buf_t *)malloc(sizeof(buf_t) + len);
    if (b == NULL) {
        return NULL;
    }
    (void)memcpy(b->buf, buf, len);
    b->len = len;
    return b;
}
void buf_destroy(buf_t *b)
{
    if (b != NULL) {
        (void)memset(b->buf, 0, b->len);
        free(b);
    }
}
void buf_print(buf_t *b)
{
    printf("len(%u), buf(%s)\n", b->len, b->buf);
}
