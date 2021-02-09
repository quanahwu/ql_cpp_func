#include "ql_cpp_func_ptr.h"
#include <stdlib.h>
funcp_t g_fp = buf_print;

void call_buf_print(buf_t *b)
{
    buf_print(b);
}

buf_op_t *buf_op_create()
{
    buf_op_t *op = (buf_op_t *)malloc(sizeof(buf_op_t));
    if (op == NULL) {
        return NULL;
    }
    op->op_buf_print = buf_print;
    return op;
}
void buf_op_destroy(buf_op_t *op)
{
    if (op != NULL) {
        memset(op, 0, sizeof(buf_op_t));
        free(op);
    }
}
void buf_op_buf_print(buf_op_t *op, buf_t *b)
{
    if (op == NULL || op->op_buf_print == NULL) {
        return;
    }
    op->op_buf_print(b);
}
