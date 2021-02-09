#ifndef __QL_CPP_FUNC_PTR_H__
#define __QL_CPP_FUNC_PTR_H__
#include "ql_cpp_func.h"

void call_buf_print(buf_t *b);

typedef void (*funcp_t)(buf_t *b);

/* buffer operation */
typedef struct buf_op_s {
    funcp_t op_buf_print;
} buf_op_t;
buf_op_t *buf_op_create();
void buf_op_destroy(buf_op_t *op);
void buf_op_buf_print(buf_op_t *op, buf_t *b);
#endif
