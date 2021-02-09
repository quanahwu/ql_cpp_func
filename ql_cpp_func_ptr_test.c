#include <stdlib.h>
#include <string.h>
#include "ql_cpp_func.h"
#include "ql_cpp_func_ptr.h"

int main(int argc, char *argv[])
{
    int r = EXIT_FAILURE;
    char *str1 = argv[1];
    buf_t *b;
    buf_op_t *op;

    b = buf_create(str1, strlen(str1));
    if (b == NULL) {
        printf("buf_t is NULL\n");
        goto err;
    }

/*     call_buf_print(b);
 */

    op = buf_op_create();
    if (op == NULL) {
        printf("buf_op_t is NULL\n");
        goto err1;
    }
    buf_op_buf_print(op, b);
    r = EXIT_SUCCESS;

    buf_op_destroy(op);
    op = NULL;
err1:
    buf_destroy(b);
    b = NULL;
err:
    return r;
}
