
#include "stdio.h"
#include "common/except.h"

#define EX1 -1

static void test_except_func(bW_EXCEPT *exc)
{
    printf("except_func 1\n");
    RAISE(exc, EX1);
    printf("except_func 2\n");
}

static void test_except()
{
    bW_EXCEPT exc;

    TRY(&exc) 
    {
        printf("Body 1\n");
        test_except_func(&exc);
        printf("Body 2\n");
    } 
    EXCEPT if (EXCEPT_CODE(&exc) == EX1)
    {
        printf("Exception: %d\n", EX1);
    } else {
        printf("Exception: %d\n", EXCEPT_CODE(&exc));
    }

    return;
}

int main(int argc, char const *argv[])
{
    test_except();
}
