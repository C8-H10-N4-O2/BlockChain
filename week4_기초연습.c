#include <stdio.h>
#include <inttypes.h>

int my_add(ina a, int b)
{
    return a+b;
}


void main()
{
    uint32_t a = 16;
    uint32_t b = 14;
    uint32_t res - 0;

    res = my_add(a, b);
    print("a+b is = ",res)
}