// 필수 헤더
#include <stdio.h> //
#include <string.h>
#include <stdlib.h>
#include <inttypes.h> //


// gcc 0320.c -o 0320
// ./0320

#define DEBUG

void shift_operation_ex()
{
    uint8_t a = 0xb3, out = 0;
    uint8_t t0=0, t1=0;

    t0 = a&0x07; // _ _ _ _ _ * * * 
    t0 = t0<<5;  // * * * _ _ _ _ _ 
    t1 = a>>3;   // _ _ _ * * * * *

    out = t0^t1;

    printf("out : %02x \n", out); // out : 76
    printf("out : 0x%02x \n", out); // out : 0x76 (당연함)
    
}

void even_odd_XOR()
{
    uint8_t a = 0xbc, out = 0;
    uint8_t t0=0, t1=0;

    t0 = a & 0xaa; //홀수는 1_1_1_1
    t1 = a & 0x55; // 짝수는 _1_1_1_1
    t0 = t0 >> 1; // t1이랑 t2랑 만나야 하니까 >> 1
    out = t0^t1; // 이거 지금 _*_*_*_*이니까 몰아넣는거 도전과제

    printf("out : 0x%02x \n", out); // 
}

void main()
{
    // shift_operation_ex();
    // even_odd_XOR();
}