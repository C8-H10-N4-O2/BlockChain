#include <stdio.h>
#include <inttypes.h>

#define DEBUG



/*

void main()
{
     
    printf("-----#1 시작-----\n");
    printf("hello world \n");
    

     
    printf("-----#2 자료형과 출력형태-----\n");
    int a = 23;
    int b = 7;

    printf("a: %d\n" , a);
    printf("a: %x\n" , a);
    printf("a: %02X\n" , a);
    printf("b: %x\n" , b);
    printf("b: %02X\n" , b);

    // %x는 헥사로 출력하는 것
    

     
    printf("-----#3 조건문-----\n");
    int c = 23;

    if (c % 2 == 0)
    {
        printf("c is even\n");
    }
    else
    {
        printf("c is odd\n");
    }
    

   printf("-----#4 반복문-----\n");

   int out = 0;

   for(int i = 1; i < 11; i++)
   {
        out = out + i;
   }
#ifdef DEBUG
    printf("sum: %d \n", out);
#endif
    //gcc main.c -DDEBUG -o main 
    //DEBUG를 정의해주는 것. 메인 바로 위에 보통 써줌
    //전체 프린트를 막는 방법으로 씀

}

void main()
{
    printf("-----#5 시프트 연산----- \n");
    unsigned char a = 0x01;
    unsigned char b = 0;
    unsigned char c = 0xff;

#ifdef DEBUG
    // left Shift 2의 지수승 곱셈으로 사용
    for (int i = 1; i <= 8; i++)
    {
        b = a << i;
        printf("shift %d : %02x \n", i, b);
    }

    // right Shift 2의 지수승 나눗셈의 몫으로 사용
    // 그럼 나머지는? &0xf처럼 &+비트수(n) 으로 구한다. 
    // ex) 2^3으로 나누면 &0x7로 구함 이게맞나
    for (int i = 1; i <= 8; i++)
    {
        b = c >> i;
        printf("shift %d : %02x \n", i, b);
    }

#endif

*/

void main()
{
    printf("-----#6 시프트 연산 예제----- \n");
    unsigned char a = 0x23;
    unsigned char b = 0;
    
    b = (a & 0xe0) >> 5;
    a = (a<<3)^b;
    printf("rotate shift : %02x \n", a);
}
