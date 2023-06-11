#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define SHA256_BLOCKLEN 64
#define SHA256_DIGESTLEN 32

typedef struct _SHA256_CTX{
    uint8_t data[SHA256_BLOCKLEN]; //8bit*64개=512bit (one block)
    uint32_t datalen; //bytelen
    uint64_t bitlen; //data bitlen
    uint32_t ChainVar[8];
}_SHA256_CTX;

typedef _SHA256_CTX SHA256_CTX[1];

#define ROTL_ULONG(x, n) ((uint32_t)((x) << (n)) | (uint32_t)((x) >> (32 - (n))))
#define ROTR_ULONG(x, n) ((uint32_t)((x) >> (n)) | (uint32_t)((x) << (32 - (n))))

#define CH(x,y,z) ((x&y)^(~x)&z)
#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define S0(x) (ROTR_ULONG(x,2)^ROTR_ULONG(x,13)^ROTR_ULONG(x,22))
#define S1(x) (ROTR_ULONG(x,6)^ROTR_ULONG(x,11)^ROTR_ULONG(x,25))
#define sig0(x) (ROTR_ULONG(x,7)^ROTR_ULONG(x,18)^((x)>>3))
#define sig1(x) (ROTR_ULONG(x,17)^ROTR_ULONG(x,19)^((x)>>10))



const uint32_t SHA256_K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
							0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
							0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
							0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
							0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
							0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
							0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
							0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
							0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
							0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
							0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// SHA-256 initial hash value
uint32_t ChainVar[8]={0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void sha256_init(SHA256_CTX ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->ChainVar[0] = 0x6a09e667;
    ctx->ChainVar[1] = 0xbb67ae85;
    ctx->ChainVar[2] = 0x3c6ef372;
    ctx->ChainVar[3] = 0xa54ff53a;
    ctx->ChainVar[4] = 0x510e527f;
    ctx->ChainVar[5] = 0x9b05688c;
    ctx->ChainVar[6] = 0x1f83d9ab;
    ctx->ChainVar[7] = 0x5be0cd19;
}

void sha256_transform(SHA256_CTX ctx, const uint8_t *msg)
{
    uint32_t W[SHA256_BLOCKLEN]={0,}; //32*16 + 연산
    uint32_t a,b,c,d,e,f,g,h,T1,T2;

    for(int i=0; i<16; i++)
    {
        W[i]=(msg[4*i]<<24)^(msg[4*i+1]<<16)^(msg[4*i+2]<<8)^msg[4*i+3];
    }
    for(int i=16; i<64; i++)
    {
        W[i]=sig1(W[i-2])+W[i-7]+sig0(W[i-15])+W[i-16];
    }

    a=ctx->ChainVar[0];
    b=ctx->ChainVar[1];
    c=ctx->ChainVar[2];
    d=ctx->ChainVar[3];
    e=ctx->ChainVar[4];
    f=ctx->ChainVar[5];
    g=ctx->ChainVar[6];
    h=ctx->ChainVar[7];

    // SHA256-one block
    for(int i=0; i<64; i++)
    {   
        T1 = h+S1(e)+CH(e,f,g)+SHA256_K[i]+W[i];
        T2 = S0(a)+Maj(a,b,c);
        h=g;
        g=f;
        f=e;
        e=d+T1;
        d=c;
        c=b;
        b=a;
        a=T1+T2;
    }

    ctx-> ChainVar[0]+=a;
    ctx->ChainVar[1]=b+ctx->ChainVar[1];
    ctx->ChainVar[2]=c+ctx->ChainVar[2];
    ctx->ChainVar[3]=d+ctx->ChainVar[3];
    ctx->ChainVar[4]=e+ctx->ChainVar[4];
    ctx->ChainVar[5]=f+ctx->ChainVar[5];
    ctx->ChainVar[6]=g+ctx->ChainVar[6];
    ctx->ChainVar[7]=h+ctx->ChainVar[7];

    //hash value
    for(int i=0; i<8; i++)
    {
        printf("Ch[%d]: %x \n",i,ChainVar[i]);
    }
}

//MsgLen => byte 단위 >= 64
void sha256_update(SHA256_CTX ctx, uint8_t *Message, uint32_t MsgLen)
{
    int templen; //우리는 전공자니까 전체패딩 하지말자!
    //datalen : MsgLen은 입력값이니까 이걸 64씩 깎으면 나중에 MsgLen을 못쓰게 됨. 입력값은 건드리지 않는게 좋음.
    ctx -> datalen = MsgLen;
    while(ctx -> datalen >= SHA256_BLOCKLEN)
    {
        // data, msg 복사
        memcpy(ctx -> data, Message, SHA256_BLOCKLEN);
        // sha256 transform
        sha256_transform(ctx, ctx->data);
        //Message 0~63/ 64~127씩 복사하고 싶음 -> 이 Message가 가르키는 주소의 값도 복사해줘야 함
        Message += SHA256_BLOCKLEN;

        ctx -> datalen -= SHA256_BLOCKLEN; //ctx ->datalen = ctx -> datalrn - SHA256_BLOCKLEN
        ctx -> bitlen += 512;
        // 데이터는 계속 깎아내려가는데 bitlen같은 경우는 512씩 늘려간다
        // 그래서 블록을 진행할 때마다 데이터 길이는 늘어난다 

    }
    // 남은 메세지 블록을 복사 => final에서 패딩
    memcpy(ctx -> data, Message, ctx -> datalen);
    
}

void sha256_final(uint8_t *hash, SHA256_CTX ctx)
{   
        int i = ctx -> datalen;
    if (ctx -> datalen < 56)
    {
        ctx -> data[i++]=0x80; //i++과 ++i (i=i+1)는 다르다!
        
        while(i<56) { ctx -> data[i++]=0x00; }
    }
    else
    {
        ctx -> data[i++]=0x80;
        while(i<64) { ctx -> data[i++]=0x00; }
        sha256_transform(ctx, ctx -> data);
        memset(ctx -> data, 0, 56);
    }

    // 길이정보 // hash
    ctx -> bitlen += ctx -> datalen * 8;
    // 64bit 번수 -> 8bit 8개
    ctx -> data[63] = (ctx -> bitlen) & 0xff;
    ctx -> data[62] = (ctx -> bitlen >> 8) & 0xff;
    ctx -> data[61] = (ctx -> bitlen >> 16) & 0xff;
    ctx -> data[60] = (ctx -> bitlen >> 24) & 0xff;
    ctx -> data[59] = (ctx -> bitlen >> 32) & 0xff;
    ctx -> data[58] = (ctx -> bitlen >> 40) & 0xff;
    ctx -> data[57] = (ctx -> bitlen >> 48) & 0xff;
    ctx -> data[56] = (ctx -> bitlen >> 56) & 0xff;

    // sha256_transform   
    sha256_transform(ctx, ctx->data);

    for(i = 0; i < 8; i++)
    {
        hash[4*i  ] = (ctx -> ChainVar[i] >> 24) & 0xff;
        hash[4*i+1] = (ctx -> ChainVar[i] >> 16) & 0xff;
        hash[4*i+2] = (ctx -> ChainVar[i] >>  8) & 0xff;
        hash[4*i+3] = (ctx -> ChainVar[i]      ) & 0xff;
    }
}

void SHA256(uint8_t *Digest, uint8_t *Message, uint32_t Msglen)
{
    SHA256_CTX ctx;
    sha256_init(ctx);
    sha256_update(ctx, Message, Msglen);
    sha256_final(Digest, ctx);
}

void main()
{
    uint8_t msg1[] = {"abc"};
    uint8_t hash1[SHA256_DIGESTLEN] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t msglen = 24; //bitlen

    // preprocessing
    uint8_t mpad[SHA256_BLOCKLEN]={0,}; //64*8

    uint32_t W[SHA256_BLOCKLEN]={0,}; //32*16 + 연산
    uint32_t a,b,c,d,e,f,g,h,T1,T2;

    mpad[0]=msg1[0]; //a
    mpad[1]=msg1[1]; //b
    mpad[2]=msg1[2]; //c
    mpad[3]=0x80;
    mpad[63]=msglen;

    //함수 테스트
    SHA256_CTX ctx;
    sha256_init(ctx);
    uint32_t mlen = 3;
    uint8_t tmp[SHA256_DIGESTLEN];

    
        //hash value
    SHA256(tmp, msg1, mlen);



    for(int i=0; i<8; i++)
    {
        printf("Ch[%d]: %x \n",i,ctx->ChainVar[i]);
    }

    for(int i = 0; i < 32; i++)
    {
        printf("%02x", tmp[i]);
    }
    printf("\n");

}                        