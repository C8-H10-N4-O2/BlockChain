#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define SHA256_BLOCKLEN 64
#define SHA256_DIGESTLEN 32

typedef struct _SHA256_CTX{
	uint8_t data[SHA256_BLOCKLEN]; //8bit * 64개 = 512bit (one block)
	uint32_t datalen; //bytelen
	uint64_t bitlen;  //data bitlen
	uint32_t ChainVar[8];
}_SHA256_CTX;

typedef _SHA256_CTX SHA256_CTX[1];

typedef struct _HMAC_ALG_INFO{
	SHA256_CTX ctx;
	uint8_t Key[SHA256_BLOCKLEN];
	uint8_t hmac_digest[SHA256_DIGESTLEN];
} _HMAC_ALG_INFO;

typedef _HMAC_ALG_INFO HMAC_ALG_INFO[1];


#define ROTL_ULONG(x, n) ((uint32_t)((x) << (n)) | (uint32_t)((x) >> (32 - (n))))
#define ROTR_ULONG(x, n) ((uint32_t)((x) >> (n)) | (uint32_t)((x) << (32 - (n))))

#define CH(x,y,z) ((x&y)^((~x)&z))
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


uint32_t ChainVar[8]={0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};


void sha256_init(SHA256_CTX ctx)
{
	ctx -> datalen = 0;
	ctx -> bitlen = 0;
	ctx -> ChainVar[0] = 0x6a09e667;
	ctx -> ChainVar[1] = 0xbb67ae85;
	ctx -> ChainVar[2] = 0x3c6ef372;
	ctx -> ChainVar[3] = 0xa54ff53a;
	ctx -> ChainVar[4] = 0x510e527f;
	ctx -> ChainVar[5] = 0x9b05688c;
	ctx -> ChainVar[6] = 0x1f83d9ab;
	ctx -> ChainVar[7] = 0x5be0cd19;
}

void sha256_transform(SHA256_CTX ctx, const uint8_t *msg)
{
	// preprocessing
	uint32_t W[SHA256_BLOCKLEN] = {0,}; //32*16 + 연산
	uint32_t a,b,c,d,e,f,g,h,T1,T2;

	for(int i=0; i<16; i++){
		W[i] = (msg[4*i]<<24)^(msg[4*i+1]<<16)^(msg[4*i+2]<<8)^msg[4*i+3];
	}

	for(int i=16; i<64; i++){
		W[i] = sig1(W[i-2])+W[i-7]+sig0(W[i-15])+W[i-16];
	}

	// for(int i=0; i<64; i++){
	// 	printf("W[%d] : %x \n", i, W[i]);
	// }

	a = ctx -> ChainVar[0];
	b = ctx -> ChainVar[1];
	c = ctx -> ChainVar[2];
	d = ctx -> ChainVar[3];
	e = ctx -> ChainVar[4];
	f = ctx -> ChainVar[5];
	g = ctx -> ChainVar[6];
	h = ctx -> ChainVar[7];


    // SHA256-one block

	for(int i=0; i<64; i++){
			T1 = h + S1(e) + CH(e,f,g)+ SHA256_K[i] + W[i];
			T2 = S0(a) + Maj(a,b,c);
			h=g;
			g=f;
			f=e;
			e=d+T1;
			d=c;
			c=b;
			b=a;
			a=T1+T2;
	}

	ctx -> ChainVar[0]=a+ctx -> ChainVar[0];
	ctx -> ChainVar[1]=b+ctx -> ChainVar[1];
	ctx -> ChainVar[2]=c+ctx -> ChainVar[2];
	ctx -> ChainVar[3]=d+ctx -> ChainVar[3];
	ctx -> ChainVar[4]=e+ctx -> ChainVar[4];
	ctx -> ChainVar[5]=f+ctx -> ChainVar[5];
	ctx -> ChainVar[6]=g+ctx -> ChainVar[6];
	ctx -> ChainVar[7]=h+ctx -> ChainVar[7];

}

// MsgLen => byte 단위 >= 64
void sha256_update(SHA256_CTX ctx, uint8_t *Message, uint32_t MsgLen)
{
	int templen;
	ctx->datalen = MsgLen;
	while(ctx->datalen>=SHA256_BLOCKLEN)
	{
		//memcpy 사용법
		//memcpy (결과, 복사하고 싶은것, 길이);
		//Message를 ctx->data에 복사
		//memcpy(ctx->data, Message, 64);
		//memcpy(ctx->data, Message, SHA256_BLOCKLEN)

		//data, msg 복사
		memcpy(ctx->data, Message, SHA256_BLOCKLEN);
		//sha256 transform
		sha256_transform(ctx, ctx->data);

		Message += SHA256_BLOCKLEN; //한 번 돌리고 나면 그 뒤에 있는 64byte를 복사하고 싶기 때문에
		ctx->datalen -= SHA256_BLOCKLEN; //ctx->datalen = ctx->datalen - SHA256_BLOCKLEN
		ctx->bitlen+=512;

	}

	memcpy(ctx->data,Message,ctx->datalen);
}

void sha256_final(uint8_t *hash, SHA256_CTX ctx)
{
	int i = ctx->datalen;

	if(ctx->datalen<56)
	{
		ctx->data[i++]= 0x80;
		while(i<56)
			ctx->data[i++]=0x00;
	}
	else{
		ctx->data[i++]=0x80;
		while(i<64)
			ctx->data[i++]=0x00;
		sha256_transform(ctx,ctx->data);
		memset(ctx->data,0,56);
		

	}
	
	//길이정보 //hash
	ctx->bitlen += ctx->datalen*8;
	//64bit변수 -> 8bit 8개
	ctx->data[63]=(ctx->bitlen)&0xff;
	ctx->data[62]=(ctx->bitlen>>8)&0xff;
	ctx->data[61]=(ctx->bitlen>>16)&0xff;
	ctx->data[60]=(ctx->bitlen>>24)&0xff;
	ctx->data[59]=(ctx->bitlen>>32)&0xff;
	ctx->data[58]=(ctx->bitlen>>40)&0xff;
	ctx->data[57]=(ctx->bitlen>>48)&0xff;
	ctx->data[56]=(ctx->bitlen>>56)&0xff;

	//sha256_transform
	sha256_transform(ctx, ctx->data);

	for(i=0; i<8; i++){
		hash[4*i]=(ctx->ChainVar[i]>>24)&0xff;
		hash[4*i+1]=(ctx->ChainVar[i]>>16)&0xff;
		hash[4*i+2]=(ctx->ChainVar[i]>>8)&0xff;
		hash[4*i+3]=(ctx->ChainVar[i])&0xff;
	}

}

void SHA256(uint8_t *Digest, uint8_t *Message, uint32_t MsgLen)
{
	SHA256_CTX ctx;
	sha256_init(ctx);
	sha256_update(ctx,Message,MsgLen);
	sha256_final(Digest,ctx);
}

//keylen -> bytelen
void hmac_sha256_init(HMAC_ALG_INFO hmacctx, uint8_t *key, uint32_t keylen)
{
	uint8_t ipad[SHA256_BLOCKLEN];
	if(keylen<=SHA256_BLOCKLEN) //keylen<=64
	{
		memcpy(hmacctx->Key, key, sizeof(uint8_t)*keylen);
		for(int i=0; i<SHA256_BLOCKLEN-keylen; i++)
		{
			hmacctx->Key[i+keylen]=0;
		}
	}
	else //keylen>64
	{
		sha256_init(hmacctx->ctx);
		sha256_update(hmacctx->ctx, key, keylen);
		sha256_final(hmacctx->Key, hmacctx->ctx); // 압축 -> key 32byte 저장
		for(int i=0; i<SHA256_BLOCKLEN-SHA256_DIGESTLEN; i++)
		{
			hmacctx->Key[i+SHA256_DIGESTLEN]=0;
		}
	}

	for(int i=0; i<SHA256_BLOCKLEN; i++)
	{
		ipad[i]=hmacctx->Key[i]^0x36;
	}
	// H(key^ipad)
	sha256_init(hmacctx->ctx);
	sha256_update(hmacctx->ctx, hmacctx->Key, SHA256_BLOCKLEN);

	//ipad 초기화
	for(int i=0; i<SHA256_BLOCKLEN; i++)
	{
		ipad[i]=0;
	}
}

void hmac_sha256_update(HMAC_ALG_INFO hmacctx, uint8_t *msg, uint32_t msglen)
{
	sha256_update(hmacctx->ctx, msg, msglen);
	sha256_final(hmacctx->hmac_digest,hmacctx->ctx);
}

void hmac_sha256_final(uint8_t *tag, HMAC_ALG_INFO hmacctx, uint32_t taglen)
{
	uint8_t opad[SHA256_BLOCKLEN];
	uint8_t tmp[SHA256_DIGESTLEN];

	for(int i=0; i<SHA256_BLOCKLEN; i++)
	{
		opad[i]=hmacctx->Key[i]^0x5c;
	}
	sha256_init(hmacctx->ctx);
	sha256_update(hmacctx->ctx, opad, SHA256_BLOCKLEN);
	sha256_update(hmacctx->ctx, hmacctx->hmac_digest, SHA256_DIGESTLEN);
	sha256_final(tmp, hmacctx->ctx);

	memcpy(tag, tmp, sizeof(uint8_t)*taglen);

	//opad 초기화
	for(int i=0; i<SHA256_BLOCKLEN; i++)
	{
		opad[i]=0;
	}
	//tmp 초기화
	for(int i=0; i<SHA256_BLOCKLEN; i++)
	{
		tmp[i]=0;
	}
}


void main()
{
    uint8_t msg1[] = {"abc"};
    uint8_t hash1[SHA256_DIGESTLEN] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
	                                 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t msglen = 24; //bitlen

	uint8_t mpad[SHA256_BLOCKLEN] = {0,}; //64*8

	mpad[0] = msg1[0]; //a
	mpad[1] = msg1[1]; //b
	mpad[2] = msg1[2]; //c
	mpad[3] = 0x80;
	mpad[63] = msglen;

	

	//함수 테스트
	SHA256_CTX ctx;
	uint32_t mlen = 3;
	uint8_t tmp[SHA256_DIGESTLEN];
	SHA256(tmp,msg1,mlen);
	
	//hash value
	for(int i=0; i<8; i++){
		printf("--Ch[%d] : %x \n", i, ctx->ChainVar[i]);
	}
	for(int i=0; i<32; i++)
	{
		printf("%02x",tmp[i]);
	}
	printf("\n");





}