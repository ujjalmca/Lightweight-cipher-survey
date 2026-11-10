#include <stdint.h>
#include <string.h>
/* ---------- PRINCE ---------- */
static const uint8_t PR_S[16]={0xb,0xf,0x3,0x2,0xa,0xc,0x9,0x1,0x6,0x7,0x8,0x0,0xe,0x5,0xd,0x4};
static const uint8_t PR_SI[16]={0xb,0x7,0x3,0x2,0xf,0xd,0x8,0x9,0xa,0x6,0x4,0x0,0x5,0xe,0xc,0x1};
static const uint8_t PR_SR[16]={0x4,0x9,0xe,0x3,0x8,0xd,0x2,0x7,0xc,0x1,0x6,0xb,0x0,0x5,0xa,0xf};
static const uint8_t PR_SRI[16]={0xc,0x9,0x6,0x3,0x0,0xd,0xa,0x7,0x4,0x1,0xe,0xb,0x8,0x5,0x2,0xf};
static const uint64_t PR_RC[12]={0x0ULL,0x13198a2e03707344ULL,0xa4093822299f31d0ULL,0x082efa98ec4e6c89ULL,
0x452821e638d01377ULL,0xbe5466cf34e90c6cULL,0x7ef84f78fd955cb1ULL,0x85840851f1ac43aaULL,
0xc882d32f25323c54ULL,0x64a51195e0e3610dULL,0xd3b5a399ca0c2399ULL,0xc0ac29b7c97c50ddULL};
static const uint16_t PR_SRC[4]={0x7bde,0xbde7,0xde7b,0xe7bd};
static uint64_t pr_sbox(uint64_t d,const uint8_t*c){uint64_t r=0;for(int i=0;i<16;i++)r|=((uint64_t)c[(d>>(4*i))&0xf])<<(4*i);return r;}
static uint8_t pr_red16(uint16_t x){return (x&0xf)^((x>>4)&0xf)^((x>>8)&0xf)^((x>>12)&0xf);}
static uint64_t pr_mult(uint64_t d){uint64_t ret=0;for(int blk=0;blk<4;blk++){uint16_t hw=(d>>(16*blk))&0xffff;int start=(blk==0||blk==3)?0:1;
for(int ni=0;ni<4;ni++)ret|=((uint64_t)pr_red16(hw&PR_SRC[(start+3-ni)%4]))<<(16*blk+4*ni);}return ret;}
static uint64_t pr_sr(uint64_t d,int inv){const uint8_t*sh=inv?PR_SRI:PR_SR;uint64_t r=0;for(int ni=0;ni<16;ni++)r|=((d>>(4*sh[ni]))&0xf)<<(4*ni);return r;}
uint64_t prince_enc(uint64_t pt,uint64_t k0,uint64_t k1){
    uint64_t k0p=(((k0&1)<<63)|(k0>>1))^(k0>>63);
    uint64_t d=pt^k0^k1^PR_RC[0];
    for(int i=1;i<6;i++){d=pr_sbox(d,PR_S);d=pr_mult(d);d=pr_sr(d,0);d^=PR_RC[i]^k1;}
    d=pr_sbox(d,PR_S);d=pr_mult(d);d=pr_sbox(d,PR_SI);
    for(int i=6;i<11;i++){d^=PR_RC[i]^k1;d=pr_sr(d,1);d=pr_mult(d);d=pr_sbox(d,PR_SI);}
    d^=PR_RC[11]^k1^k0p;
    return d;
}

