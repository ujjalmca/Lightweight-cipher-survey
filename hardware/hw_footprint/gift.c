#include <stdint.h>
#include <string.h>
/* ---------- GIFT-64 ---------- */
static const uint8_t GIFT_S[16]={1,10,4,12,6,15,3,9,2,13,11,7,5,0,8,14};
static const uint8_t GIFT_P[64]={0,17,34,51,48,1,18,35,32,49,2,19,16,33,50,3,4,21,38,55,52,5,22,39,
36,53,6,23,20,37,54,7,8,25,42,59,56,9,26,43,40,57,10,27,24,41,58,11,12,29,46,63,60,13,30,47,44,61,14,31,28,45,62,15};
static const uint8_t GIFT_RC[28]={0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,
0x27,0x0E,0x1D,0x3A,0x35,0x2B,0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B};
uint64_t gift64_enc(uint64_t pt, const uint16_t ks_in[8]){
    uint8_t b[64]; uint16_t ks[8];
    for(int i=0;i<64;i++) b[i]=(pt>>i)&1;
    for(int i=0;i<8;i++) ks[i]=ks_in[i];
    for(int r=0;r<28;r++){
        for(int n=0;n<16;n++){
            uint8_t nib=b[4*n]|(b[4*n+1]<<1)|(b[4*n+2]<<2)|(b[4*n+3]<<3);
            uint8_t sv=GIFT_S[nib];
            b[4*n]=sv&1;b[4*n+1]=(sv>>1)&1;b[4*n+2]=(sv>>2)&1;b[4*n+3]=(sv>>3)&1;
        }
        uint8_t nb[64];
        for(int i=0;i<64;i++) nb[GIFT_P[i]]=b[i];
        memcpy(b,nb,64);
        uint16_t u=ks[1],v=ks[0];
        for(int i=0;i<16;i++){ b[4*i+1]^=(u>>i)&1; b[4*i]^=(v>>i)&1; }
        uint8_t rc=GIFT_RC[r];
        for(int j=0;j<6;j++) b[4*j+3]^=(rc>>j)&1;
        b[63]^=1;
        uint16_t k0=ks[0],k1=ks[1];
        uint16_t k0r=((k0>>2)|(k0<<14))&0xFFFF, k1r=((k1>>12)|(k1<<4))&0xFFFF;
        for(int i=0;i<6;i++) ks[i]=ks[i+2];
        ks[6]=k0r; ks[7]=k1r;
    }
    uint64_t ct=0;
    for(int i=0;i<64;i++) ct|=((uint64_t)b[i])<<i;
    return ct;
}

