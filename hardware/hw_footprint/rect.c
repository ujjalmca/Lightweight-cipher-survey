#include <stdint.h>
#include <string.h>
/* ---------- RECTANGLE-80 ---------- */
static const uint8_t RC_S[16]={0x6,0x5,0xC,0xA,0x1,0xE,0x7,0x9,0xB,0x0,0x3,0xD,0x8,0xF,0x4,0x2};
static const uint8_t RC_RC[25]={0x01,0x02,0x04,0x09,0x12,0x05,0x0B,0x16,0x0C,0x19,0x13,0x07,0x0F,0x1F,
0x1E,0x1C,0x18,0x11,0x03,0x06,0x0D,0x1B,0x17,0x0E,0x1D};
static uint16_t rc_rol(uint16_t x,int n){return ((x<<n)|(x>>(16-n)))&0xFFFF;}
uint64_t rectangle80_enc(uint64_t pt,const uint16_t key[5]){
    uint16_t rows[5]; uint64_t sk[26];
    for(int i=0;i<5;i++)rows[i]=key[i];
    for(int i=0;i<25;i++){
        sk[i]=((uint64_t)rows[0])|((uint64_t)rows[1]<<16)|((uint64_t)rows[2]<<32)|((uint64_t)rows[3]<<48);
        uint16_t nr[5]; for(int t=0;t<5;t++)nr[t]=rows[t];
        for(int j=0;j<4;j++){
            uint8_t col=((rows[0]>>j)&1)|(((rows[1]>>j)&1)<<1)|(((rows[2]>>j)&1)<<2)|(((rows[3]>>j)&1)<<3);
            uint8_t s=RC_S[col];
            for(int r=0;r<4;r++)nr[r]=(nr[r]&~(1<<j))|(((s>>r)&1)<<j);
        }
        uint16_t r0=rc_rol(nr[0],8)^nr[1], r3=rc_rol(nr[3],12)^nr[4];
        rows[0]=r0;rows[1]=nr[2];rows[2]=nr[3];rows[3]=r3;rows[4]=nr[0];
        rows[0]^=RC_RC[i];
    }
    sk[25]=((uint64_t)rows[0])|((uint64_t)rows[1]<<16)|((uint64_t)rows[2]<<32)|((uint64_t)rows[3]<<48);
    uint16_t st[4]; for(int i=0;i<4;i++)st[i]=(pt>>(16*i))&0xFFFF;
    for(int i=0;i<25;i++){
        uint16_t kr[4]; for(int r=0;r<4;r++)kr[r]=(sk[i]>>(16*r))&0xFFFF;
        for(int r=0;r<4;r++)st[r]^=kr[r];
        uint16_t A0=st[0],A1=st[1],A2=st[2],A3=st[3];
        uint16_t T1=(~A1)&0xFFFF,T2=A0&T1,T3=A2^A3,B0=T2^T3,T5=A3|T1,T6=A0^T5,B1=A2^T6,T8=A1^A2,T9=T3&T6,B3=T8^T9,T11=B0|T8,B2=T6^T11;
        st[0]=B0;st[1]=rc_rol(B1,1);st[2]=rc_rol(B2,12);st[3]=rc_rol(B3,13);
    }
    uint16_t kr[4]; for(int r=0;r<4;r++)kr[r]=(sk[25]>>(16*r))&0xFFFF;
    for(int r=0;r<4;r++)st[r]^=kr[r];
    uint64_t x=0; for(int i=0;i<4;i++)x|=((uint64_t)st[i])<<(16*i);
    return x;
}

