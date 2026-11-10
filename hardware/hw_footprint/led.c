#include <stdint.h>
#include <string.h>
/* ---------- LED-64 ---------- */
static const uint8_t LED_S[16]={0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2};
static const uint8_t LED_M[4][4]={{4,1,2,2},{8,6,5,6},{0xB,0xE,0xA,9},{2,2,0xF,0xB}};
static uint8_t led_gmul(uint8_t a,uint8_t b){uint8_t p=0;for(int i=0;i<4;i++){if(b&1)p^=a;uint8_t hi=a&0x8;a=(a<<1)&0xF;if(hi)a^=0x3;b>>=1;}return p;}
uint64_t led64_enc(uint64_t pt,uint64_t key){
    uint8_t rcs[48]; uint8_t rc=0;
    for(int i=0;i<48;i++){uint8_t nb=((rc>>5)&1)^((rc>>4)&1)^1;rc=((rc<<1)|nb)&0x3F;rcs[i]=rc;}
    uint8_t s[4][4],k[4][4];
    for(int i=0;i<16;i++){s[i/4][i%4]=(pt>>(4*(15-i)))&0xF;k[i/4][i%4]=(key>>(4*(15-i)))&0xF;}
    uint8_t ks_hi=0x4,ks_lo=0x0; int ri=0;
    for(int step=0;step<8;step++){
        for(int i=0;i<4;i++)for(int j=0;j<4;j++)s[i][j]^=k[i][j];
        for(int rnd=0;rnd<4;rnd++){
            uint8_t r=rcs[ri++]; uint8_t rh=(r>>3)&0x7,rl=r&0x7;
            uint8_t add[4][4]={{(uint8_t)(0^ks_hi),rh,0,0},{(uint8_t)(1^ks_hi),rl,0,0},{(uint8_t)(2^ks_lo),rh,0,0},{(uint8_t)(3^ks_lo),rl,0,0}};
            for(int i=0;i<4;i++)for(int j=0;j<4;j++)s[i][j]^=add[i][j];
            for(int i=0;i<4;i++)for(int j=0;j<4;j++)s[i][j]=LED_S[s[i][j]];
            for(int i=0;i<4;i++){uint8_t tmp[4];for(int j=0;j<4;j++)tmp[j]=s[i][(j+i)%4];for(int j=0;j<4;j++)s[i][j]=tmp[j];}
            uint8_t ns[4][4];
            for(int j=0;j<4;j++)for(int i=0;i<4;i++){uint8_t v=0;for(int kk=0;kk<4;kk++)v^=led_gmul(LED_M[i][kk],s[kk][j]);ns[i][j]=v;}
            memcpy(s,ns,16);
        }
    }
    for(int i=0;i<4;i++)for(int j=0;j<4;j++)s[i][j]^=k[i][j];
    uint64_t x=0; for(int i=0;i<16;i++)x=(x<<4)|s[i/4][i%4];
    return x;
}

