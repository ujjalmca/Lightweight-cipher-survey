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

#ifdef TEST_MAIN
#include <stdio.h>
int main(){
    uint16_t z8[8]={0,0,0,0,0,0,0,0};
    printf("GIFT-64:  %016llx (exp f62bc3ef34f775ac)\n",(unsigned long long)gift64_enc(0,z8));
    printf("PRINCE:   %016llx (exp 818665aa0d02dfda)\n",(unsigned long long)prince_enc(0,0,0));
    printf("LED-64:   %016llx (exp 39c2401003a0c798)\n",(unsigned long long)led64_enc(0,0));
    uint16_t z5[5]={0,0,0,0,0};
    printf("RECT-80:  %016llx (exp 0874e8b1e3542d96)\n",(unsigned long long)rectangle80_enc(0,z5));
    return 0;
}
#endif
