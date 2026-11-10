/* Native benchmark of lightweight block ciphers.
 * All implementations verified against published test vectors at startup.
 * Metrics: ns/block, cycles/byte (rdtsc), throughput Mbit/s.
 * Build (bench): gcc -O2 -o lwc_bench lwc.c
 * Build (size of one cipher): gcc -Os -c -DONLY_<NAME> lwc.c -o <name>.o
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#define ROTL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r))|((x)<<(32-(r))))

/* ---------------- PRESENT-80 ---------------- */
#if !defined(SIZEBUILD) || defined(ONLY_PRESENT)
static const uint8_t SBOX[16]={0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2};
void present_ks(const uint8_t key[10], uint64_t rk[32]){
    uint64_t hi=0; uint32_t lo; int r,i;
    for(i=0;i<8;i++) hi=(hi<<8)|key[i];
    lo=((uint32_t)key[8]<<8)|key[9];           /* 80-bit key = hi(64)||lo(16) */
    for(r=1;r<=32;r++){
        rk[r-1]=hi;                             /* top 64 bits */
        {   /* rotate 80-bit register left by 61, S-box on top nibble, add counter */
            unsigned __int128 k=(((unsigned __int128)hi)<<16)|lo;
            k=((k<<61)|(k>>19)) & ((((unsigned __int128)1)<<80)-1);
            uint8_t top=(uint8_t)(k>>76);
            k=(k & ((((unsigned __int128)1)<<76)-1)) | ((unsigned __int128)SBOX[top]<<76);
            k ^= ((unsigned __int128)r)<<15;
            hi=(uint64_t)(k>>16); lo=(uint32_t)(k&0xFFFF);
        }
    }
}
uint64_t present_enc(uint64_t s, const uint64_t rk[32]){
    int r,i;
    for(r=0;r<31;r++){
        s^=rk[r];
        uint64_t t=0;
        for(i=0;i<16;i++) t|=(uint64_t)SBOX[(s>>(4*i))&0xF]<<(4*i);
        uint64_t p=0;
        for(i=0;i<63;i++) p|=((t>>i)&1ULL)<<((16*i)%63);
        p|=((t>>63)&1ULL)<<63;
        s=p;
    }
    return s^rk[31];
}
#endif

/* ---------------- SPECK64/128 ---------------- */
#if !defined(SIZEBUILD) || defined(ONLY_SPECK)
void speck_ks(const uint32_t K[4], uint32_t rk[27]){ /* K = {K3,K2,K1,K0} msw first */
    uint32_t l[30]; int i;
    l[0]=K[2]; l[1]=K[1]; l[2]=K[0]; rk[0]=K[3];
    for(i=0;i<26;i++){
        l[i+3]=(rk[i]+ROTR32(l[i],8))^(uint32_t)i;
        rk[i+1]=ROTL32(rk[i],3)^l[i+3];
    }
}
void speck_enc(uint32_t *x, uint32_t *y, const uint32_t rk[27]){
    int i;
    for(i=0;i<27;i++){
        *x=(ROTR32(*x,8)+*y)^rk[i];
        *y=ROTL32(*y,3)^*x;
    }
}
#endif

/* ---------------- SIMON64/128 ---------------- */
#if !defined(SIZEBUILD) || defined(ONLY_SIMON)
static const uint64_t Z3=0x3C2CE51207A635DBULL; /* same integer as verified Python implementation */
void simon_ks(const uint32_t K[4], uint32_t rk[44]){
    int i;
    rk[0]=K[3]; rk[1]=K[2]; rk[2]=K[1]; rk[3]=K[0];
    for(i=4;i<44;i++){
        uint32_t t=ROTR32(rk[i-1],3)^rk[i-3];
        t^=ROTR32(t,1);
        rk[i]=~rk[i-4]^t^(uint32_t)((Z3>>((i-4)%62))&1)^3U;
    }
}
void simon_enc(uint32_t *x, uint32_t *y, const uint32_t rk[44]){
    int i;
    for(i=0;i<44;i++){
        uint32_t t=*x;
        *x=*y^(ROTL32(*x,1)&ROTL32(*x,8))^ROTL32(*x,2)^rk[i];
        *y=t;
    }
}
#endif

/* ---------------- TEA / XTEA ---------------- */
#if !defined(SIZEBUILD) || defined(ONLY_TEA)
void tea_enc(uint32_t *v0, uint32_t *v1, const uint32_t k[4]){
    uint32_t s=0, d=0x9E3779B9; int i;
    for(i=0;i<32;i++){
        s+=d;
        *v0 += ((*v1<<4)+k[0]) ^ (*v1+s) ^ ((*v1>>5)+k[1]);
        *v1 += ((*v0<<4)+k[2]) ^ (*v0+s) ^ ((*v0>>5)+k[3]);
    }
}
#endif
#if !defined(SIZEBUILD) || defined(ONLY_XTEA)
void xtea_enc(uint32_t *v0, uint32_t *v1, const uint32_t k[4]){
    uint32_t s=0, d=0x9E3779B9; int i;
    for(i=0;i<32;i++){
        *v0 += (((*v1<<4)^(*v1>>5))+*v1) ^ (s+k[s&3]);
        s+=d;
        *v1 += (((*v0<<4)^(*v0>>5))+*v0) ^ (s+k[(s>>11)&3]);
    }
}
#endif

#ifndef SIZEBUILD
/* ---------------- verification + benchmark ---------------- */
static int fail=0;
static void check(const char*n,int ok){ printf("%s: %s\n",n,ok?"PASS":"FAIL"); if(!ok)fail=1; }

typedef struct { double ns_blk, cyc_byte, mbit; } res_t;

static res_t bench64(void (*enc2)(uint32_t*,uint32_t*,const uint32_t*), const uint32_t*rk, long N){
    uint32_t x=0x12345678,y=0x9abcdef0; volatile uint32_t sink=0;
    struct timespec a,b; long i;
    /* warmup */
    for(i=0;i<10000;i++){ enc2(&x,&y,rk); }
    unsigned long long c0=__rdtsc();
    clock_gettime(CLOCK_MONOTONIC,&a);
    for(i=0;i<N;i++){ enc2(&x,&y,rk); }
    clock_gettime(CLOCK_MONOTONIC,&b);
    unsigned long long c1=__rdtsc();
    sink=x^y; (void)sink;
    double ns=(b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec);
    res_t r; r.ns_blk=ns/N; r.cyc_byte=(double)(c1-c0)/N/8.0; r.mbit=8.0*64.0/ (ns/N) *1e3/1e3; 
    r.mbit=64.0/(ns/N)*1000.0; /* bits per ns *1e9 /1e6 = *1000 => Mbit/s */
    return r;
}

int main(void){
    long N=2000000;
    /* --- vectors --- */
    { uint8_t k[10]={0}; uint64_t rk[32]; present_ks(k,rk);
      check("PRESENT-80", present_enc(0,rk)==0x5579C1387B228445ULL); }
    uint32_t K[4]={0x1b1a1918,0x13121110,0x0b0a0908,0x03020100};
    uint32_t spk[27]; speck_ks(K,spk);
    { uint32_t x=0x3b726574,y=0x7475432d; speck_enc(&x,&y,spk);
      check("SPECK64/128", x==0x8c6fa548 && y==0x454e028b); }
    uint32_t sik[44]; simon_ks(K,sik);
    { uint32_t x=0x656b696c,y=0x20646e75; simon_enc(&x,&y,sik);
      check("SIMON64/128", x==0x44c8fc20 && y==0xb9dfa07a); }
    { uint32_t v0=0,v1=0,k4[4]={0,0,0,0}; tea_enc(&v0,&v1,k4);
      check("TEA", v0==0x41ea3a0a && v1==0x94baa940); }
    { uint32_t v0=0x41424344,v1=0x45464748,
        k4[4]={0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f}; xtea_enc(&v0,&v1,k4);
      check("XTEA", v0==0x497df3d0 && v1==0x72612cb5); }
    if(fail){ puts("VECTOR FAILURE"); return 1; }

    /* --- benchmarks --- */
    printf("BENCH_START\n");
    { /* PRESENT via wrapper on 64-bit state */
      uint8_t k[10]={1,2,3,4,5,6,7,8,9,10}; uint64_t rk[32]; present_ks(k,rk);
      volatile uint64_t sink=0; uint64_t s=0x0123456789abcdefULL; long i;
      for(i=0;i<10000;i++) s=present_enc(s,rk);
      struct timespec a,b; unsigned long long c0=__rdtsc();
      clock_gettime(CLOCK_MONOTONIC,&a);
      long Np=N/4; /* PRESENT slower */
      for(i=0;i<Np;i++) s=present_enc(s,rk);
      clock_gettime(CLOCK_MONOTONIC,&b);
      unsigned long long c1=__rdtsc(); sink=s;(void)sink;
      double ns=((b.tv_sec-a.tv_sec)*1e9+(b.tv_nsec-a.tv_nsec))/Np;
      printf("PRESENT-80 %.2f %.1f %.1f 256\n", ns, (double)(c1-c0)/Np/8.0, 64.0/ns*1000.0);
    }
    { uint32_t rk[27]; speck_ks(K,rk); res_t r=bench64(speck_enc,rk,N);
      printf("SPECK64/128 %.2f %.1f %.1f 108\n", r.ns_blk, r.cyc_byte, r.mbit); }
    { uint32_t rk[44]; simon_ks(K,rk); res_t r=bench64(simon_enc,rk,N);
      printf("SIMON64/128 %.2f %.1f %.1f 176\n", r.ns_blk, r.cyc_byte, r.mbit); }
    { uint32_t k4[4]={1,2,3,4};
      res_t r=bench64((void(*)(uint32_t*,uint32_t*,const uint32_t*))tea_enc,k4,N);
      printf("TEA %.2f %.1f %.1f 16\n", r.ns_blk, r.cyc_byte, r.mbit); }
    { uint32_t k4[4]={1,2,3,4};
      res_t r=bench64((void(*)(uint32_t*,uint32_t*,const uint32_t*))xtea_enc,k4,N);
      printf("XTEA %.2f %.1f %.1f 16\n", r.ns_blk, r.cyc_byte, r.mbit); }
    return 0;
}
#endif
