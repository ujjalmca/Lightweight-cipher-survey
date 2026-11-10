#include <stdint.h>
#include <string.h>
static const uint8_t SBOX[16]={0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2};
/* PRESENT-80 key schedule without __int128: key register as hi(16)|lo(64) = 80 bits */
void present_ks(const uint8_t key[10], uint64_t rk[32]){
    /* load: key[0] is most significant byte -> k79..k72 */
    uint64_t lo=0; uint16_t hi=0;
    /* build 80-bit value: hi = top 16 bits, lo = bottom 64 bits */
    hi=((uint16_t)key[0]<<8)|key[1];
    for(int i=2;i<10;i++) lo=(lo<<8)|key[i];
    for(int r=0;r<32;r++){
        rk[r]=((uint64_t)hi<<48)|(lo>>16); /* top 64 bits of the 80-bit register */
        /* rotate left by 61 over 80 bits == rotate right by 19 */
        /* full 80-bit value V = (hi<<64)|lo. Rotate left 61. */
        /* newV = (V<<61 | V>>19) mod 2^80 */
        /* compute via pieces */
        uint64_t lo_new = (lo<<61) | ((uint64_t)hi<<45) | (lo>>19);
        uint16_t hi_new = (uint16_t)(((lo>>3)) & 0xFFFF);
        lo=lo_new; hi=hi_new & 0xFFFF;
        /* sbox top nibble (bits 79..76) */
        uint8_t top=(hi>>12)&0xF;
        hi=(hi&0x0FFF)|((uint16_t)SBOX[top]<<12);
        /* xor round counter (r+1) into bits 19..15 */
        uint8_t rc=(uint8_t)(r+1);
        lo ^= ((uint64_t)rc)<<15;
    }
    return;
}
uint64_t present_enc(uint64_t s, const uint64_t rk[32]){
    for(int r=0;r<31;r++){
        s^=rk[r];
        uint64_t t=0; int i;
        for(i=0;i<16;i++) t|=(uint64_t)SBOX[(s>>(4*i))&0xF]<<(4*i);
        uint64_t p=0;
        for(i=0;i<63;i++) p|=((t>>i)&1ULL)<<((16*i)%63);
        p|=((t>>63)&1ULL)<<63;
        s=p;
    }
    return s^rk[31];
}
#ifdef TEST_MAIN
#include <stdio.h>
int main(){uint8_t k[10]={0};uint64_t rk[32];present_ks(k,rk);
printf("PRESENT-80: %016llx (exp 5579c1387b228445)\n",(unsigned long long)present_enc(0,rk));return 0;}
#endif
