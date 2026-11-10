#include <stdint.h>
#include <string.h>
void xtea_enc(uint32_t *v0, uint32_t *v1, const uint32_t k[4]){
    uint32_t s=0, d=0x9E3779B9; int i;
    for(i=0;i<32;i++){
        *v0 += (((*v1<<4)^(*v1>>5))+*v1) ^ (s+k[s&3]);
        s+=d;
        *v1 += (((*v0<<4)^(*v0>>5))+*v0) ^ (s+k[(s>>11)&3]);
    }
}
