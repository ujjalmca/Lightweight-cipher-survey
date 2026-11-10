#include <stdint.h>
#include <string.h>
void tea_enc(uint32_t *v0, uint32_t *v1, const uint32_t k[4]){
    uint32_t s=0, d=0x9E3779B9; int i;
    for(i=0;i<32;i++){
        s+=d;
        *v0 += ((*v1<<4)+k[0]) ^ (*v1+s) ^ ((*v1>>5)+k[1]);
        *v1 += ((*v0<<4)+k[2]) ^ (*v0+s) ^ ((*v0>>5)+k[3]);
    }
}
