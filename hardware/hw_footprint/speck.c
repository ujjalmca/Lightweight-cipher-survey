#include <stdint.h>
#include <string.h>
#define ROTL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r))|((x)<<(32-(r))))
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
