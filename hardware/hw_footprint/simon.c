#include <stdint.h>
#include <string.h>
#define ROTL32(x,r) (((x)<<(r))|((x)>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r))|((x)<<(32-(r))))
static const uint64_t Z3=0x3C2CE51207A635DBULL;
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
