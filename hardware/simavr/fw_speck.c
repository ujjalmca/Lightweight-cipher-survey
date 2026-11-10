#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include "speck_core.h"
volatile uint64_t sink; volatile uint32_t sink32;
int main(void){
    DDRB=0xFF; PORTB=0x01;
    
    uint32_t K[4]={0x1b1a1918,0x13121110,0x0b0a0908,0x03020100},rk[27]; speck_ks(K,rk);
    uint32_t x=0x3b726574,y=0x7475432d;
    for(uint8_t i=0;i<100;i++){speck_enc(&x,&y,rk);} sink32=x^y;
    PORTB=0x2A; while(1){} return 0;
}
