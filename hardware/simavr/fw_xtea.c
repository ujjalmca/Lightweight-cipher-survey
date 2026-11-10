#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include "xtea_core.h"
volatile uint64_t sink; volatile uint32_t sink32;
int main(void){
    DDRB=0xFF; PORTB=0x01;
    
    uint32_t k[4]={0,0,0,0},v0=0,v1=0;
    for(uint8_t i=0;i<100;i++){xtea_enc(&v0,&v1,k);} sink32=v0^v1;
    PORTB=0x2A; while(1){} return 0;
}
