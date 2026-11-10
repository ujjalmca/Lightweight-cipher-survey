#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include "present_core.h"
volatile uint64_t sink; volatile uint32_t sink32;
int main(void){
    DDRB=0xFF; PORTB=0x01;
    
    uint8_t k[10]={0}; uint64_t rk[32]; present_ks(k,rk);
    uint64_t s=0x0123456789abcdefULL;
    for(uint8_t i=0;i<100;i++){s=present_enc(s,rk);} sink=s;
    PORTB=0x2A; while(1){} return 0;
}
