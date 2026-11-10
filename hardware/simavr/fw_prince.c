#include <stdint.h>
#include <string.h>
#include <avr/io.h>
#include "prince_core.h"
volatile uint64_t sink; volatile uint32_t sink32;
int main(void){
    DDRB=0xFF; PORTB=0x01;
    
    uint64_t pt=0x0123456789abcdefULL,c=0;
    for(uint8_t i=0;i<100;i++){c=prince_enc(pt,0,0);pt=c;} sink=c;
    PORTB=0x2A; while(1){} return 0;
}
