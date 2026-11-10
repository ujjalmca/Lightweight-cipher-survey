#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simavr/sim_avr.h"
#include "simavr/sim_elf.h"
#include "simavr/avr_ioport.h"

static uint64_t start_cycle=0, done_cycle=0;
static int started=0, done=0;
static avr_t *g_avr=NULL;

static void portb_hook(struct avr_irq_t *irq, uint32_t value, void *param){
    if(value==0x01 && !started){ started=1; start_cycle=g_avr->cycle; }
    else if(value==0x2A && !done){ done=1; done_cycle=g_avr->cycle; }
}
int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: host <elf>\n");return 1;}
    elf_firmware_t fw; memset(&fw,0,sizeof(fw));
    if(elf_read_firmware(argv[1],&fw)){fprintf(stderr,"elf read fail\n");return 1;}
    avr_t*avr=avr_make_mcu_by_name("atmega328p");
    if(!avr){fprintf(stderr,"mcu fail\n");return 1;}
    avr_init(avr); g_avr=avr;
    avr_load_firmware(avr,&fw);
    avr->frequency=16000000;
    // hook PORTB output register writes
    avr_irq_register_notify(
        avr_io_getirq(avr,AVR_IOCTL_IOPORT_GETIRQ('B'),IOPORT_IRQ_REG_PORT),
        portb_hook,NULL);
    int state=cpu_Running; long guard=0;
    while(state!=cpu_Done && state!=cpu_Crashed && !done && guard<200000000){
        state=avr_run(avr); guard++;
    }
    if(done && started) printf("%llu\n",(unsigned long long)(done_cycle-start_cycle));
    else printf("ERR started=%d done=%d\n",started,done);
    return 0;
}
