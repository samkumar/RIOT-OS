/*
 * Copyright (C) 2017 Sam Kumar
 * Copyright (C) 2017 University of California, Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

#include <stdint.h>
#include "cpu.h"

#include "periph/dmac.h"
#include "periph_conf.h"
#include "pm_layered.h"
#define ENABLE_DEBUG    (0)
#include "debug.h"

/* Guard in case no DMAC is defined */
#if DMAC_NUMOF

/* Transfer descriptor sections. */
volatile DmacDescriptor descriptor_section[DMAC_EN_CHANNELS] __attribute__((aligned(16)));
volatile DmacDescriptor writeback_section[DMAC_EN_CHANNELS] __attribute__((aligned(16)));

/* DMA channel callbacks. */
typedef struct {
    dma_callback_t callback;
    void* arg;
} dma_callback_entry_t;

dma_callback_entry_t channel_callbacks[DMAC_EN_CHANNELS];

/* DMA Controller Configuration */

void dmac_init(void) {
    dmac_disable();
    dmac_reset();
    dmac_configure();
    dmac_enable();
}

void dmac_enable(void) {
    /* Turn on power manager for DMAC */
    PM->APBBMASK.reg |= PM_APBBMASK_DMAC;
    PM->AHBMASK.reg |= PM_AHBMASK_DMAC;

    NVIC_EnableIRQ(DMAC_IRQ);
    DMAC_DEV->CTRL.reg = 0x0F02;
}

void dmac_disable(void) {
    DMAC_DEV->CTRL.reg = 0x0000;
    NVIC_DisableIRQ(DMAC_IRQ);

    /* Turn off power management for DMA. */
    //PM->APBBMASK.reg &= ~PM_APBBMASK_DMAC;
    //PM->AHBMASK.reg &= ~PM_AHBMASK_DMAC;
}

void dmac_reset(void) {
    DMAC_DEV->CTRL.reg = 0x0001;
}

void dmac_configure(void) {
    DMAC_DEV->BASEADDR.reg = (uint32_t) &descriptor_section[0];
    DMAC_DEV->WRBADDR.reg = (uint32_t) &writeback_section[0];
    DMAC_DEV->DBGCTRL.reg = 0x01;
}

/* DMA Channel Configuration */

void dma_channel_register_callback(dma_channel_t channel, dma_callback_t callback, void* arg) {
    dma_callback_entry_t* entry = &channel_callbacks[channel];
    entry->callback = callback;
    entry->arg = arg;
}

void dma_channel_set_current(dma_channel_t channel) {
    DMAC_DEV->CHID.reg = channel & 0x0F;
}

void dma_channel_enable_current(void) {
    //pm_block(0);
    DMAC_DEV->CHINTENSET.reg = 0x07;
    DMAC_DEV->CHCTRLA.reg = 0x02;
}

void dma_channel_disable_current(void) {
    DMAC_DEV->CHCTRLA.reg = 0x00;
    DMAC_DEV->CHINTENCLR.reg = 0x07;
    //pm_unblock(0);
}

void dma_channel_reset_current(void) {
    DMAC_DEV->CHCTRLA.reg = 0x01;
}

void dma_channel_configure_periph_current(dma_channel_periph_config_t* config) {
    uint32_t chctrlb_reg = (((uint32_t) (config->periph_src & 0x3F)) << 8);
    switch (config->on_trigger) {
    case DMAC_ACTION_BEAT:
        chctrlb_reg |= 0x00800000;
        break;
    case DMAC_ACTION_BLOCK:
        chctrlb_reg |= 0x00000000;
        break;
    case DMAC_ACTION_TRANSACTION:
        chctrlb_reg |= 0x00C00000;
        break;
    }
    DMAC_DEV->CHCTRLB.reg = chctrlb_reg;
}

void dma_channel_configure_memory(dma_channel_t channel, dma_channel_memory_config_t* config) {
    volatile DmacDescriptor* desc = &descriptor_section[channel];
    uint16_t btctrl_reg = 0x0009; // interrupt at end of block, and valid bit
    switch (config->beatsize) {
    case DMAC_BEATSIZE_BYTE:
        btctrl_reg |= 0x0000;
        break;
    case DMAC_BEATSIZE_HALFWORD:
        btctrl_reg |= 0x0100;
        break;
    case DMAC_BEATSIZE_WORD:
        btctrl_reg |= 0x0200;
        break;
    }
    desc->BTCTRL.reg = btctrl_reg;
    desc->BTCNT.reg = config->num_beats;
    desc->SRCADDR.reg = (uint32_t) config->source;
    desc->DSTADDR.reg = (uint32_t) config->destination;
    desc->DESCADDR.reg = 0x00000000; // Don't handle linked descriptors
}

void DMAC_ISR(void) {
    uint32_t intstatus = DMAC_DEV->INTSTATUS.reg;

    dma_channel_t channel = 0;
    while (intstatus != 0) {
        uint32_t pending = intstatus & 0x00000001;
        if (pending != 0) {
            assert(channel < DMAC_EN_CHANNELS);

            int error;

            // Get the reason (finished, or error)
            uint8_t reason = DMAC_DEV->CHINTFLAG.reg;
            if ((reason & 0x01) == 0x01)  {
                error = 1;
            } else {
                error = 0;
                assert((reason & 0x02) == 0x02);
            }

            // Clear the interrupt
            DMAC_DEV->CHINTFLAG.reg = 0x07;

            dma_callback_entry_t* entry = &channel_callbacks[channel];
            entry->callback(entry->arg, error);
        }

        intstatus >>= 1;
        channel++;
    }

    cortexm_isr_end();
}

#endif /* DMAC_NUMOF */
