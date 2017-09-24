/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @ingroup     cpu_samr21
 * @{
 *
 * @file
 * @brief       ADC driver implementation
 *
 * @author      Michael Andersen <m.andersen@berkeley.edu>
 * @author      Hyung-Sin Kim <hs.kim@berkeley.edu>
 * @author      Sam Kumar <samkumar@berkeley.edu>
 * @author      Rane Balslev (SAMR21) <ranebalslev@gmail.com>
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 * @author      Mark Solters <msolters@driblet.io>
 *
 * @}
 */

#include <stdint.h>
#include "cpu.h"

#include "mutex.h"
#include "periph/adc.h"
#include "periph/dmac.h"
#include "periph_conf.h"
#define ENABLE_DEBUG    (0)
#include "debug.h"

/* guard in case that no ADC device is defined */
#if ADC_NUMOF

int adc_init(adc_t channel) {

    /*  Disable ADC Module before init. */
    ADC_DEV->CTRLA.bit.ENABLE = 0;

    /* Setup generic clock mask for adc */
    PM->APBCMASK.reg |= PM_APBCMASK_ADC;

    /* GCLK Setup*/
    GCLK->CLKCTRL.reg = (uint32_t)(GCLK_CLKCTRL_CLKEN     |
                                   GCLK_CLKCTRL_GEN_GCLK0 |
                                  (ADC_GCLK_ID << GCLK_CLKCTRL_ID_Pos));

    ADC_DEV->CTRLA.bit.SWRST = 1;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    uint32_t bias = (*((uint32_t *) ADC_FUSES_BIASCAL_ADDR) & ADC_FUSES_BIASCAL_Msk) >> ADC_FUSES_BIASCAL_Pos;
    uint32_t linearity = (*((uint32_t *) ADC_FUSES_LINEARITY_0_ADDR) & ADC_FUSES_LINEARITY_0_Msk) >> ADC_FUSES_LINEARITY_0_Pos;
    linearity |= ((*((uint32_t *) ADC_FUSES_LINEARITY_1_ADDR) & ADC_FUSES_LINEARITY_1_Msk) >> ADC_FUSES_LINEARITY_1_Pos) << 5;

    ADC_DEV->CALIB.reg = ADC_CALIB_BIAS_CAL(bias) | ADC_CALIB_LINEARITY_CAL(linearity);

    /* Set RUN_IN_STANDBY */
    ADC_DEV->CTRLA.bit.RUNSTDBY = 0;

    /* Set Voltage Reference */
    ADC_DEV->REFCTRL.bit.REFSEL  = ADC_REFCTRL_REFSEL_INT1V_Val;
    ADC_DEV->REFCTRL.bit.REFCOMP = 1;

    /* Set the accumulation and divide result */
    ADC_DEV->AVGCTRL.bit.SAMPLENUM = 4;
    ADC_DEV->AVGCTRL.bit.ADJRES    = 0;//ADC_AVGCTRL_ADJRES(divideResult) | accumulate;

    /* Set Sample length */
    ADC_DEV->SAMPCTRL.bit.SAMPLEN = 16;//ADC_SAMPCTRL_SAMPLEN(ADC_0_SAMPLE_LENGTH);
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /* Configure CTRLB Register HERE IS THE RESOLUTION SET!*/
    ADC_DEV->CTRLB.bit.DIFFMODE  = 0;
    ADC_DEV->CTRLB.bit.FREERUN   = 0;
    ADC_DEV->CTRLB.bit.CORREN    = 0;
    ADC_DEV->CTRLB.bit.LEFTADJ   = 0; // Left-adjusted results
    ADC_DEV->CTRLB.bit.RESSEL    = ADC_CTRLB_RESSEL_12BIT_Val;
    ADC_DEV->CTRLB.bit.PRESCALER = ADC_CTRLB_PRESCALER_DIV128_Val;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    ADC_DEV->INPUTCTRL.bit.GAIN        = ADC_INPUTCTRL_GAIN_1X_Val;
    ADC_DEV->INPUTCTRL.bit.INPUTOFFSET = 0;

    /* Port configuration */
    PM->APBBMASK.reg |= PM_APBBMASK_PORT;

    int pin = ADC_GET_PIN(channel);
    PortGroup* pg = ADC_GET_PORT_GROUP(channel);

    pg->DIRCLR.reg = (1 << pin);
    pg->PINCFG[pin].bit.INEN = 1;
    pg->PINCFG[pin].bit.PMUXEN = 1;
    pg->PMUX[pin >> 1].reg &= ~(0xf << (4 * (pin & 0x1)));
    pg->PMUX[pin >> 1].reg |= (PORT_PMUX_PMUXE_B_Val << (4 * (pin & 0x1)));

    ADC_DEV->INPUTCTRL.bit.MUXNEG      = ADC_INPUTCTRL_MUXNEG_IOGND_Val;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /* Configure Window Mode Register */
    ADC_DEV->WINCTRL.reg = ADC_WINCTRL_WINMODE_DISABLE;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /* Enable interrupts and events related to result */
    ADC_DEV->EVCTRL.bit.RESRDYEO = 1;
    ADC_DEV->INTENSET.bit.RESRDY = 1;

    /* ADC runs during debug mode */
    ADC_DEV->DBGCTRL.bit.DBGRUN = 1;

    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    return 0;
}

int adc_sample_start(adc_t channel, adc_res_t res) {
    /* Set input channel for ADC */
    int chan = ADC_GET_CHANNEL(channel);
    ADC_DEV->INPUTCTRL.bit.MUXPOS = chan;

    /*  Enable bandgap */
    SYSCTRL->VREF.reg |= SYSCTRL_VREF_BGOUTEN;

    /* Set resolution */
    switch (res) {
        case ADC_RES_8BIT:
            ADC_DEV->CTRLB.bit.RESSEL = ADC_CTRLB_RESSEL_8BIT_Val;
            break;
        case ADC_RES_10BIT:
            ADC_DEV->CTRLB.bit.RESSEL = ADC_CTRLB_RESSEL_10BIT_Val;
            break;
        case ADC_RES_12BIT:
            ADC_DEV->CTRLB.bit.RESSEL = ADC_CTRLB_RESSEL_12BIT_Val;
            break;
        case ADC_RES_16BIT:
            ADC_DEV->CTRLB.bit.RESSEL = ADC_CTRLB_RESSEL_16BIT_Val;
            break;
        default:
            return -1;
            break;
    }

    /* Wait for sync. */
    while (ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /* Enable ADC Module. */
    ADC_DEV->CTRLA.bit.ENABLE = 1;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /* Start the conversion. */
    ADC_DEV->SWTRIG.reg = ADC_SWTRIG_START;

    return 0;
}

void adc_sample_wait(void) {
    /* Wait for the result. */
    while (!(ADC_DEV->INTFLAG.reg & ADC_INTFLAG_RESRDY));
}

int adc_sample_read(void) {
    /* Read result */
    int output = (int) ADC_DEV->RESULT.reg;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);
    return output;
}

void adc_sample_end(void) {
    ADC_DEV->CTRLA.bit.ENABLE = 0;
    while(ADC_DEV->STATUS.reg & ADC_STATUS_SYNCBUSY);

    /*  Disable bandgap */
    SYSCTRL->VREF.reg &= ~SYSCTRL_VREF_BGOUTEN;
}


int adc_sample_without_dma(adc_t channel, adc_res_t res) {
    int error = adc_sample_start(channel, res);
    if (error != 0) {
        return error;
    }
    adc_sample_wait();
    int output = adc_sample_read();
    adc_sample_end();
    return output;
}

struct adc_dma_waiter {
    mutex_t waiter;
    volatile int error;
};

void adc_dma_unblock(void* arg, int error) {
    struct adc_dma_waiter* waiter = arg;
    waiter->error = error;
    mutex_unlock(&waiter->waiter);
}

void adc_configure_dma_channel(dma_channel_t channel) {
    dma_channel_set_current(channel);
    dma_channel_reset_current();

    dma_channel_periph_config_t periph_config;
    periph_config.on_trigger = DMAC_ACTION_TRANSACTION;
    periph_config.periph_src = 0x27; // this is the ADC
    dma_channel_configure_periph_current(&periph_config);
}

int adc_sample_with_dma(adc_t adc_channel, adc_res_t res, dma_channel_t dma_channel) {
    volatile uint16_t result;

    dma_channel_memory_config_t memory_config;
    memory_config.source = (volatile void*) &ADC_DEV->RESULT.reg;
    memory_config.destination = &result;
    memory_config.beatsize = DMAC_BEATSIZE_HALFWORD;
    memory_config.num_beats = 1;
    memory_config.stepsize = DMAC_STEPSIZE_X1;
    memory_config.stepsel = DMAC_STEPSEL_SRC;
    memory_config.increment_source = false;
    memory_config.increment_destination = false;
    memory_config.next_block = NULL;
    dma_channel_configure_memory(dma_channel, &memory_config);

    struct adc_dma_waiter waiter;
    mutex_init(&waiter.waiter);
    waiter.error = 0;
    dma_channel_register_callback(dma_channel, adc_dma_unblock, &waiter);

    dma_channel_set_current(dma_channel);
    dma_channel_enable_current();

    /* Set RUN_IN_STANDBY */
    ADC_DEV->CTRLA.bit.RUNSTDBY = 0;

    int start_error = adc_sample_start(adc_channel, res);
    if (start_error != 0) {
        ADC_DEV->CTRLA.bit.RUNSTDBY = 0;
        dma_channel_disable_current();
        return start_error;
    }

    mutex_lock(&waiter.waiter);
    mutex_lock(&waiter.waiter);

    // Thread blocks here until result is ready

    /* Turn off RUN_IN_STANDBY to save power */
    ADC_DEV->CTRLA.bit.RUNSTDBY = 0;

    dma_channel_set_current(dma_channel);
    dma_channel_disable_current();
    adc_sample_end();
    mutex_unlock(&waiter.waiter);

    if (waiter.error != 0) {
        return waiter.error;
    }

    return (int) result;
}

dma_channel_t default_dma_channel = DMA_CHANNEL_UNDEF;

int adc_sample(adc_t channel, adc_res_t res) {
    if (default_dma_channel == DMA_CHANNEL_UNDEF || irq_is_in()) {
        return adc_sample_without_dma(channel, res);
    }

    return adc_sample_with_dma(channel, res, default_dma_channel);
}

void adc_set_dma_channel(dma_channel_t channel) {
    if (channel != DMA_CHANNEL_UNDEF) {
        adc_configure_dma_channel(channel);
    }

    default_dma_channel = channel;
}

#endif /* ADC_NUMOF */
