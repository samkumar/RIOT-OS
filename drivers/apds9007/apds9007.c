/*
 * Copyright (C) 2017 Hyung-Sin Kim
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 */

/**
 * @ingroup     drivers_apds9007
 * @{
 *
 * @file
 * @brief       Driver for the APDS9007 Light Sensor.
 *
 * @author      Hyung-Sin Kim <hs.kim@berkeley.edu>
 *
 * @}
 */

#include <string.h>

#include "apds9007.h"
#include "mutex.h"
#include "xtimer.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"


int apds9007_set_active(apds9007_t *dev) {
    gpio_write(dev->p.gpio, 0);
    return 0;
}

int apds9007_set_idle(apds9007_t *dev) {
    gpio_write(dev->p.gpio, 1);
    return 0;
}

int apds9007_init(apds9007_t *dev, const apds9007_params_t *params) {
    dev->p.gpio = params->gpio;
    dev->p.adc  = params->adc;
    dev->p.res  = params->res;
    gpio_init(params->gpio, GPIO_OUT);
    adc_init(params->adc);
    apds9007_set_idle(dev);
    return 0;
}

int apds9007_read(apds9007_t *dev, int16_t *light) {
    apds9007_set_active(dev);
    xtimer_usleep(APDS9007_STABILIZATION_TIME);
    *light = (int16_t) adc_sample(dev->p.adc, dev->p.res);
    apds9007_set_idle(dev);
    return 0;
}

mutex_t block_dma_thread = MUTEX_INIT;

void unblock_dma_thread(int error) {
    (void) error;
    mutex_unlock(&block_dma_thread);
}

int apds9007_read_dma(apds9007_t* dev, int16_t* light, dma_channel_t channel) {
    mutex_lock(&block_dma_thread);

    dmac_disable();
    dmac_reset();
    dmac_configure();
    dmac_enable();

    dma_channel_register_callback(channel, unblock_dma_thread);

    dma_channel_set_current(channel);

    dma_channel_disable_current();
    dma_channel_reset_current();

    dma_channel_periph_config_t periph_config;
    periph_config.on_trigger = DMAC_ACTION_TRANSACTION;
    periph_config.periph_src = 0x27; // this is the ADC
    dma_channel_configure_periph_current(&periph_config);

    dma_channel_memory_config_t memory_config;
    memory_config.source = (volatile void*) &ADC_DEV->RESULT.reg;
    memory_config.destination = (volatile void*) light;
    memory_config.beatsize = DMAC_BEATSIZE_HALFWORD;
    memory_config.num_beats = 1;
    dma_channel_configure_memory(channel, &memory_config);

    dma_channel_enable_current();

    apds9007_set_active(dev);
    xtimer_usleep(APDS9007_STABILIZATION_TIME);
    adc_sample_start(dev->p.adc, dev->p.res);

    mutex_lock(&block_dma_thread);
    // Thread blocks here until DMA is completed

    adc_sample_end();
    apds9007_set_idle(dev);

    mutex_unlock(&block_dma_thread);
    return 0;
}
