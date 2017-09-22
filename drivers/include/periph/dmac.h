/*
 * Copyright (C) 2017 Sam Kumar
 * Copyright (C) 2017 University of California, Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef PERIPH_DMAC_H
#define PERIPH_DMAC_H

#include <limits.h>

#include "periph_cpu.h"
#include "periph_conf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Define default DMAC channel type identifier
 * @{
 */
#ifndef HAVE_DMAC_T
typedef unsigned int dma_channel_t;
#endif
/** @} */

/**
 * @brief   Default DMA channel; undefined value
 * @{
 */
#ifndef DMAC_UNDEF
#define DMAC_UNDEF          (UINT_MAX)
#endif
/** @} */

/**
 * @brief   Default DMAC channel access macro (zero-indexed)
 * @{
 */
#ifndef DMA_CHANNEL
#define DMA_CHANNEL(x)     (x)
#endif
/** @} */

typedef void (*dma_callback_t)(int);

typedef enum {
    DMAC_BEATSIZE_BYTE = 0,
    DMAC_BEATSIZE_HALFWORD,
    DMAC_BEATSIZE_WORD,
} dmac_beatsize_t;

typedef enum {
    DMAC_ACTION_BLOCK = 0,
    DMAC_ACTION_BEAT,
    DMAC_ACTION_TRANSACTION
} dmac_action_t;

typedef struct {
    volatile void* source;
    volatile void* destination;
    dmac_beatsize_t beatsize;
    uint16_t num_beats;
} dma_channel_memory_config_t;

typedef struct {
    dmac_action_t on_trigger;
    uint8_t periph_src;
} dma_channel_periph_config_t;


void dmac_enable(void);
void dmac_disable(void);
void dmac_reset(void);
void dmac_configure(void);

void dma_channel_register_callback(dma_channel_t channel, dma_callback_t callback);
void dma_channel_set_current(dma_channel_t channel);
void dma_channel_enable_current(void);
void dma_channel_disable_current(void);
void dma_channel_reset_current(void);
void dma_channel_configure_periph_current(dma_channel_periph_config_t* config);
void dma_channel_configure_memory(dma_channel_t channel, dma_channel_memory_config_t* config);

#ifdef __cplusplus
}
#endif

#endif /* PERIPH_ADC_H */
/** @} */
