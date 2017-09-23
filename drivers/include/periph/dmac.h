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
#ifndef DMA_CHANNEL_UNDEF
#define DMA_CHANNEL_UNDEF   (UINT_MAX)
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

typedef void (*dma_callback_t)(void*, int);

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

typedef enum {
    DMAC_STEPSIZE_X1 = 0x0,
    DMAC_STEPSIZE_X2 = 0x1,
    DMAC_STEPSIZE_X4 = 0x2,
    DMAC_STEPSIZE_X8 = 0x3,
    DMAC_STEPSIZE_X16 = 0x4,
    DMAC_STEPSIZE_X32 = 0x5,
    DMAC_STEPSIZE_X64 = 0x6,
    DMAC_STEPSIZE_X128 = 0x7
} dmac_stepsize_t;

typedef enum {
    DMAC_STEPSEL_SRC = 0x0,
    DMAC_STEPSEL_DST = 0x1
} dmac_stepsel_t;

struct dma_channel_linked_block_;
typedef struct dma_channel_linked_block_ dma_channel_linked_block_t;

typedef struct {
    const volatile void* source;
    volatile void* destination;
    dmac_beatsize_t beatsize;
    uint16_t num_beats;

    dmac_stepsize_t stepsize;
    dmac_stepsel_t stepsel;
    bool increment_source;
    bool increment_destination;

    dma_channel_linked_block_t* next_block;
} dma_channel_memory_config_t;

typedef struct dma_channel_linked_block_ {
    volatile uint8_t descriptor_blob[16] __attribute__((aligned(16)));
    dma_channel_memory_config_t config;
} dma_channel_linked_block_t;

typedef struct {
    dmac_action_t on_trigger;
    uint8_t periph_src;
} dma_channel_periph_config_t;

void dmac_init(void);

void dmac_enable(void);
void dmac_disable(void);
void dmac_reset(void);
void dmac_configure(void);

void dma_channel_register_callback(dma_channel_t channel, dma_callback_t callback, void* arg);
void dma_channel_set_current(dma_channel_t channel);
void dma_channel_enable_current(void);
void dma_channel_disable_current(void);
void dma_channel_reset_current(void);
void dma_channel_configure_periph_current(dma_channel_periph_config_t* config);
void dma_channel_create_descriptor(volatile void* descriptor, dma_channel_memory_config_t* config);
void dma_channel_configure_memory(dma_channel_t channel, dma_channel_memory_config_t* config);
volatile void* dma_channel_get_descriptor_address(dma_channel_t channel);

#ifdef __cplusplus
}
#endif

#endif /* PERIPH_ADC_H */
/** @} */
