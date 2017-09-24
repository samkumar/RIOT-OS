/*
 * Copyright (C) 2014-2016 Freie Universität Berlin
 *               2015 Kaspar Schleiser <kaspar@schleiser.de>
 *               2015 FreshTemp, LLC.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_sam0_common
 * @ingroup     drivers_periph_spi
 * @{
 *
 * @file
 * @brief       Low-level SPI driver implementation
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 * @author      Thomas Eichinger <thomas.eichinger@fu-berlin.de>
 * @author      Troels Hoffmeyer <troels.d.hoffmeyer@gmail.com>
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 * @author      Joakim Nohlgård <joakim.nohlgard@eistec.se>
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 *
 * @}
 */

#include "cpu.h"
#include "mutex.h"
#include "assert.h"
#include "periph/dmac.h"
#include "periph/spi.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

typedef struct {
    mutex_t lock;
    dma_channel_t read_dma_channel;
    dma_channel_t write_dma_channel;
} spi_state_t;

/**
 * @brief Array holding one pre-initialized mutex for each SPI device, and the
 *        default DMA channels for that device.
 */
static spi_state_t spi_state[SPI_NUMOF];

/**
 * @brief   Shortcut for accessing the used SPI SERCOM device
 */
static inline SercomSpi *dev(spi_t bus)
{
    return spi_config[bus].dev;
}

static inline void poweron(spi_t bus)
{
#if defined(CPU_FAM_SAMD21)
    PM->APBCMASK.reg |= (PM_APBCMASK_SERCOM0 << sercom_id(dev(bus)));
#elif defined(CPU_FAM_SAML21)
    MCLK->APBCMASK.reg |= (MCLK_APBCMASK_SERCOM0 << sercom_id(dev(bus)));
#endif
}

static inline void poweroff(spi_t bus)
{
#if defined(CPU_FAM_SAMD21)
    PM->APBCMASK.reg &= ~(PM_APBCMASK_SERCOM0 << sercom_id(dev(bus)));
#elif defined(CPU_FAM_SAML21)
    MCLK->APBCMASK.reg &= ~(MCLK_APBCMASK_SERCOM0 << sercom_id(dev(bus)));
#endif
}

void spi_init(spi_t bus)
{
    /* make sure given bus is good */
    assert(bus < SPI_NUMOF);

    /* initialize the device state */
    mutex_init(&spi_state[bus].lock);
    spi_state[bus].read_dma_channel = DMA_CHANNEL_UNDEF;
    spi_state[bus].write_dma_channel = DMA_CHANNEL_UNDEF;

    /* configure pins and their muxes */
    spi_init_pins(bus);

    /* wake up device */
    poweron(bus);

    /* reset all device configuration */
    dev(bus)->CTRLA.reg |= SERCOM_SPI_CTRLA_SWRST;
    while ((dev(bus)->CTRLA.reg & SERCOM_SPI_CTRLA_SWRST) ||
           (dev(bus)->SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_SWRST));

    /* configure base clock: using GLK GEN 0 */
#if defined(CPU_FAM_SAMD21)
    GCLK->CLKCTRL.reg = (GCLK_CLKCTRL_CLKEN | GCLK_CLKCTRL_GEN_GCLK0 |
                         (SERCOM0_GCLK_ID_CORE + sercom_id(dev(bus))));
    while (GCLK->STATUS.reg & GCLK_STATUS_SYNCBUSY) {}
#elif defined(CPU_FAM_SAML21)
    GCLK->PCHCTRL[SERCOM0_GCLK_ID_CORE + sercom_id(dev(bus))].reg =
                                (GCLK_PCHCTRL_CHEN | GCLK_PCHCTRL_GEN_GCLK0);
#endif

    /* enable receiver and configure character size to 8-bit
     * no synchronization needed, as SERCOM device is not enabled */
    dev(bus)->CTRLB.reg = (SERCOM_SPI_CTRLB_CHSIZE(0) | SERCOM_SPI_CTRLB_RXEN);

    /* put device back to sleep */
    poweroff(bus);
}

void spi_init_pins(spi_t bus)
{
    /* MISO must always have PD/PU, see #5968. This is a ~65uA difference */
    gpio_init(spi_config[bus].miso_pin, GPIO_IN_PD);
    gpio_init(spi_config[bus].mosi_pin, GPIO_OUT);
    gpio_init(spi_config[bus].clk_pin, GPIO_OUT);
    gpio_init_mux(spi_config[bus].miso_pin, spi_config[bus].miso_mux);
    gpio_init_mux(spi_config[bus].mosi_pin, spi_config[bus].mosi_mux);
    gpio_init_mux(spi_config[bus].clk_pin, spi_config[bus].clk_mux);
}

int spi_acquire(spi_t bus, spi_cs_t cs, spi_mode_t mode, spi_clk_t clk)
{
    /* get exclusive access to the device */
    mutex_lock(&spi_state[bus].lock);
    /* power on the device */
    poweron(bus);

    /* disable the device */
    dev(bus)->CTRLA.reg &= ~(SERCOM_SPI_CTRLA_ENABLE);
    while (dev(bus)->SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_ENABLE) {}

    /* configure bus clock, in synchronous mode its calculated from
     * BAUD.reg = (f_ref / (2 * f_bus) - 1)
     * with f_ref := CLOCK_CORECLOCK as defined by the board */
    dev(bus)->BAUD.reg = (uint8_t)(((uint32_t)CLOCK_CORECLOCK) / (2 * clk) - 1);

    /* configure device to be master and set mode and pads,
     *
     * NOTE: we could configure the pads already during spi_init, but for
     * efficiency reason we do that here, so we can do all in one single write
     * to the CTRLA register */
    dev(bus)->CTRLA.reg = (SERCOM_SPI_CTRLA_MODE(0x3) |     /* 0x3 -> master */
                           SERCOM_SPI_CTRLA_DOPO(spi_config[bus].mosi_pad) |
                           SERCOM_SPI_CTRLA_DIPO(spi_config[bus].miso_pad) |
                           (mode <<  SERCOM_SPI_CTRLA_CPOL_Pos));
    /* also no synchronization needed here, as CTRLA is write-synchronized */

    /* finally enable the device */
    dev(bus)->CTRLA.reg |= SERCOM_SPI_CTRLA_ENABLE;
    while (dev(bus)->SYNCBUSY.reg & SERCOM_SPI_SYNCBUSY_ENABLE) {}

    return SPI_OK;
}

void spi_release(spi_t bus)
{
    /* release access to the device */
    mutex_unlock(&spi_state[bus].lock);
}

int spi_dma_transact(spi_t bus, const volatile void* out, volatile void* in, size_t len);

dma_channel_t spi_read_dma_channel = DMA_CHANNEL_UNDEF;
dma_channel_t spi_write_dma_channel = DMA_CHANNEL_UNDEF;

void spi_transfer_bytes(spi_t bus, spi_cs_t cs, bool cont,
                        const void *out, void *in, size_t len)
{
    const uint8_t *out_buf = out;
    uint8_t *in_buf = in;

    assert(out || in);

    if (cs != SPI_CS_UNDEF) {
        gpio_clear((gpio_t)cs);
    }

    if (spi_read_dma_channel == DMA_CHANNEL_UNDEF || irq_is_in()) {
        for (int i = 0; i < (int)len; i++) {
            uint8_t tmp = (out_buf) ? out_buf[i] : 0;
            while (!(dev(bus)->INTFLAG.reg & SERCOM_SPI_INTFLAG_DRE)) {}
            dev(bus)->DATA.reg = tmp;
            while (!(dev(bus)->INTFLAG.reg & SERCOM_SPI_INTFLAG_RXC)) {}
            tmp = (uint8_t)dev(bus)->DATA.reg;
            if (in_buf) {
                in_buf[i] = tmp;
            }
        }
    } else {
        spi_dma_transact(bus, out_buf, in_buf, len);
    }

    if ((!cont) && (cs != SPI_CS_UNDEF)) {
        gpio_set((gpio_t)cs);
    }
}

void spi_set_dma_channel(spi_t bus, dma_channel_t read_channel, dma_channel_t write_channel)
{
    if (read_channel != DMA_CHANNEL_UNDEF) {
        assert(write_channel != DMA_CHANNEL_UNDEF);
        assert(read_channel != write_channel);

        dma_channel_set_current(read_channel);
        dma_channel_reset_current();
        dma_channel_periph_config_t periph_config;
        periph_config.on_trigger = DMAC_ACTION_BEAT;
        periph_config.periph_src = 0x09;
        dma_channel_configure_periph_current(&periph_config);

        dma_channel_set_current(write_channel);
        dma_channel_reset_current();
        periph_config.periph_src++;
        dma_channel_configure_periph_current(&periph_config);
    }

    spi_state[bus].read_dma_channel = read_channel;
    spi_state[bus].write_dma_channel = write_channel;
}

struct spi_dma_waiter {
    mutex_t waiter;
    volatile int error;
    int count;
};

void spi_dma_unblock(void* arg, int error)
{
    struct spi_dma_waiter* waiter = arg;
    if (waiter->error == 0) {
        waiter->error = error;
    }
    waiter->count++;
    if (waiter->count == 2) {
        mutex_unlock(&waiter->waiter);
    } else if (waiter->count > 2) {
        for (;;) {}
    }
}

int spi_dma_transact(spi_t bus, const volatile void* out, volatile void* in, size_t len)
{
    SercomSpi* spi = dev(bus);
    dma_channel_t spi_read_dma_channel = spi_state[bus].read_dma_channel;
    dma_channel_t spi_write_dma_channel = spi_state[bus].write_dma_channel;

    const uint8_t dummy_out = 0;
    uint8_t dummy_in = 0;

    dma_channel_memory_config_t memory_config;
    memory_config.beatsize = DMAC_BEATSIZE_BYTE;
    memory_config.num_beats = len;
    memory_config.stepsize = DMAC_STEPSIZE_X1;
    memory_config.next_block = NULL;

    /* Configure read DMA channel */
    if (in == NULL) {
        memory_config.destination = &dummy_in;
        memory_config.increment_destination = false;
    } else {
        memory_config.destination = ((volatile uint8_t*) in) + len;
        memory_config.increment_destination = true;
    }
    memory_config.source = &spi->DATA.reg;
    memory_config.stepsel = DMAC_STEPSEL_DST;
    memory_config.increment_source = false;
    dma_channel_configure_memory(spi_read_dma_channel, &memory_config);

    /* Configure write DMA channel */
    if (out == NULL) {
        memory_config.source = &dummy_out;
        memory_config.increment_source = false;
    } else {
        memory_config.source = ((const volatile uint8_t*) out) + len;
        memory_config.increment_source = true;
    }
    memory_config.destination = &spi->DATA.reg;
    memory_config.stepsel = DMAC_STEPSEL_SRC;
    memory_config.increment_destination = false;
    dma_channel_configure_memory(spi_write_dma_channel, &memory_config);

    /* Set up thread to properly block */
    struct spi_dma_waiter waiter;
    mutex_init(&waiter.waiter);
    waiter.error = 0;
    waiter.count = 0;

    dma_channel_register_callback(spi_read_dma_channel, spi_dma_unblock, &waiter);
    dma_channel_register_callback(spi_write_dma_channel, spi_dma_unblock, &waiter);

    /* Start the transaction */
    mutex_lock(&waiter.waiter);
    dma_channel_set_current(spi_read_dma_channel);
    dma_channel_enable_current();
    dma_channel_set_current(spi_write_dma_channel);
    dma_channel_enable_current();

    mutex_lock(&waiter.waiter);

    // Once both DMA transactions are complete, the thread will progress

    dma_channel_set_current(spi_read_dma_channel);
    dma_channel_disable_current();
    dma_channel_set_current(spi_write_dma_channel);
    dma_channel_disable_current();
    mutex_unlock(&waiter.waiter);

    return waiter.error;
}
