/*
 * Copyright (C) 2014 CLENET Baptiste
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_sam0_common
 * @ingroup     drivers_periph_i2c
 * @{
 *
 * @file
 * @brief       Low-level I2C driver implementation
 *
 * @author      Baptiste Clenet <bapclenet@gmail.com>
 * @author      Thomas Eichinger <thomas.eichinger@fu-berlin.de>
 *
 * @}
 */

#include <stdint.h>

#include "cpu.h"
#include "board.h"
#include "mutex.h"
#include "periph_conf.h"
#include "periph/dmac.h"
#include "periph/i2c.h"

#include "sched.h"
#include "thread.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

/* guard file in case no I2C device is defined */
#if I2C_NUMOF

#define SAMD21_I2C_TIMEOUT  (65535)

#define BUSSTATE_UNKNOWN SERCOM_I2CM_STATUS_BUSSTATE(0)
#define BUSSTATE_IDLE SERCOM_I2CM_STATUS_BUSSTATE(1)
#define BUSSTATE_OWNER SERCOM_I2CM_STATUS_BUSSTATE(2)
#define BUSSTATE_BUSY SERCOM_I2CM_STATUS_BUSSTATE(3)

#if CPU_FAM_SAML21
#define SERCOM_I2CM_CTRLA_MODE_I2C_MASTER SERCOM_I2CM_CTRLA_MODE(5)
#endif

/* static function definitions */
static void _i2c_poweron(SercomI2cm *sercom);
static void _i2c_poweroff(SercomI2cm *sercom);

static int _start(SercomI2cm *dev, uint8_t address, uint8_t rw_flag);
static inline int _write(SercomI2cm *dev, const uint8_t *data, int length);
static inline int _read(SercomI2cm *dev, uint8_t *data, int length);
static inline void _stop(SercomI2cm *dev);
static inline int _wait_for_response(SercomI2cm *dev, uint32_t max_timeout_counter);

static int _start_dma(SercomI2cm *dev, uint8_t address, uint8_t rw_flag, uint8_t total_bytes, dma_channel_t dma_channel);
static int _transact_dma(SercomI2cm* dev, dma_channel_t dma_channel);
static void _configure_write_dma(SercomI2cm *dev, const uint8_t *data, int length, dma_channel_t dma_channel);
static void _configure_read_dma(SercomI2cm *dev, uint8_t *data, int length, dma_channel_t dma_channel);
static void _stop_dma(SercomI2cm* dev);

typedef struct {
    mutex_t lock;
    dma_channel_t dma_channel;
} i2c_state_t;

/**
 * @brief Array holding one pre-initialized mutex for each I2C device, and the
 *        default DMA channel to use
 */
static i2c_state_t i2c_state[] = {
#if I2C_0_EN
    [I2C_0] = { MUTEX_INIT, DMA_CHANNEL_UNDEF },
#endif
#if I2C_1_EN
    [I2C_1] = { MUTEX_INIT, DMA_CHANNEL_UNDEF },
#endif
#if I2C_2_EN
    [I2C_2] = { MUTEX_INIT, DMA_CHANNEL_UNDEF },
#endif
#if I2C_3_EN
    [I2C_3] = { MUTEX_INIT, DMA_CHANNEL_UNDEF }
#endif
};

int i2c_init_master(i2c_t dev, i2c_speed_t speed)
{
    SercomI2cm *I2CSercom = 0;
    gpio_t pin_scl = 0;
    gpio_t pin_sda = 0;
    gpio_mux_t mux;
    uint32_t clock_source_speed = 0;
    uint8_t sercom_gclk_id = 0;
    uint8_t sercom_gclk_id_slow = 0;

    uint32_t timeout_counter = 0;
    int32_t tmp_baud;

    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            I2CSercom = &I2C_0_DEV;
            pin_sda = I2C_0_SDA;
            pin_scl = I2C_0_SCL;
            mux = I2C_0_MUX;
            clock_source_speed = CLOCK_CORECLOCK;
            sercom_gclk_id = I2C_0_GCLK_ID;
            sercom_gclk_id_slow = I2C_0_GCLK_ID_SLOW;
            break;
#endif
        default:
            DEBUG("I2C FALSE VALUE\n");
            return -1;
    }

    /* DISABLE I2C MASTER */
    i2c_poweroff(dev);

    /* Reset I2C */
    I2CSercom->CTRLA.reg = SERCOM_I2CS_CTRLA_SWRST;
    while (I2CSercom->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}

    /* Turn on power manager for sercom */
#if CPU_FAM_SAML21
    /* OK for SERCOM0-4 */
    MCLK->APBCMASK.reg |= (MCLK_APBCMASK_SERCOM0 << (sercom_gclk_id - SERCOM0_GCLK_ID_CORE));
#else
    PM->APBCMASK.reg |= (PM_APBCMASK_SERCOM0 << (sercom_gclk_id - GCLK_CLKCTRL_ID_SERCOM0_CORE_Val));
#endif

    /* I2C using CLK GEN 0 */
#if CPU_FAM_SAML21
    GCLK->PCHCTRL[sercom_gclk_id].reg = (GCLK_PCHCTRL_CHEN |
                         GCLK_PCHCTRL_GEN_GCLK0  );
    while (GCLK->SYNCBUSY.bit.GENCTRL) {}

    GCLK->PCHCTRL[sercom_gclk_id_slow].reg = (GCLK_PCHCTRL_CHEN |
                         GCLK_PCHCTRL_GEN_GCLK0  );
    while (GCLK->SYNCBUSY.bit.GENCTRL) {}
#else
    GCLK->CLKCTRL.reg = (GCLK_CLKCTRL_CLKEN |
                         GCLK_CLKCTRL_GEN_GCLK0 |
                         GCLK_CLKCTRL_ID(sercom_gclk_id));
    while (GCLK->STATUS.bit.SYNCBUSY) {}

    GCLK->CLKCTRL.reg = (GCLK_CLKCTRL_CLKEN |
                         GCLK_CLKCTRL_GEN_GCLK0 |
                         GCLK_CLKCTRL_ID(sercom_gclk_id_slow));
    while (GCLK->STATUS.bit.SYNCBUSY) {}
#endif


    /* Check if module is enabled. */
    if (I2CSercom->CTRLA.reg & SERCOM_I2CM_CTRLA_ENABLE) {
        DEBUG("STATUS_ERR_DENIED\n");
        return -3;
    }
    /* Check if reset is in progress. */
    if (I2CSercom->CTRLA.reg & SERCOM_I2CM_CTRLA_SWRST) {
        DEBUG("STATUS_BUSY\n");
        return -3;
    }

    /************ SERCOM PAD0 - SDA and SERCOM PAD1 - SCL *************/
    gpio_init_mux(pin_sda, mux);
    gpio_init_mux(pin_scl, mux);

    /* I2C CONFIGURATION */
    while (I2CSercom->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}

    /* Set sercom module to operate in I2C master mode. */
    I2CSercom->CTRLA.reg = SERCOM_I2CM_CTRLA_MODE_I2C_MASTER;

    /* Enable Smart Mode (ACK is sent when DATA.DATA is read) */
    I2CSercom->CTRLB.reg = SERCOM_I2CM_CTRLB_SMEN;

    /* Find and set baudrate. Read speed configuration. Set transfer
     * speed: SERCOM_I2CM_CTRLA_SPEED(0): Standard-mode (Sm) up to 100
     * kHz and Fast-mode (Fm) up to 400 kHz */
    switch (speed) {
        case I2C_SPEED_NORMAL:
            tmp_baud = (int32_t)(((clock_source_speed + (2 * (100000)) - 1) / (2 * (100000))) - 5);
            if (tmp_baud < 255 && tmp_baud > 0) {
                I2CSercom->CTRLA.reg |= SERCOM_I2CM_CTRLA_SPEED(0);
                I2CSercom->BAUD.reg = SERCOM_I2CM_BAUD_BAUD(tmp_baud);
            }
            break;
        case I2C_SPEED_FAST:
            tmp_baud = (int32_t)(((clock_source_speed + (2 * (400000)) - 1) / (2 * (400000))) - 5);
            if (tmp_baud < 255 && tmp_baud > 0) {
                I2CSercom->CTRLA.reg |= SERCOM_I2CM_CTRLA_SPEED(0);
                I2CSercom->BAUD.reg = SERCOM_I2CM_BAUD_BAUD(tmp_baud);
            }
            break;
        case I2C_SPEED_HIGH:
            tmp_baud = (int32_t)(((clock_source_speed + (2 * (3400000)) - 1) / (2 * (3400000))) - 1);
            if (tmp_baud < 255 && tmp_baud > 0) {
                I2CSercom->CTRLA.reg |= SERCOM_I2CM_CTRLA_SPEED(2);
                I2CSercom->BAUD.reg = SERCOM_I2CM_BAUD_HSBAUD(tmp_baud);
            }
            break;
        default:
            DEBUG("BAD BAUDRATE\n");
            return -2;
    }

    /* ENABLE I2C MASTER */
    i2c_poweron(dev);

    /* Start timeout if bus state is unknown. */
    while ((I2CSercom->STATUS.reg & SERCOM_I2CM_STATUS_BUSSTATE_Msk) == BUSSTATE_UNKNOWN) {
        if (timeout_counter++ >= SAMD21_I2C_TIMEOUT) {
            /* Timeout, force bus state to idle. */
            I2CSercom->STATUS.reg = BUSSTATE_IDLE;
        }
    }
    return 0;
}

int i2c_acquire(i2c_t dev)
{
    if (dev >= I2C_NUMOF) {
        return -1;
    }
    mutex_lock(&i2c_state[dev].lock);
    return 0;
}

int i2c_release(i2c_t dev)
{
    if (dev >= I2C_NUMOF) {
        return -1;
    }
    mutex_unlock(&i2c_state[dev].lock);
    return 0;
}

int i2c_read_byte(i2c_t dev, uint8_t address, void *data)
{
    return i2c_read_bytes(dev, address, data, 1);
}

int i2c_read_bytes(i2c_t dev, uint8_t address, void *data, int length)
{
    SercomI2cm *i2c;

    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            i2c = &I2C_0_DEV;
            break;
#endif
        default:
            return -1;
    }

    dma_channel_t i2c_dma_channel = i2c_state[dev].dma_channel;
    if (i2c_dma_channel != DMA_CHANNEL_UNDEF && !irq_is_in()) {
        _configure_read_dma(i2c, data, length, i2c_dma_channel);
        _start_dma(i2c, address, I2C_FLAG_READ, (uint8_t) length, i2c_dma_channel);
        _transact_dma(i2c, i2c_dma_channel);
        _stop_dma(i2c);
        return length;
    }

    /* start transmission and send slave address */
    if (_start(i2c, address, I2C_FLAG_READ) < 0) {
        return 0;
    }
    /* read data to register */
    if (_read(i2c, data, length) < 0) {
        return 0;
    }
    _stop(i2c);
    /* return number of bytes sent */
    return length;
}

int i2c_read_reg(i2c_t dev, uint8_t address, uint8_t reg, void *data)
{
    return i2c_read_regs(dev, address, reg, data, 1);
}

int i2c_read_regs(i2c_t dev, uint8_t address, uint8_t reg, void *data, int length)
{
    SercomI2cm *i2c;

    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            i2c = &I2C_0_DEV;
            break;
#endif
        default:
            return -1;
    }

    dma_channel_t i2c_dma_channel = i2c_state[dev].dma_channel;
    if (i2c_dma_channel != DMA_CHANNEL_UNDEF && !irq_is_in()) {
        _configure_write_dma(i2c, &reg, 1, i2c_dma_channel);
        _start_dma(i2c, address, I2C_FLAG_WRITE, 1, i2c_dma_channel);
        _transact_dma(i2c, i2c_dma_channel);
        _stop_dma(i2c);
        return i2c_read_bytes(dev, address, data, length);
    }

    /* start transmission and send slave address */
    if (_start(i2c, address, I2C_FLAG_WRITE) < 0) {
        return 0;
    }
    /* send register address/command and wait for complete transfer to
     * be finished */
    if (_write(i2c, &reg, 1) < 0) {
        return 0;
    }
    return i2c_read_bytes(dev, address, data, length);
}

int i2c_write_byte(i2c_t dev, uint8_t address, uint8_t data)
{
    return i2c_write_bytes(dev, address, &data, 1);
}

int i2c_write_bytes(i2c_t dev, uint8_t address, const void *data, int length)
{
    SercomI2cm *I2CSercom;

    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            I2CSercom = &I2C_0_DEV;
            break;
#endif
        default:
            return -1;
    }

    dma_channel_t i2c_dma_channel = i2c_state[dev].dma_channel;
    if (i2c_dma_channel != DMA_CHANNEL_UNDEF && !irq_is_in()) {
        _configure_write_dma(I2CSercom, data, length, i2c_dma_channel);
        _start_dma(I2CSercom, address, I2C_FLAG_WRITE, length, i2c_dma_channel);
        _transact_dma(I2CSercom, i2c_dma_channel);
        _stop_dma(I2CSercom);
        return length;
    }

    if (_start(I2CSercom, address, I2C_FLAG_WRITE) < 0) {
        return 0;
    }
    if (_write(I2CSercom, data, length) < 0) {
        return 0;
    }
    _stop(I2CSercom);
    return length;
}


int i2c_write_reg(i2c_t dev, uint8_t address, uint8_t reg, uint8_t data)
{
    return i2c_write_regs(dev, address, reg, &data, 1);
}

int i2c_write_regs(i2c_t dev, uint8_t address, uint8_t reg, const void *data, int length)
{
    SercomI2cm *i2c;

    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            i2c = &I2C_0_DEV;
            break;
#endif
        default:
            return -1;
    }

    dma_channel_t i2c_dma_channel = i2c_state[dev].dma_channel;
    if (i2c_dma_channel != DMA_CHANNEL_UNDEF && !irq_is_in()) {

        /*
         * We could just use the following six lines to do the work:
         *
         * _start_dma(i2c, address, I2C_FLAG_WRITE, 1 + (uint8_t) length, i2c_dma_channel);
         * _configure_write_dma(i2c, &reg, 1, i2c_dma_channel);
         * _transact_dma(i2c, i2c_dma_channel);
         * _configure_write_dma(i2c, data, length, i2c_dma_channel);
         * _transact_dma(i2c, i2c_dma_channel);
         * _stop_dma(i2c);
         *
         * However, that would be inefficient, because the CPU wakes up between
         * the two writes. Instead, we use a linked descriptor so the DMA
         * performs both writes without waking up the CPU.
         */

        _start_dma(i2c, address, I2C_FLAG_WRITE, 1 + (uint8_t) length, i2c_dma_channel);

        dma_channel_memory_config_t first_block;
        dma_channel_linked_block_t second_block;

        first_block.source = &reg;
        first_block.destination = &i2c->DATA.reg;
        first_block.beatsize = DMAC_BEATSIZE_BYTE;
        first_block.num_beats = 1;
        first_block.stepsize = DMAC_STEPSIZE_X1;
        first_block.stepsel = DMAC_STEPSEL_SRC;
        first_block.increment_source = false;
        first_block.increment_destination = false;
        first_block.next_block = &second_block;

        second_block.config.source = ((const uint8_t*) data) + length;
        second_block.config.destination = &i2c->DATA.reg;
        second_block.config.beatsize = DMAC_BEATSIZE_BYTE;
        second_block.config.num_beats = length;
        second_block.config.stepsize = DMAC_STEPSIZE_X1;
        second_block.config.stepsel = DMAC_STEPSEL_SRC;
        second_block.config.increment_source = true;
        second_block.config.increment_destination = false;
        second_block.config.next_block = NULL;

        dma_channel_configure_memory(i2c_dma_channel, &first_block);

        _transact_dma(i2c, i2c_dma_channel);
        _stop_dma(i2c);

        return length;
    }

    /* start transmission and send slave address */
    if (_start(i2c, address, I2C_FLAG_WRITE) < 0) {
        return 0;
    }
    /* send register address and wait for complete transfer to be finished */
    if (_write(i2c, &reg, 1) < 0) {
        return 0;
    }
    /* write data to register */
    if (_write(i2c, data, length) < 0) {
        return 0;
    }
    /* finish transfer */
    _stop(i2c);
    return length;
}

static void _i2c_poweron(SercomI2cm *sercom)
{
    if (sercom == NULL) {
        return;
    }
    sercom->CTRLA.bit.ENABLE = 1;
    while (sercom->SYNCBUSY.bit.ENABLE) {}
}

void i2c_poweron(i2c_t dev)
{
    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            _i2c_poweron(&I2C_0_DEV);
            break;
#endif
        default:
            return;
    }
}

static void _i2c_poweroff(SercomI2cm *sercom)
{
    if (sercom == NULL) {
        return;
    }
    sercom->CTRLA.bit.ENABLE = 0;
    while (sercom->SYNCBUSY.bit.ENABLE) {}
}

void i2c_poweroff(i2c_t dev)
{
    switch (dev) {
#if I2C_0_EN
        case I2C_0:
            _i2c_poweroff(&I2C_0_DEV);
            break;
#endif
        default:
            return;
    }
}

static int _start(SercomI2cm *dev, uint8_t address, uint8_t rw_flag)
{
    /* Wait for hardware module to sync */
    DEBUG("Wait for device to be ready\n");
    while (dev->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}

    /* Set action to ACK. */
    dev->CTRLB.reg &= ~SERCOM_I2CM_CTRLB_ACKACT;

    /* Send Start | Address | Write/Read */
    DEBUG("Generate start condition by sending address\n");
    dev->ADDR.reg = (address << 1) | rw_flag | (0 << SERCOM_I2CM_ADDR_HS_Pos);

    /* Wait for response on bus. */
    if (rw_flag == I2C_FLAG_READ) {
        /* Some devices (e.g. SHT2x) can hold the bus while preparing the reply */
        if (_wait_for_response(dev, 100 * SAMD21_I2C_TIMEOUT) < 0)
            return -1;
    }
    else {
        if (_wait_for_response(dev, SAMD21_I2C_TIMEOUT) < 0)
            return -1;
    }

    /* Check for address response error unless previous error is detected. */
    /* Check for error and ignore bus-error; workaround for BUSSTATE
     * stuck in BUSY */
    if (dev->INTFLAG.reg & SERCOM_I2CM_INTFLAG_SB) {
        /* Clear write interrupt flag */
        dev->INTFLAG.reg = SERCOM_I2CM_INTFLAG_SB;
        /* Check arbitration. */
        if (dev->STATUS.reg & SERCOM_I2CM_STATUS_ARBLOST) {
            DEBUG("STATUS_ERR_PACKET_COLLISION\n");
            return -2;
        }
    }
    /* Check that slave responded with ack. */
    else if (dev->STATUS.reg & SERCOM_I2CM_STATUS_RXNACK) {
        /* Slave busy. Issue ack and stop command. */
        dev->CTRLB.reg |= SERCOM_I2CM_CTRLB_CMD(3);
        DEBUG("STATUS_ERR_BAD_ADDRESS\n");
        return -3;
    }
    return 0;
}

static inline int _write(SercomI2cm *dev, const uint8_t *data, int length)
{
    uint16_t tmp_data_length = length;
    uint16_t buffer_counter = 0;

    /* Write data buffer until the end. */
    DEBUG("Looping through bytes\n");
    while (tmp_data_length--) {
        /* Check that bus ownership is not lost. */
        if ((dev->STATUS.reg & SERCOM_I2CM_STATUS_BUSSTATE_Msk) != BUSSTATE_OWNER) {
            DEBUG("STATUS_ERR_PACKET_COLLISION\n");
            return -2;
        }

        /* Wait for hardware module to sync */
        while (dev->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}

        DEBUG("Written byte #%i to data reg, now waiting for DR to be empty again\n", buffer_counter);
        dev->DATA.reg = data[buffer_counter++];

        /* Wait for response on bus. */
        if (_wait_for_response(dev, SAMD21_I2C_TIMEOUT) < 0)
            return -1;

        /* Check for NACK from slave. */
        if (dev->STATUS.reg & SERCOM_I2CM_STATUS_RXNACK) {
            DEBUG("STATUS_ERR_OVERFLOW\n");
            return -4;
        }
    }
    return 0;
}

static inline int _read(SercomI2cm *dev, uint8_t *data, int length)
{
    uint8_t count = 0;

    /* Set action to ack. */
    dev->CTRLB.reg &= ~SERCOM_I2CM_CTRLB_ACKACT;

    /* Read data buffer. */
    while (count != length) {
        /* Check that bus ownership is not lost. */
        if ((dev->STATUS.reg & SERCOM_I2CM_STATUS_BUSSTATE_Msk) != BUSSTATE_OWNER) {
            DEBUG("STATUS_ERR_PACKET_COLLISION\n");
            return -2;
        }

        /* Wait for hardware module to sync */
        while (dev->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}
        /* Save data to buffer. */
        data[count] = dev->DATA.reg;

        /* Wait for response on bus. */
        if (_wait_for_response(dev, SAMD21_I2C_TIMEOUT) < 0)
            return -1;

        count++;
    }
    /* Send NACK before STOP */
    dev->CTRLB.reg |= SERCOM_I2CM_CTRLB_ACKACT;
    return 0;
}

static inline void _stop(SercomI2cm *dev)
{
    /* Wait for hardware module to sync */
    while (dev->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}
    /* Stop command */
    dev->CTRLB.reg |= SERCOM_I2CM_CTRLB_CMD(3);
    /* Wait for bus to be idle again */
    while ((dev->STATUS.reg & SERCOM_I2CM_STATUS_BUSSTATE_Msk) != BUSSTATE_IDLE) {}
    DEBUG("Stop sent\n");
}

static inline int _wait_for_response(SercomI2cm *dev, uint32_t max_timeout_counter)
{
    uint32_t timeout_counter = 0;
    DEBUG("Wait for response.\n");
    while (!(dev->INTFLAG.reg & SERCOM_I2CM_INTFLAG_MB)
           && !(dev->INTFLAG.reg & SERCOM_I2CM_INTFLAG_SB)) {
        if (++timeout_counter >= max_timeout_counter) {
            DEBUG("STATUS_ERR_TIMEOUT\n");
            return -1;
        }
    }
    return 0;
}

/* DMA Functionality */

void i2c_set_dma_channel(i2c_t dev, dma_channel_t channel)
{
    if (channel != DMA_CHANNEL_UNDEF) {
        dma_channel_set_current(channel);
        dma_channel_reset_current();
    }
    i2c_state[dev].dma_channel = channel;
}

struct i2c_dma_waiter {
    mutex_t waiter;
    volatile int error;
};

void i2c_dma_unblock(void* arg, int error)
{
    struct i2c_dma_waiter* waiter = arg;
    waiter->error = error;
    mutex_unlock(&waiter->waiter);
}

static int _start_dma(SercomI2cm *dev, uint8_t address, uint8_t rw_flag, uint8_t total_bytes, dma_channel_t dma_channel)
{
    /* Wait for hardware module to sync */
    DEBUG("Wait for device to be ready\n");
    while (dev->SYNCBUSY.reg & SERCOM_I2CM_SYNCBUSY_MASK) {}

    /* Set action to ACK. */
    dev->CTRLB.reg &= ~SERCOM_I2CM_CTRLB_ACKACT;

    /* Configure DMA channel. */
    dma_channel_set_current(dma_channel);
    dma_channel_periph_config_t periph_config;
    periph_config.on_trigger = DMAC_ACTION_BEAT;
    periph_config.periph_src = (I2C_0_SERCOM_NUM << 1) + ((rw_flag == I2C_FLAG_READ) ? 1 : 2);
    dma_channel_configure_periph_current(&periph_config);

    /* Send Start | Address | Write/Read | Total Length for Automatic STOP at the end. */
    DEBUG("Generate start condition by sending address\n");
    dev->ADDR.reg = (address << 1) | rw_flag | (1 << SERCOM_I2CM_ADDR_LENEN_Pos) | (0 << SERCOM_I2CM_ADDR_HS_Pos) | (((uint32_t) total_bytes) << 16);

    return 0;
}

static int _transact_dma(SercomI2cm* dev, dma_channel_t dma_channel)
{
    struct i2c_dma_waiter waiter;
    mutex_init(&waiter.waiter);
    waiter.error = 0;

    dma_channel_register_callback(dma_channel, i2c_dma_unblock, &waiter);

    dma_channel_set_current(dma_channel);
    mutex_lock(&waiter.waiter);
    dma_channel_enable_current();
    mutex_lock(&waiter.waiter);

    // The thread blocks here until the transfer is complete

    dma_channel_set_current(dma_channel);
    dma_channel_disable_current();
    mutex_unlock(&waiter.waiter);

    return waiter.error;
}

static void _configure_write_dma(SercomI2cm* dev, const uint8_t* data, int length, dma_channel_t dma_channel)
{
    dma_channel_memory_config_t memory_config;
    memory_config.source = (volatile void*) &data[length];
    memory_config.destination = (volatile void*) &dev->DATA.reg;
    memory_config.beatsize = DMAC_BEATSIZE_BYTE;
    memory_config.num_beats = length;
    memory_config.stepsize = DMAC_STEPSIZE_X1;
    memory_config.stepsel = DMAC_STEPSEL_SRC;
    memory_config.increment_source = true;
    memory_config.increment_destination = false;
    memory_config.next_block = NULL;
    dma_channel_configure_memory(dma_channel, &memory_config);
}

static void _configure_read_dma(SercomI2cm* dev, uint8_t* data, int length, dma_channel_t dma_channel)
{
    dma_channel_memory_config_t memory_config;
    memory_config.source = (volatile void*) &dev->DATA.reg;
    memory_config.destination = (volatile void*) &data[length];
    memory_config.beatsize = DMAC_BEATSIZE_BYTE;
    memory_config.num_beats = length;
    memory_config.stepsize = DMAC_STEPSIZE_X1;
    memory_config.stepsel = DMAC_STEPSEL_DST;
    memory_config.increment_source = false;
    memory_config.increment_destination = true;
    memory_config.next_block = NULL;
    dma_channel_configure_memory(dma_channel, &memory_config);
}

static inline void _stop_dma(SercomI2cm *dev)
{
    /* Wait for bus to be idle again */
    while ((dev->STATUS.reg & SERCOM_I2CM_STATUS_BUSSTATE_Msk) != BUSSTATE_IDLE) {}
}

#endif /* I2C_NUMOF */
