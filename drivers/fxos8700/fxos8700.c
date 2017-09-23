/*
 * Copyright (C) Daniel Krebs
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @file
 * @brief       Driver for the FXOS8700 temperature sensor with serial EEPROM
 *
 * @author      Daniel Krebs <github@daniel-krebs.net>
 */


#include "periph/i2c.h"
#include "xtimer.h"

#include "fxos8700.h"

#define ENABLE_DEBUG (0)
#include "debug.h"


#define I2C_SPEED            I2C_SPEED_NORMAL

#define ACCEL_ONLY_MODE      0x00
#define MAG_ONLY_MODE        0x01
#define HYBRID_MODE          0x03



static int fxos8700_read_regs(fxos8700_t* dev, uint8_t reg, uint8_t* data, size_t len)
{
    i2c_acquire(dev->p.i2c);
    if(i2c_read_regs(dev->p.i2c, dev->p.addr, reg, (char*) data, len) <= 0) {
        DEBUG("[fxos8700] Can't read register 0x%x\n", reg);
        i2c_release(dev->p.i2c);
        return -1;
    }
    i2c_release(dev->p.i2c);

    return 0;
}

static int fxos8700_write_regs(fxos8700_t* dev, uint8_t reg, uint8_t* data, size_t len)
{
    i2c_acquire(dev->p.i2c);
    if(i2c_write_regs(dev->p.i2c, dev->p.addr, reg, (char*) data, len) <= 0) {
        DEBUG("[fxos8700] Can't write to register 0x%x\n", reg);
        i2c_release(dev->p.i2c);
        return -1;
    }
    i2c_release(dev->p.i2c);

    return 0;
}

static int fxos8700_reset(fxos8700_t* dev)
{
    //  uint8_t ctrl2 = 0x40;
    //  return fxos8700_write_regs(dev, FXOS8700_REG_CTRL_REG2, &ctrl2, 1);
    return 0;
}

int fxos8700_init(fxos8700_t* dev, const fxos8700_params_t *params)
{
    dev->p.i2c = params->i2c;
    int rv;
    uint8_t config;

    if ( (params->addr < 0x1C) || (params->addr > 0x1F) ) {
        DEBUG("[fxos8700] Invalid address\n");
        return -2;
    }
    dev->p.addr = params->addr;

    i2c_acquire(dev->p.i2c);
    if(i2c_init_master(dev->p.i2c, I2C_SPEED_NORMAL) != 0) {
        DEBUG("[fxos8700] Can't initialize I2C master\n");
        i2c_release(dev->p.i2c);
        return -3;
    }

    rv = i2c_read_regs(dev->p.i2c, dev->p.addr, 0x0D, &config, 1);
    if (rv != 1) {
        i2c_release(dev->p.i2c);
		    DEBUG("[fxos8700] Could not read WHOAMI (%d)\n", rv);
        return -4;
    }

    dev->whoami = config;
    i2c_release(dev->p.i2c);

     /* Reset the device */
    if(fxos8700_reset(dev) != 0) {
        return -5;
    }


    /* Configure the ODR to maximum (400Hz in hybrid mode) */
    config = 0x00;
    if (fxos8700_write_regs(dev, FXOS8700_REG_CTRL_REG1, &config, 1) != 0) {
        return -6;
    }
    /* Activate hybrid mode */
    config = HYBRID_MODE;
    if (fxos8700_write_regs(dev, FXOS8700_REG_M_CTRL_REG1, &config, 1) != 0) {
        return -7;
    }
    /* Set burst read mode (accel + magnet together) */
    config = 0x20;
    if (fxos8700_write_regs(dev, FXOS8700_REG_M_CTRL_REG2, &config, 1) != 0) {
        return -8;
    }

    return 0;
}

int fxos8700_set_active(fxos8700_t* dev)
{
    uint8_t config = 0x01;
    if (fxos8700_write_regs(dev, FXOS8700_REG_CTRL_REG1, &config, 1) != 0) {
    	return -1;
    }
    return 0;
}

int fxos8700_set_idle(fxos8700_t* dev)
{
    uint8_t config = 0x00;
    if (fxos8700_write_regs(dev, FXOS8700_REG_CTRL_REG1, &config, 1) != 0) {
	    return -1;
    }
    return 0;
}

int fxos8700_read(fxos8700_t* dev, fxos8700_measurement_t* m)
{
    uint8_t data[12];
    uint8_t ready = 0;

    if (fxos8700_set_active(dev)) {
        return -1;
    }

    while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG__STATUS, &ready, 1);
    }
    while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG_M_DR_STATUS, &ready, 1);
    }

    /* Read all data at once */
    if (fxos8700_read_regs(dev, FXOS8700_REG_OUT_X_MSB, &data[0], 12)) {
        return -2;
    }

    if (fxos8700_set_idle(dev)) {
        return -3;
    }

    /* Read accelerometer */
    m->acc_x = (int16_t) ((data[0]<<6) | (data[1]>>2));
    m->acc_y = (int16_t) ((data[2]<<6) | (data[3]>>2));
    m->acc_z = (int16_t) ((data[4]<<6) | (data[5]>>2));

    /* Read magnetometer */
    m->mag_x = (int16_t) ((data[6] <<8) | data[7]);
    m->mag_y = (int16_t) ((data[8] <<8) | data[9]);
    m->mag_z = (int16_t) ((data[10]<<8) | data[11]);

    return 0;
}

int fxos8700_read_mag(fxos8700_t* dev, fxos8700_measurement_mag_t* m)
{
    uint8_t data[12];
    uint8_t ready = 0;

    if (fxos8700_set_active(dev)) {
        return -1;
    }

    while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG__STATUS, &ready, 1);
    }
    while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG_M_DR_STATUS, &ready, 1);
    }

    /* Read all data at once */
    if (fxos8700_read_regs(dev, FXOS8700_REG_OUT_X_MSB, &data[0], 12)) {
        return -2;
    }

    if (fxos8700_set_idle(dev)) {
        return -3;
    }

    /* Read magnetometer */
    m->mag_x = (int16_t) ((data[6] <<8) | data[7]);
    m->mag_y = (int16_t) ((data[8] <<8) | data[9]);
    m->mag_z = (int16_t) ((data[10]<<8) | data[11]);

    return 0;
}

int fxos8700_read_acc(fxos8700_t* dev, fxos8700_measurement_acc_t* m)
{
    uint8_t data[12];
    uint8_t ready = 0;

    if (fxos8700_set_active(dev)) {
        return -1;
    }

    while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG__STATUS, &ready, 1);
    }
	while(!(ready & 0x08)) {
        fxos8700_read_regs(dev, FXOS8700_REG_M_DR_STATUS, &ready, 1);
    }

    /* Read all data at once */
    if (fxos8700_read_regs(dev, FXOS8700_REG_OUT_X_MSB, &data[0], 12)) {
	    return -2;
    }

    if (fxos8700_set_idle(dev)) {
        return -3;
    }

    /* Read accelerometer */
    m->acc_x = (int16_t) ((data[0]<<6) | (data[1]>>2));
    m->acc_y = (int16_t) ((data[2]<<6) | (data[3]>>2));
    m->acc_z = (int16_t) ((data[4]<<6) | (data[5]>>2));

    return 0;
}
