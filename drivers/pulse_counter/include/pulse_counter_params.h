/*
 * Copyright (C) 2017 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_pulse_counter
 *
 * @{
 * @file
 * @brief       Default configuration for PULSE_COUNTER devices
 *
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 */

#ifndef PULSE_COUNTER_PARAMS_H
#define PULSE_COUNTER_PARAMS_H

#include "board.h"
#include "pulse_counter.h"
#include "saul_reg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Set default configuration parameters for the PULSE_COUNTER driver
 * @{
 */
#ifndef PULSE_COUNTER_PARAMS_BOARD
#define PULSE_COUNTER_PARAMS_DEFAULT  { .gpio = GPIO_PIN(PA, 19) }
#endif 
/**@}*/

/**
 * @brief   PULSE_COUNTER configuration
 */
static const pulse_counter_params_t pulse_counter_params[] =
{
#ifdef PULSE_COUNTER_PARAMS_BOARD
    PULSE_COUNTER_PARAMS_BOARD,
#else
    PULSE_COUNTER_PARAMS_DEFAULT,
#endif
};

/**
 * @brief   Additional meta information to keep in the SAUL registry
 */
static const saul_reg_info_t pulse_counter_saul_info[] =
{
    {
        .name = "pulse counter",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* PULSE_COUNTER_PARAMS_H */
/** @} */
