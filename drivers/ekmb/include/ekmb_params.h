/*
 * Copyright (C) 2017 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_ekmb
 *
 * @{
 * @file
 * @brief       Default configuration for EKMB devices
 *
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 */

#ifndef EKMB_PARAMS_H
#define EKMB_PARAMS_H

#include "board.h"
#include "ekmb.h"
#include "saul_reg.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Set default configuration parameters for the EKMB driver
 * @{
 */
#ifndef EKMB_PARAMS_BOARD
#define EKMB_PARAMS_DEFAULT  { .gpio = GPIO_PIN(PA, 6) }
#endif 
/**@}*/

/**
 * @brief   EKMB configuration
 */
static const ekmb_params_t ekmb_params[] =
{
#ifdef EKMB_PARAMS_BOARD
    EKMB_PARAMS_BOARD,
#else
    EKMB_PARAMS_DEFAULT,
#endif
};

/**
 * @brief   Additional meta information to keep in the SAUL registry
 */
static const saul_reg_info_t ekmb_saul_info[] =
{
    {
        .name = "ekmb",
    },
};

#ifdef __cplusplus
}
#endif

#endif /* EKMB_PARAMS_H */
/** @} */
