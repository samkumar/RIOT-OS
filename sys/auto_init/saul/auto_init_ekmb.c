/*
 * Copyright (C) 2017 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 */

/*
 * @ingroup     auto_init_saul
 * @{
 *
 * @file
 * @brief       Auto initialization for EKMB devices
 *
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 *
 * @}
 */

#ifdef MODULE_EKMB

#include "log.h"
#include "saul_reg.h"
#include "ekmb_params.h"

/**
 * @brief   Define the number of configured sensors
 */
#define EKMB_NUM    (sizeof(ekmb_params)/sizeof(ekmb_params[0]))

/**
 * @brief   Allocate memory for the device descriptors
 */
static ekmb_t ekmb_devs[EKMB_NUM];

/**
 * @brief   Memory for the SAUL registry entries
 */
static saul_reg_t saul_entries[EKMB_NUM];

/**
 * @brief   Reference the driver struct
 * @{
 */
extern saul_driver_t ekmb_saul_occup_driver;
/** @} */


void auto_init_ekmb(void)
{
    for (unsigned i = 0; i < EKMB_NUM; i++) {
        LOG_DEBUG("[auto_init_saul] initializing ekmb #%u\n", i);

        int res = ekmb_init(&ekmb_devs[i], &ekmb_params[i]);
        if (res != 0) {
            LOG_ERROR("[auto_init_saul] error initializing ekmb #%u\n", i);
        }
        else {
            saul_entries[i].dev = &(ekmb_devs[i]);
            saul_entries[i].name = ekmb_saul_info[i].name;
            saul_entries[i].driver = &ekmb_saul_occup_driver;
            saul_reg_add(&(saul_entries[i]));
        }
    }
}

#else
typedef int dont_be_pedantic;
#endif /* MODULE_EKMB */
