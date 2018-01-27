/*
 * Copyright (C) 2017 Fundacion Inria Chile
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Implementation of OpenThread alarm platform abstraction
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @}
 */

#include <stdint.h>

#include "openthread/platform/alarm-milli.h"
#include "ot.h"
#include "msg.h"
#include "xtimer.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

static uint32_t prev = 0;
static uint32_t long_cnt = 0;

/**
 * Set the alarm to fire at @p aDt milliseconds after @p aT0.
 *
 * @param[in] aInstance  The OpenThread instance structure.
 * @param[in] aT0        The reference time.
 * @param[in] aDt        The time delay in milliseconds from @p aT0.
 */
void otPlatAlarmMilliStartAt(otInstance *aInstance, uint32_t aT0, uint32_t aDt)
{
    DEBUG("otPlatAlarmMilliStartAt: aT0: %" PRIu32 ", aDT: %" PRIu32 "\n", aT0, aDt);
    
    xtimer_remove(openthread_get_timer());

    msg_t msg;
    msg.type = OPENTHREAD_XTIMER_MSG_TYPE_EVENT;
    if (aDt <= 1) {
        msg_send(&msg, openthread_get_preevent_pid());
    }
    else {
        uint32_t dt = aDt * US_PER_MS;
        xtimer_set(openthread_get_timer(), dt);
    }
}

/* OpenThread will call this to stop alarms */
void otPlatAlarmMilliStop(otInstance *aInstance)
{
    DEBUG("otPlatAlarmMilliStop\n");
    xtimer_remove(openthread_get_timer());
}

/* OpenThread will call this for getting running time in millisecs */
uint32_t otPlatAlarmMilliGetNow(void)
{
    uint32_t now = xtimer_now_usec() / US_PER_MS;
    /* With the same unit32_t type, microsec timer overflows faster than millisec timer. 
     * This mismatch should be handled here */
    if (prev > now) {
        long_cnt++;
    }
    prev = now;
    now += long_cnt * (0xFFFFFFFF / US_PER_MS);
    DEBUG("otPlatAlarmMilliGetNow: %" PRIu32 "\n", now);
    return now;
}
