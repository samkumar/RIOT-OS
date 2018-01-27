/*
 * Copyright (C) 2017 Fundacion Inria Chile
 * Copyright (C) 2017 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Implementation of OpenThread main functions
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 * @}
 */

#include <assert.h>

#include "openthread/platform/uart.h"
#include "ot.h"
#include "random.h"
#include "xtimer.h"

#ifdef MODULE_AT86RF2XX
#include "at86rf2xx.h"
#include "at86rf2xx_params.h"
#endif

#define ENABLE_DEBUG (1)
#include "debug.h"

static xtimer_t ot_timer;

#ifdef MODULE_AT86RF2XX     /* is mutual exclusive with above ifdef */
#define OPENTHREAD_NETIF_NUMOF        (sizeof(at86rf2xx_params) / sizeof(at86rf2xx_params[0]))
static at86rf2xx_t at86rf2xx_dev;
#endif

static char ot_task_thread_stack[THREAD_STACKSIZE_MAIN];
static char ot_event_thread_stack[THREAD_STACKSIZE_MAIN];
static char ot_preevent_thread_stack[THREAD_STACKSIZE_IDLE];

/* get OpenThread netdev */
netdev_t* openthread_get_netdev(void) {
    return (netdev_t*) &at86rf2xx_dev;
}

/* get OpenThread timer */
xtimer_t* openthread_get_timer(void) {
    return &ot_timer;
}

/* Interupt handler for OpenThread timer event */
static void _timer_cb(void* arg) {
    msg_t msg;
	msg.type = OPENTHREAD_XTIMER_MSG_TYPE_EVENT;
	msg_send(&msg, openthread_get_preevent_pid());
}

/* Interupt handler for OpenThread event thread */
static void _event_cb(netdev_t *dev, netdev_event_t event) {
    switch (event) {
        case NETDEV_EVENT_ISR:
            {
                msg_t msg;
                msg.type = OPENTHREAD_NETDEV_MSG_TYPE_EVENT;
                msg.content.ptr = dev;
                if (msg_send(&msg, openthread_get_event_pid()) <= 0) {
                    DEBUG("ot_event: possibly lost interrupt.\n");
                }
                break;
            }
        case NETDEV_EVENT_ISR2:
            {
                msg_t msg;
                msg.type = OPENTHREAD_NETDEV_MSG_TYPE_EVENT;
                msg.content.ptr = dev;
                if (msg_send(&msg, openthread_get_preevent_pid()) <= 0) {
                    DEBUG("ot_preevent: possibly lost interrupt.\n");
                }
                break;
            }
        case NETDEV_EVENT_RX_COMPLETE:
            recv_pkt(openthread_get_instance(), dev);
            break;
        case NETDEV_EVENT_TX_COMPLETE:
        case NETDEV_EVENT_TX_COMPLETE_DATA_PENDING:
        case NETDEV_EVENT_TX_NOACK:
        case NETDEV_EVENT_TX_MEDIUM_BUSY:
            sent_pkt(openthread_get_instance(), event);
            break;
        default:
            break;
    }
}

uint8_t ot_call_command(char* command, void *arg, void* answer) {
    ot_job_t job;

    job.command = command;
    job.arg = arg;
    job.answer = answer;

    msg_t msg, reply;
    msg.type = OPENTHREAD_JOB_MSG_TYPE_EVENT;
    msg.content.ptr = &job;
    msg_send_receive(&msg, &reply, openthread_get_event_pid());
    return (uint8_t)reply.content.value;
}

void openthread_bootstrap(void)
{

    DEBUG("OT init start\n");
    /* init random */
    ot_random_init();

    /* set openthread timer callback */
    ot_timer.callback = _timer_cb;

    /* setup netdev modules */
#ifdef MODULE_AT86RF2XX
    at86rf2xx_setup(&at86rf2xx_dev, &at86rf2xx_params[0]);
    netdev_t *netdev = (netdev_t *) &at86rf2xx_dev;
#endif
    netdev->driver->init(netdev);
    netdev->event_callback = _event_cb;
    netopt_enable_t enable = NETOPT_ENABLE;
    netdev->driver->set(netdev, NETOPT_RX_END_IRQ, &enable, sizeof(enable));
    netdev->driver->set(netdev, NETOPT_TX_END_IRQ, &enable, sizeof(enable));
    openthread_radio_init(netdev);
    DEBUG("OT-RADIO setting is OK\n");

    /* enable OpenThread UART */
    otPlatUartEnable();
    DEBUG("OT-UART setting is OK\n");

    /* init three threads for openthread */
    openthread_preevent_init(ot_preevent_thread_stack, sizeof(ot_preevent_thread_stack),
                         THREAD_PRIORITY_MAIN - 3, "openthread_preevent"); 
    openthread_task_init(ot_task_thread_stack, sizeof(ot_task_thread_stack),
                         THREAD_PRIORITY_MAIN - 1, "openthread_task"); 
    openthread_event_init(ot_event_thread_stack, sizeof(ot_event_thread_stack),
                         THREAD_PRIORITY_MAIN - 2, "openthread_event"); 
}
