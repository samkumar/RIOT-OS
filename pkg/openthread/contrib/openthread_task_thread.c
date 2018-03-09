/*
 * Copyright (C) 2018 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Implementation of OpenThread Task Thread
 *
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 * @}
 */

#include <assert.h>

#include "openthread/tasklet.h"
#ifdef MODULE_OPENTHREAD_FTD
#include "openthread/platform/alarm-micro.h"
#endif
#include "ot.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#define OPENTHREAD_TASK_QUEUE_LEN      (4)
static msg_t _queue[OPENTHREAD_TASK_QUEUE_LEN];
static kernel_pid_t _task_pid;

/* get OpenThread Task Thread pid */
kernel_pid_t openthread_get_task_pid(void) {
    return _task_pid;
}

/* OpenThread Task Thread
 * OpenThread posts tasks when sending a packet. This task thread processes these tasks,
 * pre-processing a packet, moving it to the radio queue and triggering a radio transmission.
 * When a transmission is completed, this event is reported to Event Thread.
 *
 * Given that processing interrupts is more urgent than processing posted tasks, this thread
 * is preempted by OpenThread (Pre)Event Thread.
 *
 * The msg_queue size of this thread can be bounded by '1' since it receives a message from
 * OpenThread Event Thread only when the tasklet's state switches from empty to non-empty.
**/
static void *_openthread_task_thread(void *arg) {
    _task_pid = thread_getpid();

    msg_init_queue(_queue, OPENTHREAD_TASK_QUEUE_LEN);
    msg_t msg;

    DEBUG("ot_task: START!\n");

    while (1) {
        msg_receive(&msg);
        openthread_lock_coarse_mutex();
//printf("\not_task start\n");
        switch (msg.type) {
            case OPENTHREAD_TASK_MSG_TYPE_EVENT:
                /* Process OpenThread tasks (pre-processing a sending packet) */
                DEBUG("\not_task: OPENTHREAD_TASK_MSG_TYPE_EVENT received\n");
                break;
#ifdef MODULE_OPENTHREAD_FTD
            case OPENTHREAD_MICROTIMER_MSG_TYPE_EVENT:
                /* Tell OpenThread a microsec time event was received (CSMA timer)
                 * It checks the current time and executes callback functions of
                 * only expired timers. */
                DEBUG("\not_task: OPENTHREAD_MICROTIMER_MSG_TYPE_EVENT received\n");
                otPlatAlarmMicroFired(openthread_get_instance());
                break;
#endif
            case OPENTHREAD_NETDEV_MSG_TYPE_EVENT:
                /* Received an event from radio driver */
                DEBUG("\not_event: OPENTHREAD_NETDEV_MSG_TYPE_EVENT received\n");
                printf("\nfin->");
                //msg.type = OPENTHREAD_NETDEV_MSG_TYPE_EVENT;
                //msg_send(&msg, openthread_get_event_pid());
                mutex_lock(openthread_get_radio_mutex());
                openthread_get_netdev()->driver->isr(openthread_get_netdev());
                mutex_unlock(openthread_get_radio_mutex());
                break;
            case OPENTHREAD_TX_FAIL_RADIO_BUSY:
                DEBUG("\not_event: OPENTHREAD_TX_FAIL_RADIO_BUSY\n");
                sent_pkt(openthread_get_instance(), NETDEV_EVENT_TX_MEDIUM_BUSY);
                break;
        }
        while(otTaskletsArePending(openthread_get_instance())) {
#ifdef MODULE_OPENTHREAD_FTD
            /* Call this function just in case a timer event is missed */
            otPlatAlarmMicroFired(openthread_get_instance());
#endif
            otTaskletsProcess(openthread_get_instance());
        }
        openthread_unlock_coarse_mutex();

        /* Stack overflow check */
        openthread_task_thread_overflow_check();

    }
    return NULL;
}

/* starts OpenThread task thread */
int openthread_task_init(char *stack, int stacksize, char priority, const char *name) {

    _task_pid = thread_create(stack, stacksize, priority, THREAD_CREATE_STACKTEST,
                         _openthread_task_thread, NULL, name);

    if (_task_pid <= 0) {
        return -EINVAL;
    }

    return _task_pid;
}
