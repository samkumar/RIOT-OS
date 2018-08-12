/*
 * Copyright (C) 2018 UC Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     BETS
 * @file
 * @brief       Implementation of OpenThread preevent thread
 *
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 * @}
 */

#include "ot.h"
#include "rethos.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

#define OPENTHREAD_PREEVENT_QUEUE_LEN (1)
static msg_t _queue[OPENTHREAD_PREEVENT_QUEUE_LEN];
static kernel_pid_t _preevent_pid;

/* get OpenThread Preevent Thread pid */
kernel_pid_t openthread_get_preevent_pid(void) {
    return _preevent_pid;
}

/* OpenThread Preevent Thread
 * This thread is used exclusively for REthos.
**/
volatile bool rethos_queued = false;
static void *_openthread_preevent_thread(void *arg) {
    int state;
    _preevent_pid = thread_getpid();

    msg_init_queue(_queue, OPENTHREAD_PREEVENT_QUEUE_LEN);
    msg_t msg;

    DEBUG("ot_preevent: START!\n");

    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case OPENTHREAD_RETHOS_ISR_EVENT:
                /* Service REthos ISR. */
                DEBUG("ot_preevent: OPENTHREAD_RETHOS_ISR_EVENT received\n");
                state = irq_disable();
                rethos_queued = false;
                irq_restore(state);
                rethos_service_isr(msg.content.ptr);
                break;
            default:
                assert(false);
                break;
        }

        /* Stack overflow check */
        openthread_preevent_thread_overflow_check();
    }

    return NULL;
}

/* starts OpenThread Preevent Thread */
int openthread_preevent_init(char *stack, int stacksize, char priority, const char *name) {

    _preevent_pid = thread_create(stack, stacksize, priority, THREAD_CREATE_STACKTEST,
                         _openthread_preevent_thread, NULL, name);

    if (_preevent_pid <= 0) {
        return -EINVAL;
    }

    return _preevent_pid;
}
