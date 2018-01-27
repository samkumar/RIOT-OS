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

#define ENABLE_DEBUG (0)
#include "debug.h"

#define OPENTHREAD_PREEVENT_QUEUE_LEN (2)
static msg_t _queue[OPENTHREAD_PREEVENT_QUEUE_LEN];
static kernel_pid_t _preevent_pid;

/* get OpenThread Preevent Thread pid */
kernel_pid_t openthread_get_preevent_pid(void) {
    return _preevent_pid;
}

/* OpenThread Preevent Thread 
 * This thread receives event messages directly from interrupt handlers (timer and radio) and
 * delivers them to OpenThread Event Thread. Even though we have OpenThread Event Thread to
 * process events, this additional thread is necessary for safe operation.
 *
 * Note that RIOT's message delivery from an interrupt handler to a thread is failed when
 * the thread's msg_queue is full, while that from a thread to another thread is safe even when
 * the receiving thread's msg_queue is full thanks to backpressure.
 *
 * Thus, sending all types of event messages directly from interrupt handlers to Event Thread
 * can miss important events. Specifically, when the radio receives many packets and
 * Event Thread's msg_queue is full of received packets, timer or tx_complete event can be
 * dropped, resulting in malfunction.
 *
 * Given that this thread manages urgent requests and does a very simple job, it preempts both
 * OpenThread Event Thread and OpenThread Task Thread.
 *
 * The msg_queue size of this thread can be bounded by the number of event types it handles, '2'.
 * 1) OpenThread exposes only one timer to RIOT at a time.
 * 2) OpenThread does not send a packet before receiving tx_complete event for the previous packet. 
**/
static void *_openthread_preevent_thread(void *arg) {
    _preevent_pid = thread_getpid();

    msg_init_queue(_queue, OPENTHREAD_PREEVENT_QUEUE_LEN);
    msg_t msg;

    DEBUG("ot_preevent: START!\n");

    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case OPENTHREAD_XTIMER_MSG_TYPE_EVENT:
                /* Tell event_thread a time event was received */
                DEBUG("ot_preevent: OPENTHREAD_XTIMER_MSG_TYPE_EVENT received\n");
                msg.type = OPENTHREAD_XTIMER_MSG_TYPE_EVENT;
                msg_send(&msg, openthread_get_event_pid());
                break;
            case OPENTHREAD_NETDEV_MSG_TYPE_EVENT:
                /* Tell event_thread a radio event was received (post-processing a sent packet) */
                DEBUG("ot_preevent: OPENTHREAD_NETDEV_MSG_TYPE_EVENT received\n");
                msg.type = OPENTHREAD_NETDEV_MSG_TYPE_EVENT;
                msg_send(&msg, openthread_get_event_pid());
                break;
        }
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
