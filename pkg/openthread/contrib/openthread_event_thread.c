/*
 * Copyright (C) 2017 Fundacion Inria Chile
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
 * @brief       Implementation of OpenThread Event thread
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @author      Hyung-Sin Kim <hs.kim@cs.berkeley.edu>
 * @}
 */

#include "openthread/platform/alarm-milli.h"
#include "openthread/platform/uart.h"
#include "openthread/cli.h"
#include "openthread/ip6.h"
#include "openthread/thread.h"
#include "openthread/instance.h"
#include "xtimer.h"
#include "ot.h"

#ifdef MODULE_OPENTHREAD_NCP_FTD
#include "openthread/ncp.h"
#include "openthread/commissioner.h"
#endif

#ifdef MODULE_AT86RF2XX
#include "at86rf2xx.h"
#endif

#define ENABLE_DEBUG (0)
#include "debug.h"

#define OPENTHREAD_EVENT_QUEUE_LEN (8)
static msg_t _queue[OPENTHREAD_EVENT_QUEUE_LEN];
static kernel_pid_t _event_pid;

static otInstance *sInstance;
static bool otTaskPending = false;

/* get OpenThread instance */
otInstance* openthread_get_instance(void) {
    return sInstance;
}

/* get OpenThread Event Thread pid */
kernel_pid_t openthread_get_event_pid(void) {
    return _event_pid;
}

/* OpenThread will call this when switching state from empty tasklet to non-empty tasklet. */
void otTaskletsSignalPending(otInstance *aInstance) {
    (void) aInstance;
    /* 1) Triggered in OpenThread Event Thread: just indicator update */
    if (thread_getpid() == openthread_get_event_pid()) {
        otTaskPending = true;
        msg_t msg;
        msg.type = OPENTHREAD_TASK_MSG_TYPE_EVENT;
        msg_try_send(&msg, openthread_get_task_pid()); 
    /* 2) Triggered in OpenThread Task Thread: do nothing */
    } else if (thread_getpid() == openthread_get_task_pid()) {
        ;
    /* 3) Triggered in another thread (application): message passing */
    } else {
        msg_t msg;
        msg.type = OPENTHREAD_TASK_MSG_TYPE_EVENT;
        msg_send(&msg, openthread_get_task_pid());        
    }
}

/* OpenThread Event Thread 
 * This thread processes all events by calling proper functions of OpenThread.
 * Given that processing interrupts is more urgent than processing posted tasks, this thread
 * preempts OpenThread Task Thread. It is preempted by OpenThread Preevent Thread. 
**/
static void *_openthread_event_thread(void *arg) {
    _event_pid = thread_getpid();

    msg_init_queue(_queue, OPENTHREAD_EVENT_QUEUE_LEN);
    msg_t msg, reply;

    ot_job_t *job;
    serial_msg_t* serialBuffer;

    DEBUG("ot_event: START!\n");
    /* Wait until other threads are initialized */
    xtimer_usleep(100000);

    /* Init OpenThread instance */
    sInstance = otInstanceInitSingle();
    DEBUG("OT-instance setting is OK\n");
    
    /* Init default parameters */
    otPanId panid = OPENTHREAD_PANID;
    uint8_t channel = OPENTHREAD_CHANNEL;
    otLinkSetPanId(sInstance, panid);
    otLinkSetChannel(sInstance, channel);

#if defined(MODULE_OPENTHREAD_CLI_FTD) || defined(MODULE_OPENTHREAD_CLI_MTD)
    otCliUartInit(sInstance);
    DEBUG("OT-UART initialization is OK\n");
    /* Bring up the IPv6 interface  */
    otIp6SetEnabled(sInstance, true);
    DEBUG("OT-IPv6 setting is OK\n");
    /* Start Thread operation */
    otThreadSetEnabled(sInstance, true);
    DEBUG("OT-FTD/MTD initialization is OK\n");
#endif

#ifdef MODULE_OPENTHREAD_NCP_FTD
    otNcpInit(sInstance);
    DEBUG("OT-NCP initialization is OK\n");
    //otCommissionerStart(sInstance);
    //DEBUG("OT-Commisioner initialization is OK\n");
#endif

#if OPENTHREAD_ENABLE_DIAG
    diagInit(sInstance);
#endif

    while (1) {
        msg_receive(&msg);
        //printf("\not_event start\n");
        switch (msg.type) {
            case OPENTHREAD_NETDEV_MSG_TYPE_EVENT:
                /* Received an event from radio driver */
                DEBUG("\not_event: OPENTHREAD_NETDEV_MSG_TYPE_EVENT received\n");
                /* Wait until the task thread finishes accessing the shared resoure (radio) */
                mutex_lock(openthread_get_radio_mutex());
                openthread_get_netdev()->driver->isr(openthread_get_netdev());
                mutex_unlock(openthread_get_radio_mutex());
#ifdef MODULE_OPENTHREAD_FTD
                unsigned state = irq_disable();
                ((at86rf2xx_t *)openthread_get_netdev())->pending_irq--;
                irq_restore(state);
#endif
                break;
            case OPENTHREAD_MILLITIMER_MSG_TYPE_EVENT:
                /* Tell OpenThread a millisec time event was received */
                DEBUG("\not_event: OPENTHREAD_MILLITIMER_MSG_TYPE_EVENT received\n");
                otPlatAlarmMilliFired(sInstance);
                break;
            case OPENTHREAD_SERIAL_MSG_TYPE_EVENT:
                /* Tell OpenThread about the reception of a CLI command */
                DEBUG("\not_event: OPENTHREAD_SERIAL_MSG_TYPE received\n");
                serialBuffer = (serial_msg_t*)msg.content.ptr;
                DEBUG("%s", serialBuffer->buf);
                otPlatUartReceived((uint8_t*) serialBuffer->buf,serialBuffer->length);
                serialBuffer->serial_buffer_status = OPENTHREAD_SERIAL_BUFFER_STATUS_FREE;
                break;
            case OPENTHREAD_JOB_MSG_TYPE_EVENT:
                DEBUG("\not_event: OPENTHREAD_JOB_MSG_TYPE_EVENT receimake deved\n");
                job = msg.content.ptr;
                reply.content.value = ot_exec_command(sInstance, job->command, job->arg, job->answer);
                msg_reply(&msg, &reply);
                break;
        }
        
        /* Execute this just in case a timer event is missed */
        otPlatAlarmMilliFired(sInstance);

        /* Stack overflow check */
        openthread_event_thread_overflow_check();
    }

    return NULL;
}

/* starts OpenThread Event thread */
int openthread_event_init(char *stack, int stacksize, char priority, const char *name) {

    _event_pid = thread_create(stack, stacksize, priority, THREAD_CREATE_STACKTEST,
                         _openthread_event_thread, NULL, name);

    if (_event_pid <= 0) {
        return -EINVAL;
    }

    return _event_pid;
}
