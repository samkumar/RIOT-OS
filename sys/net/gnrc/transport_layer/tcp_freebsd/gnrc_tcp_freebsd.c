/*
 * Copyright (C) 2016 University of California, Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_gnrc_tcp_freebsd
 * @{
 *
 * @file
 * @brief       TCP frontend for GNRC
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * Based partially on sys/net/gnrc/transport_layer/udp/gnrc_udp.c.
 * @}
 */

#include <stdio.h>
#include <errno.h>

#include "msg.h"
#include "thread.h"
#include "net/gnrc/tcp_freebsd.h"

#include "bsdtcp/tcp.h"
#include "bsdtcp/tcp_fsm.h"
#include "bsdtcp/tcp_var.h"

 /**
  * @brief   Save the TCP thread ID for later reference (just like the UDP
  *          implementation)
  */
static kernel_pid_t _pid = KERNEL_PID_UNDEF;

#define GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS 3
#define GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS 3

/**
 * @brief    Statically allocated pools of active and passive TCP sockets
 */
struct tcpcb tcbs[GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];
struct tcpcb_listen tcbls[GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS];

/**
 * @brief   Allocate memory for the TCP thread's stack
 */
#if ENABLE_DEBUG
static char _stack[GNRC_TCP_FREEBSD_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_TCP_FREEBSD_STACK_SIZE];
#endif

static void* _event_loop(void* arg)
{
    (void) arg;
    msg_t msg;
    msg_t setget_reply;
    msg_t msg_queue[GNRC_TCP_FREEBSD_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t netreg;

    setget_reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    setget_reply.content.value = (uint32_t) -ENOTSUP;

    msg_init_queue(msg_queue, GNRC_TCP_FREEBSD_MSG_QUEUE_SIZE);

    netreg.demux_ctx = GNRC_NETREG_DEMUX_CTX_ALL;
    netreg.pid = thread_getpid();
    gnrc_netreg_register(GNRC_NETTYPE_TCP, &netreg);

    for (;;) {
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                printf("tcp_freebsd: got RCV message: %p\n", msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                /* Not sure what kind of protocol is going to pass a packet
                 * down to TCP, since the whole point of TCP is that protocols
                 * on top of it deal with _streams_ rather than _packets_.
                 */
                printf("tcp_freebsd: got SND message: %p\n", msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SET:
            case GNRC_NETAPI_MSG_TYPE_GET:
                msg_reply(&msg, &setget_reply);
            case GNRC_NETAPI_MSG_TYPE_ACK:
                printf("tcp_freebsd: received SET, GET, or ACK\n");
                break;
            default:
                printf("tcp_freebsd: received unidentified message\n");
                break;
        }
    }

    /* not reached */
    return NULL;
}

int gnrc_tcp_freebsd_init(void)
{
    int i;

    if (_pid == KERNEL_PID_UNDEF) {
        _pid = thread_create(_stack, sizeof(_stack), GNRC_TCP_FREEBSD_PRIO,
                             THREAD_CREATE_STACKTEST, _event_loop, NULL,
                             "tcp_freebsd");

        /* Additional initialization work for TCP. */
        tcp_init();
        for (i = 0; i < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
            tcbs[i].index = i;
            initialize_tcb(&tcbs[i], 0, NULL, 0, NULL);
        }
        for (i = 0; i < GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
            tcbls[i].t_state = TCPS_CLOSED;
            tcbls[i].index = i;
            tcbls[i].lport = 0;
            tcbls[i].acceptinto = NULL;
        }
    }
    return _pid;
}
