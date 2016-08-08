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
#include <stdint.h>
#include <errno.h>

#include "gnrc_tcp_freebsd_internal.h"

#include "msg.h"
#include "thread.h"
#include "net/gnrc/tcp_freebsd.h"

#include "bsdtcp/tcp.h"
#include "bsdtcp/tcp_fsm.h"
#include "bsdtcp/tcp_var.h"

#define SUCCESS 0

static const int TRUE = 1;
static const int FALSE = 0;

 /**
  * @brief   Save the TCP thread ID for later reference (just like the UDP
  *          implementation)
  */
static kernel_pid_t _pid = KERNEL_PID_UNDEF;

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

/* A helper function. PORT is in network byte order. */
bool portisfree(uint16_t port)
{
    int i;
    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
        if (tcbs[i].lport == port) {
            return FALSE;
        }
    }
    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
        if (tcbls[i].lport == port) {
            return FALSE;
        }
    }
    return TRUE;
}

/* The external API. */

int psock_getID(uint8_t psockid)
{
    return tcbls[psockid].index;
}

int asock_getID(uint8_t asockid)
{
    return tcbs[asockid].index;
}

int asock_getState(uint8_t asockid)
{
    return tcbs[asockid].t_state;
}

void asock_getPeerInfo(uint8_t asockid, struct in6_addr** addr, uint16_t** port)
{
    *addr = &tcbs[asockid].faddr;
    *port = &tcbs[asockid].fport;
}

error_t asock_bind(uint8_t asockid, uint16_t port)
{
    uint16_t oldport = tcbs[asockid].lport;
    port = htons(port);
    tcbs[asockid].lport = 0;
    if (port == 0 || portisfree(port)) {
        tcbs[asockid].lport = port;
        return SUCCESS;
    }
    tcbs[asockid].lport = oldport;
    return EADDRINUSE;
}

error_t psock_bind(uint8_t psockid, uint16_t port)
{
    uint16_t oldport = tcbls[psockid].lport;
    port = htons(port);
    tcbls[psockid].lport = 0;
    if (port == 0 || portisfree(port)) {
        tcbls[psockid].lport = port;
        return SUCCESS;
    }
    tcbls[psockid].lport = oldport;
    return EADDRINUSE;
}

error_t psock_listenaccept(uint8_t psockid, int asockid, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    tcbls[psockid].t_state = TCPS_LISTEN;
    if (tcbs[asockid].t_state != TCPS_CLOSED) {
        tcbls[psockid].t_state = TCPS_CLOSED;
        return EISCONN;
    }
    initialize_tcb(&tcbs[asockid], tcbs[asockid].lport, recvbuf, recvbuflen, reassbmp);
    tcbls[psockid].acceptinto = &tcbs[asockid];
    return SUCCESS;
}

error_t asock_connect(uint8_t asockid, struct sockaddr_in6* addr, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    struct tcpcb* tp = &tcbs[asockid];
    if (tp->t_state != TCPS_CLOSED) { // This is a check that I added
        return (EISCONN);
    }
    initialize_tcb(tp, tp->lport, recvbuf, recvbuflen, reassbmp);
    return tcp6_usr_connect(tp, addr);
}

error_t asock_send(uint8_t asockid, struct lbufent* data, int moretocome, int* status)
{
    struct tcpcb* tp = &tcbs[asockid];
    return (error_t) tcp_usr_send(tp, moretocome, data, status);
}

error_t asock_receive(uint8_t asockid, uint8_t* buffer, uint32_t len, size_t* bytessent)
{
    struct tcpcb* tp = &tcbs[asockid];
    *bytessent = cbuf_read(&tp->recvbuf, buffer, len, 1);
    return (error_t) tcp_usr_rcvd(tp);
}

error_t asock_shutdown(uint8_t asockid, bool shut_rd, bool shut_wr)
{
    int error = SUCCESS;
    if (shut_rd) {
        cbuf_pop(&tcbs[asockid].recvbuf, cbuf_used_space(&tcbs[asockid].recvbuf)); // remove all data from the cbuf
        // TODO We need to deal with bytes received out-of-order
        // Our strategy is to "pretend" that we got those extra bytes and ACK them.
        tpcantrcvmore(&tcbs[asockid]);
    }
    if (shut_wr) {
        error = tcp_usr_shutdown(&tcbs[asockid]);
    }
    return error;
}

error_t psock_close(uint8_t psockid)
{
    tcbls[psockid].t_state = TCP6S_CLOSED;
    tcbls[psockid].acceptinto = NULL;
    return SUCCESS;
}

error_t asock_abort(uint8_t asockid)
{
    tcp_usr_abort(&tcbs[asockid]);
    return SUCCESS;
}

/* The internal API. */

void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen)
{
    /* TODO */
}

uint32_t get_ticks(void)
{
    /* TODO */
    return 0;
}

uint32_t get_millis(void)
{
    /* TODO */
    return 0;
}

void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay)
{
    /* TODO */
}

void stop_timer(struct tcpcb* tcb, uint8_t timer_id)
{
    /* TODO */
}

void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port)
{
    /* TODO */
}

void connection_lost(struct tcpcb* tcb, uint8_t errnum)
{
    /* TODO */
}

void ip_free(void* ptr)
{
    (void) ptr;
}

void* ip_malloc(size_t len)
{
    return NULL;
}
