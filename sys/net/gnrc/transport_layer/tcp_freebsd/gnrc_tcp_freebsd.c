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
 * @brief       TCP interface to the GNRC
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * Based partially on sys/net/gnrc/transport_layer/udp/gnrc_udp.c.
 * @}
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "gnrc_tcp_freebsd_internal.h"

#include "msg.h"
#include "thread.h"
#include "net/gnrc/pkt.h"
#include "net/gnrc/tcp_freebsd.h"

#include "bsdtcp/tcp.h"
#include "bsdtcp/tcp_fsm.h"
#include "bsdtcp/tcp_var.h"

#include "task_sched.h"
#include "xtimer.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#define SUCCESS 0
 /**
  * @brief   Save the TCP thread IDs for later reference (just like the UDP
  *          implementation)
  */
static kernel_pid_t _packet_pid = KERNEL_PID_UNDEF;
static kernel_pid_t _timer_pid = KERNEL_PID_UNDEF;

/**
 * @brief    Statically allocated pools of active and passive TCP sockets
 */
struct tcpcb tcbs[GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];
struct tcpcb_listen tcbls[GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS];

/**
 * @brief    Timers used for TCP. Each active socket requires four timers.
 */
static struct task_sched tcp_timer_sched;
struct task tcp_timers[GNRC_TCP_FREEBSD_NUM_TIMERS];

/**
 * @brief   Allocate memory for the TCP thread's stack
 */
#if ENABLE_DEBUG
static char _packet_stack[GNRC_TCP_FREEBSD_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
static char _timer_stack[GNRC_TCP_FREEBSD_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _packet_stack[GNRC_TCP_FREEBSD_STACK_SIZE];
static char _timer_stack[GNRC_TCP_FREEBSD_STACK_SIZE];
#endif

static void _handle_timer(int timer_id)
{
    struct tcpcb* tp;
    DEBUG("Timer %d fired!\n", timer_id);
    assert((timer_id >> 2) < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);

    tp = &tcbs[timer_id >> 2];
    timer_id &= 0x3;

    switch (timer_id) {
    case TOS_DELACK:
        DEBUG("Delayed ACK\n");
        tcp_timer_delack(tp);
        break;
    case TOS_REXMT: // Also include persist case
        if (tcp_timer_active(tp, TT_REXMT)) {
            DEBUG("Retransmit\n");
            tcp_timer_rexmt(tp);
        } else {
            DEBUG("Persist\n");
            tcp_timer_persist(tp);
        }
        break;
    case TOS_KEEP:
        DEBUG("Keep\n");
        tcp_timer_keep(tp);
        break;
    case TOS_2MSL:
        DEBUG("2MSL\n");
        tcp_timer_2msl(tp);
        break;
    }
}

/**
 *  @brief   Passes signals to the user of this module.
 */
void handle_signals(struct tcpcb* tp, uint8_t signals, uint32_t freedentries)
{
    struct sockaddr_in6 addrport;

    if (signals & SIG_CONN_ESTABLISHED) {
        addrport.sin6_port = tp->fport;
        memcpy(&addrport.sin6_addr, &tp->faddr, sizeof(addrport.sin6_addr));

        event_connectDone((uint8_t) tp->index, &addrport);
    }

    if (signals & SIG_RECVBUF_NOTEMPTY) {
        event_receiveReady((uint8_t) tp->index, 0);
    }

    if (signals & SIG_RCVD_FIN) {
        event_receiveReady((uint8_t) tp->index, 1);
    }

    if (freedentries > 0) {
        event_sendDone((uint8_t) tp->index, freedentries);
    }
}

/**
 * Called when an active socket loses a connection.
 */
void connection_lost(struct tcpcb* tcb, uint8_t errnum)
{
    event_connectionLost((uint8_t) tcb->index, errnum);
}

/**
 * Called when a passive socket accepts a connection.
 */
void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port)
{
    struct sockaddr_in6 addrport;
    addrport.sin6_port = port;
    memcpy(&addrport.sin6_addr, addr, sizeof(struct in6_addr));
    // TODO: signal acceptDone(&addrport, tpl->acceptinto->index)
    tpl->t_state = TCPS_CLOSED;
    tpl->acceptinto = NULL;
}

/**
 * @brief   Called when a TCP segment is received and passed up from the IPv6
 *          layer.
 */
static void _receive(gnrc_pktsnip_t* pkt)
{
    gnrc_pktsnip_t* tcp;
    gnrc_pktsnip_t* ipv6;
    struct tcphdr* th;
    struct tcpcb* tcb;
    struct tcpcb_listen* tcbl;
    struct ip6_hdr* iph;

    int i;
    uint16_t sport;
    uint16_t dport;
    uint16_t packet_len;

    /* Bitmask of signals that need to be sent to the user of this module. */
    uint8_t signals = 0;

    /* Number of lbuf entries that the user of this module can free. */
    uint32_t freedentries = 0;

    tcp = gnrc_pktbuf_start_write(pkt);
    if (tcp == NULL) {
        DEBUG("tcp_freebsd: unable to get write access to packet\n");
        goto error;
    }
    pkt = tcp;

    ipv6 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
    assert(ipv6 != NULL);

    iph = (struct ip6_hdr*) ipv6->data;

    /* I'm actually not going to mark the TCP section. The tcp_input function
     * is written to consider both the TCP section and the payload together,
     * and specifically making it would just take up extra memory for the new
     * pktsnip.
     */
#if 0
    if ((pkt->next != NULL) && (pkt->next->type == GNRC_NETTYPE_TCP)) {
        /* Someone already marked the TCP header, so we can just use it. */
        tcp = pkt->next;
    } else if (pkt->size >= sizeof(struct tcphdr)) {
        /* The TCP header may include options, and therefore may have variable
         * length. So we need to actually parse it first, in order to correctly
         * mark it...
         */
         th = (struct tcphdr*) pkt->data;
         if (th->th_off < 5 || th->th_off > 15) {
             goto error;
         }

         /* This is the size of the TCP header, in bytes. */
         size_t hdrlen = ((size_t) th->th_off) << 2;

         tcp = gnrc_pktbuf_mark(pkt, hdrlen, GNRC_NETTYPE_TCP);
         if (tcp == NULL) {
             DEBUG("tcp_freebsd: error marking TCP header, dropping packet\n");
             goto error;
         }
    } else {
        goto error;
    }

    /* Mark payload as type UNDEF. */
    pkt->type = GNRC_NETTYPE_UNDEF;
#endif

    th = (struct tcphdr*) tcp->data;

    packet_len = iph->ip6_plen;
    if (packet_len != ipv6->size + tcp->size) {
        DEBUG("Sizes don't add up: packet length is %" PRIu16 ", but got %zu\n", packet_len, ipv6->size + tcp->size);
        goto error;
    }
    if (th->th_off < 5 || th->th_off > 15 || (((size_t) th->th_off) << 2) > tcp->size) {
        DEBUG("Too many options: header claims %" PRIu8 " words (pktsnip has %zu bytes)\n", th->th_off, tcp->size);
    }

    /* TODO validate the checksum */

    sport = th->th_sport; // network byte order
    dport = th->th_dport; // network byte order
    tcp_fields_to_host(th);

    /* Actually do the work. */
    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
        tcb = &tcbs[i];
        if (tcb->t_state != TCP6S_CLOSED && dport == tcb->lport
            && sport == tcb->fport
            && !memcmp(&iph->ip6_src, &tcb->faddr, sizeof(iph->ip6_src))) {
            DEBUG("Matches active socket %d\n", i);
            if (RELOOKUP_REQUIRED == tcp_input(iph, th, &tcbs[i], NULL, &signals, &freedentries)) {
                break;
            } else {
                handle_signals(&tcbs[i], signals, freedentries);
            }
            return;
        }
    }

    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
        tcbl = &tcbls[i];
        if (tcbl->t_state == TCP6S_LISTEN && dport == tcbl->lport) {
            DEBUG("Matches passive socket %d\n", i);
            tcp_input(iph, th, NULL, &tcbls[i], NULL, NULL);
            return;
        }
    }

    DEBUG("Does not match any socket\n");
    tcp_dropwithreset(iph, th, NULL, tcp->size - (th->th_off << 2), ECONNREFUSED);

    return;

error:
    gnrc_pktbuf_release(pkt);
    return;
}

/**
 * @brief Event loop for received TCP segments.
 */
static void* _packet_loop(void* arg)
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
                _receive(msg.content.ptr);
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

    gnrc_tcp_freebsd_allocator_init();

    if (_packet_pid == KERNEL_PID_UNDEF) {
        _packet_pid = thread_create(_packet_stack, sizeof(_packet_stack),
                             GNRC_TCP_FREEBSD_PRIO, THREAD_CREATE_STACKTEST,
                             _packet_loop, NULL, "tcp_freebsd");
        tcp_timer_sched.coalesce_shift = 64;
        tcp_timer_sched.max_coalesce_time_delta = 0; // no coalescence for now
        tcp_timer_sched.tasks = tcp_timers;
        tcp_timer_sched.num_tasks = GNRC_TCP_FREEBSD_NUM_TIMERS;
        tcp_timer_sched.thread_stack = _timer_stack;
        tcp_timer_sched.thread_stack_size = sizeof(_timer_stack);
        tcp_timer_sched.thread_priority = GNRC_TCP_FREEBSD_PRIO;
        tcp_timer_sched.thread_name = "tcp_freebsd timers";
        tcp_timer_sched.task_handler = _handle_timer;
        _timer_pid = start_task_sched(&tcp_timer_sched);

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
    return _packet_pid;
}

/* A helper function. PORT is in network byte order. */
bool portisfree(uint16_t port)
{
    int i;
    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
        if (tcbs[i].lport == port) {
            return false;
        }
    }
    for (i = 0; i < GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
        if (tcbls[i].lport == port) {
            return false;
        }
    }
    return true;
}

/* The external API. */

int psock_getID_impl(int psockid)
{
    return tcbls[psockid].index;
}

int asock_getID_impl(int asockid)
{
    return tcbs[asockid].index;
}

int asock_getState_impl(int asockid)
{
    return tcbs[asockid].t_state;
}

void asock_getPeerInfo_impl(int asockid, struct in6_addr** addr, uint16_t** port)
{
    *addr = &tcbs[asockid].faddr;
    *port = &tcbs[asockid].fport;
}

error_t asock_bind_impl(int asockid, uint16_t port)
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

error_t psock_bind_impl(int psockid, uint16_t port)
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

error_t psock_listenaccept_impl(int psockid, int asockid, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
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

error_t asock_connect_impl(int asockid, struct sockaddr_in6* addr, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    struct tcpcb* tp = &tcbs[asockid];
    if (tp->t_state != TCPS_CLOSED) { // This is a check that I added
        return (EISCONN);
    }
    initialize_tcb(tp, tp->lport, recvbuf, recvbuflen, reassbmp);
    return tcp6_usr_connect(tp, addr);
}

error_t asock_send_impl(int asockid, struct lbufent* data, int moretocome, int* status)
{
    struct tcpcb* tp = &tcbs[asockid];
    return (error_t) tcp_usr_send(tp, moretocome, data, status);
}

error_t asock_receive_impl(int asockid, uint8_t* buffer, uint32_t len, size_t* bytessent)
{
    struct tcpcb* tp = &tcbs[asockid];
    *bytessent = cbuf_read(&tp->recvbuf, buffer, len, 1);
    return (error_t) tcp_usr_rcvd(tp);
}

error_t asock_shutdown_impl(int asockid, bool shut_rd, bool shut_wr)
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

error_t psock_close_impl(int psockid)
{
    tcbls[psockid].t_state = TCP6S_CLOSED;
    tcbls[psockid].acceptinto = NULL;
    return SUCCESS;
}

error_t asock_abort_impl(int asockid)
{
    tcp_usr_abort(&tcbs[asockid]);
    return SUCCESS;
}

/* The internal API. */

void send_message(gnrc_pktsnip_t* pkt)
{
    if (!gnrc_netapi_dispatch_send(pkt->type, GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
        DEBUG("udp: cannot send packet: network layer not found\n");
        gnrc_pktbuf_release(pkt);
    }
}

uint32_t get_millis(void)
{
    uint64_t micros = xtimer_now64();
    return micros / 1000;
}

uint32_t get_ticks(void)
{
    return get_millis();
}

void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay)
{
    int task_id = (((int) tcb->index) << 2) | (int) timer_id;
    int64_t delay_micros = MICROS_PER_TICK * (int64_t) delay;

    if (sched_task(&tcp_timer_sched, task_id, delay_micros) != 0) {
        DEBUG("sched_task failed!\n");
    }
}

void stop_timer(struct tcpcb* tcb, uint8_t timer_id)
{
    int task_id = (((int) tcb->index) << 2) | (int) timer_id;

    if (cancel_task(&tcp_timer_sched, task_id) != 0) {
        DEBUG("cancel_task failed!\n");
    }
}
