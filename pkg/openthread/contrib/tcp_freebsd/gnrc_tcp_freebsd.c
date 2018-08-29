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

//#include "gnrc_sock_internal.h"
#include "gnrc_tcp_freebsd_internal.h"

#include "msg.h"
#include "thread.h"
#include "net/gnrc/pkt.h"
#include "../include/tcp_freebsd.h"
#include "netinet/in.h"

#include <openthread/ip6.h>
#include <openthread/types.h>
#include <openthread/message.h>
#include <openthread/thread.h>
#include "ot.h"

#include "bsdtcp/tcp.h"
#include "bsdtcp/tcp_fsm.h"
#include "bsdtcp/tcp_var.h"

#include "task_sched.h"
#include "xtimer.h"

#include "ot.h"
#include "mutex.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define SUCCESS 0
 /**
  * @brief   Save the TCP thread IDs for later reference (just like the UDP
  *          implementation)
  */
static kernel_pid_t _packet_pid = KERNEL_PID_UNDEF;
static kernel_pid_t _timer_pid = KERNEL_PID_UNDEF;

mutex_t tcp_lock = MUTEX_INIT;

/**
 * @brief    Statically allocated pools of active and passive TCP sockets
 */
struct tcpcb tcbs[GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];
struct tcpcb_listen tcbls[GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS];
uint8_t tcp_poll_state[1 + ((GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS-1) >> 2)]; //two bits per TCB

/**
 * @brief    Timers used for TCP. Each active socket requires four timers, plus
 *           one to control the polling frequency.
 */
static struct task_sched tcp_timer_sched;
struct task tcp_timers[GNRC_TCP_FREEBSD_NUM_TIMERS + GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];
bool fast_poll_scheduled[GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];

/**
 * @brief   Allocate memory for the TCP thread's stack
 */
#define GNRC_TCP_FREEBSD_STACK_SIZE 1024
#define GNRC_TCP_FREEBSD_PRIO 14
#if ENABLE_DEBUG
//static char _packet_stack[GNRC_TCP_FREEBSD_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
static char _timer_stack[GNRC_TCP_FREEBSD_STACK_SIZE/* + THREAD_EXTRA_STACKSIZE_PRINTF*/];
#else
//static char _packet_stack[GNRC_TCP_FREEBSD_STACK_SIZE];
static char _timer_stack[GNRC_TCP_FREEBSD_STACK_SIZE];
#endif

#define TCP_FAST_POLL_MILLISECONDS (100)
#define TCP_SLOW_POLL_MILLISECONDS (10000)

#define TCP_NO_POLL 0x0
#define TCP_SLOW_POLL 0x1
#define TCP_FAST_POLL 0x2

#define TCP_MIN_POLL_DELAY_MILLISECONDS 16

static uint32_t tcp_get_poll_delay_milliseconds(int index) {
    struct tcpcb* tp = &tcbs[index];
    if (tp->t_srtt == 0) {
        // No RTT estimate? Then start after 16 ms.
        return TCP_MIN_POLL_DELAY_MILLISECONDS;
    }
    int srtt_minus_4rttvar_milliseconds = ((tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT)) - tp->t_rttvar) >> TCP_DELTA_SHIFT;
    int half_rtt_milliseconds = tp->t_srtt >> (TCP_RTT_SHIFT + 1);

    int poll_delay_milliseconds;
    if (srtt_minus_4rttvar_milliseconds < half_rtt_milliseconds) {
        poll_delay_milliseconds = srtt_minus_4rttvar_milliseconds;
    } else {
        poll_delay_milliseconds = half_rtt_milliseconds;
    }

    if (poll_delay_milliseconds < TCP_MIN_POLL_DELAY_MILLISECONDS) {
        poll_delay_milliseconds = TCP_MIN_POLL_DELAY_MILLISECONDS;
    }
    return (uint32_t) poll_delay_milliseconds;
}

static int current_poll_state = TCP_NO_POLL;
static uint8_t tcp_get_poll_state(int index) {
    return (tcp_poll_state[index >> 2] >> ((index & 0x3) << 1)) & 0x3;
}
static void _update_tcp_poll_state(void) {
    uint8_t new_state = TCP_NO_POLL;
    for (int i = 0; i != GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
        uint8_t state = tcp_get_poll_state(i);
        if (state > new_state) {
            new_state = state;
        }
    }
    if (new_state != current_poll_state) {
        printf("[tcp] Switching poll state: %d -> %d\n", current_poll_state, new_state);
        current_poll_state = new_state;
        switch (current_poll_state) {
            case TCP_NO_POLL:
                otThreadSetMaxPollInterval(openthread_get_instance(), 0);
                break;
            case TCP_SLOW_POLL:
                otThreadSetMaxPollInterval(openthread_get_instance(), TCP_SLOW_POLL_MILLISECONDS);
                break;
            case TCP_FAST_POLL:
                otThreadSetMaxPollInterval(openthread_get_instance(), TCP_FAST_POLL_MILLISECONDS);
                break;
        }
    }
}
static void tcp_set_poll_state(int index, uint8_t state) {
    uint8_t byte = tcp_poll_state[index >> 2];
    uint8_t shift = (index & 0x3) << 1;
    uint8_t masked = byte & (0xFF << shift);

    fast_poll_scheduled[index] = false;
    if (cancel_task(&tcp_timer_sched, GNRC_TCP_FREEBSD_NUM_TIMERS + index) != 0) {
        DEBUG("cancel_task failed!\n");
    }

    if (masked == (state << shift)) {
        return;
    }
    tcp_poll_state[index >> 2] = (byte ^ masked) | (state << shift);
    _update_tcp_poll_state();
}

static void tcp_fast_poll_timed(int index) {
    uint32_t poll_delay_milliseconds = tcp_get_poll_delay_milliseconds(index);
    printf("Delaying for %d milliseconds\n", (int) poll_delay_milliseconds);
    fast_poll_scheduled[index] = true;
    if (sched_task(&tcp_timer_sched, GNRC_TCP_FREEBSD_NUM_TIMERS + index, poll_delay_milliseconds * 1000) != 0) {
        DEBUG("sched_task failed!\n");
    }
}

static void _handle_timer(int timer_id)
{
    struct tcpcb* tp;
    DEBUG("Timer %d fired!\n", timer_id);

    openthread_lock_coarse_mutex();
    mutex_lock(&tcp_lock);
    if (timer_id < GNRC_TCP_FREEBSD_NUM_TIMERS) {
        // TCP timer

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

    } else {
        // Poll timer
        int asockid = timer_id - GNRC_TCP_FREEBSD_NUM_TIMERS;
        if (fast_poll_scheduled[asockid]) {
            tcp_set_poll_state(asockid, TCP_FAST_POLL);
        }
    }

    mutex_unlock(&tcp_lock);
    openthread_unlock_coarse_mutex();
}

/**
 *  @brief   Passes signals to the user of this module.
 */
void handle_signals(struct tcpcb* tp, uint8_t signals)
{
    struct sockaddr_in6 addrport;

    if (signals & SIG_CONN_ESTABLISHED && !tpispassiveopen(tp)) {
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

    if (signals & SIG_SENDBUF_NOTFULL) {
        event_sendReady((uint8_t) tp->index);
    }

    if (signals & SIG_SENDBUF_EMPTY) {
        tcp_set_poll_state(tp->index, TCP_NO_POLL);
    }
}

void _fill_acceptArgs_from_tcpcb(acceptArgs_t* args, struct tcpcb* tcb) {
    args->asockid = tcb->index;
    args->recvbuf = tcb->recvbuf.buf;
    args->recvbuflen = tcb->recvbuf.size;
    args->reassbmp = tcb->reassbmp;
}

/**
 * Called when an active socket loses a connection.
 */
void connection_lost(struct tcpcb* tcb, uint8_t errnum)
{
    acceptArgs_t args;
    _fill_acceptArgs_from_tcpcb(&args, tcb);
    mutex_unlock(&tcp_lock);
    event_connectionLost(&args, errnum);
    mutex_lock(&tcp_lock);
}

/**
 * Called when a passive socket is about to accept a connection,
 * and needs an active socket to accept into.
 */
struct tcpcb* accept_ready(struct tcpcb_listen* tpl)
{
    acceptArgs_t args;
    mutex_unlock(&tcp_lock);
    args = event_acceptReady((uint8_t) tpl->index);
    mutex_lock(&tcp_lock);
    if (args.asockid == -1) {
        return NULL;
    }
    assert(args.asockid >= 0 && args.asockid < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);
    struct tcpcb* asock = &tcbs[args.asockid];
    initialize_tcb(asock, NULL, asock->lport, args.sendbuf, args.sendbuflen, args.recvbuf, args.recvbuflen, args.reassbmp);
    return asock;
}

/**
 * Called when a passive socket accepts a connection.
 */
bool accepted_connection(struct tcpcb_listen* tpl, struct tcpcb* accepted, struct in6_addr* addr, uint16_t port)
{
    bool accepted_successfully;
    struct sockaddr_in6 addrport;
    acceptArgs_t acceptedArgs;
    _fill_acceptArgs_from_tcpcb(&acceptedArgs, accepted);
    mutex_unlock(&tcp_lock);
    addrport.sin6_port = port;
    memcpy(&addrport.sin6_addr, addr, sizeof(struct in6_addr));
    accepted_successfully = event_acceptDone((uint8_t) tpl->index, &addrport, &acceptedArgs);
    mutex_lock(&tcp_lock);

    return accepted_successfully;
}

/**
 * Called when a TCB transitions to a new state.
 */
void on_state_change(struct tcpcb* tp, int newstate) {
    /* Update polling state. */
    switch (newstate) {
        case TCP6S_SYN_SENT:
        case TCP6S_SYN_RECEIVED:
        case TCP6S_FIN_WAIT_1:
        case TCP6S_FIN_WAIT_2:
        case TCP6S_CLOSING:
        case TCP6S_CLOSE_WAIT:
        case TCP6S_LAST_ACK:
            tcp_set_poll_state(tp->index, TCP_FAST_POLL);
            break;
        case TCP6S_ESTABLISHED:
        case TCP6S_CLOSED:
            tcp_set_poll_state(tp->index, TCP_NO_POLL);
            break;
        case TCP6S_TIME_WAIT:
            tcp_set_poll_state(tp->index, TCP_SLOW_POLL);
            break;
    }
}

int sent_pkts = 0;
int recv_pkts = 0;
int bad_cksum_pkts = 0;

/**
 * @brief   Called when a TCP segment is received and passed up from the IPv6
 *          layer.
 */
void tcp_freebsd_receive(void* iphdr, otMessage* message, otMessageInfo* info)
{
    //gnrc_pktsnip_t* tcp;
    //gnrc_pktsnip_t* ipv6;
    struct tcphdr* th;
    struct tcpcb* tcb;
    struct tcpcb_listen* tcbl;
    struct ip6_hdr* iph;

    int i;
    uint16_t sport;
    uint16_t dport;
    uint16_t packet_len;

    uint16_t empirical_len;
    //gnrc_pktsnip_t* temp;

    /* Bitmask of signals that need to be sent to the user of this module. */
    uint8_t signals = 0;

    /*
     * In this entrypoint, the openthread lock is held, so there is no need
     * to acquire it here.
     */

    /* Number of lbuf entries that the user of this module can free. */
    //uint32_t freedentries = 0;

    /* Extra 40 bytes is for TCP Options */
    char tcphdrbuf[sizeof(struct tcphdr) + 40];

    iph = iphdr;
    th = (struct tcphdr*) &tcphdrbuf[0];

    otMessageRead(message, otMessageGetOffset(message), th, sizeof(struct tcphdr));

    packet_len = htons(iph->ip6_plen);
    empirical_len = otMessageGetLength(message) - otMessageGetOffset(message);

    if (packet_len != empirical_len) {
        DEBUG("Sizes don't add up: packet length is %" PRIu16 ", but got %" PRIu16 "\n", packet_len, empirical_len);
        goto done;
    }
    if (th->th_off < 5 || th->th_off > 15 || (((size_t) th->th_off) << 2) > empirical_len) {
        DEBUG("Too many options: header claims %" PRIu8 " words (pktsnip has %u bytes)\n", th->th_off, (unsigned int) empirical_len);
    }
    otMessageRead(message, otMessageGetOffset(message) + sizeof(struct tcphdr), th + 1, (th->th_off << 2) - sizeof(struct tcphdr));

    struct tcp_checksum_state cksum_state;
    cksum_state.partial_sum = (uint32_t) otMessageChecksum(0x0000u, message);
    cksum_state.half_read = false;
    tcp_checksum_pseudoheader(&cksum_state, info, empirical_len);
    uint16_t csum = tcp_checksum_finalize(&cksum_state);
    if (csum != 0) {
        printf("Dropping packet: bad checksum (%" PRIu16 ")\n", csum);
        bad_cksum_pkts++;
        goto done;
    }

    recv_pkts++;

    sport = th->th_sport; // network byte order
    dport = th->th_dport; // network byte order
    tcp_fields_to_host(th);

    /* Actually do the work. */
    for (i = 0; i != GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
        tcb = &tcbs[i];
        if (tcb->t_state != TCP6S_CLOSED && dport == tcb->lport
            && sport == tcb->fport
            && !memcmp(&iph->ip6_src, &tcb->faddr, sizeof(iph->ip6_src))) {
            int rv;
            DEBUG("Matches active socket %d\n", i);
            mutex_lock(&tcp_lock);
            rv = tcp_input(iph, th, message, &tcbs[i], NULL, &signals);
            mutex_unlock(&tcp_lock);
            if (RELOOKUP_REQUIRED == rv) {
                break;
            } else {
                handle_signals(&tcbs[i], signals);
            }
            goto done;
        }
    }

    for (i = 0; i != GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
        tcbl = &tcbls[i];
        if (tcbl->t_state == TCP6S_LISTEN && dport == tcbl->lport) {
            DEBUG("Matches passive socket %d\n", i);
            mutex_lock(&tcp_lock);
            tcp_input(iph, th, message, NULL, &tcbls[i], NULL);
            mutex_unlock(&tcp_lock);
            goto done;
        }
    }

    DEBUG("Does not match any socket\n");
    tcp_dropwithreset(iph, th, NULL, empirical_len - (th->th_off << 2), ECONNREFUSED);

done:
    return;
}

#if 0
/**
 * @brief Event loop for received TCP segments.
 */
static void* _packet_loop(void* arg)
{
    (void) arg;
    msg_t msg;
    msg_t setget_reply;
    msg_t msg_queue[GNRC_TCP_FREEBSD_MSG_QUEUE_SIZE];

    /* _packet_pid may not be assigned, if the scheduler switches to this thread
     * before thread_create returns, or after thread_create returns but before
     * the return value is stored.
     */
    _packet_pid = thread_getpid();

    gnrc_netreg_entry_t netreg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            _packet_pid);

    setget_reply.type = GNRC_NETAPI_MSG_TYPE_ACK;
    setget_reply.content.value = (uint32_t) -ENOTSUP;

    msg_init_queue(msg_queue, GNRC_TCP_FREEBSD_MSG_QUEUE_SIZE);

    if (gnrc_netreg_register(GNRC_NETTYPE_TCP, &netreg)) {
        DEBUG("Error listening for packets\n");
    }

    for (;;) {
        msg_receive(&msg);
        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("tcp_freebsd: got RCV message: %p\n", msg.content.ptr);
                _receive(msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                /* Not sure what kind of protocol is going to pass a packet
                 * down to TCP, since the whole point of TCP is that protocols
                 * on top of it deal with _streams_ rather than _packets_.
                 */
                DEBUG("tcp_freebsd: got SND message: %p\n", msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SET:
            case GNRC_NETAPI_MSG_TYPE_GET:
                msg_reply(&msg, &setget_reply);
            case GNRC_NETAPI_MSG_TYPE_ACK:
                DEBUG("tcp_freebsd: received SET, GET, or ACK\n");
                break;
            default:
                DEBUG("tcp_freebsd: received unidentified message\n");
                break;
        }
    }

    /* not reached */
    return NULL;
}

#endif

int gnrc_tcp_freebsd_init(void)
{
    int i;

    gnrc_tcp_freebsd_allocator_init();

    //if (_packet_pid == KERNEL_PID_UNDEF) {
        /*_packet_pid = thread_create(_packet_stack, sizeof(_packet_stack),
                             GNRC_TCP_FREEBSD_PRIO, THREAD_CREATE_STACKTEST,
                             _packet_loop, NULL, "tcp_freebsd");*/
        tcp_timer_sched.coalesce_shift = 64;
        tcp_timer_sched.max_coalesce_time_delta = 0; // no coalescence for now
        tcp_timer_sched.tasks = tcp_timers;
        tcp_timer_sched.num_tasks = GNRC_TCP_FREEBSD_NUM_TIMERS + GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS;
        tcp_timer_sched.thread_stack = _timer_stack;
        tcp_timer_sched.thread_stack_size = sizeof(_timer_stack);
        tcp_timer_sched.thread_priority = GNRC_TCP_FREEBSD_PRIO;
        tcp_timer_sched.thread_name = "tcp_freebsd timers";
        tcp_timer_sched.task_handler = _handle_timer;
        _timer_pid = start_task_sched(&tcp_timer_sched);

        /* Additional initialization work for TCP. */
        tcp_init();
        for (i = 0; i != GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS; i++) {
            tcbs[i].index = i;
            initialize_tcb(&tcbs[i], NULL, 0, NULL, 0, NULL, 0, NULL);
            fast_poll_scheduled[i] = false;
        }
        for (i = 0; i != GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS; i++) {
            tcbls[i].t_state = TCPS_CLOSED;
            tcbls[i].index = i;
            tcbls[i].lport = 0;
        }
        memset(tcp_poll_state, 0x00, sizeof(tcp_poll_state));
    //}
    return _packet_pid;
}

/* A helper function. PORT is in network byte order. */
bool gnrc_tcp_freebsd_portisfree(uint16_t port)
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
    mutex_lock(&tcp_lock);
    *addr = &tcbs[asockid].faddr;
    *port = &tcbs[asockid].fport;
    mutex_unlock(&tcp_lock);
}

const struct in6_addr* get_default_ipv6_address(void) {
    return (const struct in6_addr*) otThreadGetMeshLocalEid(openthread_get_instance());
}

const struct in6_addr* get_source_ipv6_address(const struct in6_addr* peer) {
    const otNetifAddress* source = otIp6SelectSourceAddress(openthread_get_instance(), (const otIp6Address*) peer);
    return (const struct in6_addr*) &source->mAddress;
}

error_t asock_bind_impl(int asockid, const struct in6_addr* address, uint16_t port)
{
    error_t rv;
    uint16_t oldport;
    mutex_lock(&tcp_lock);
    oldport = tcbs[asockid].lport;
    port = htons(port);
    tcbs[asockid].lport = 0;
    if (port == 0 || gnrc_tcp_freebsd_portisfree(port)) {
        tcbs[asockid].lport = port;
        memcpy(&tcbs[asockid].laddr, address, sizeof(struct in6_addr));
        rv = SUCCESS;
        goto done;
    }
    tcbs[asockid].lport = oldport;
    rv = EADDRINUSE;
done:
    mutex_unlock(&tcp_lock);
    return rv;
}

error_t psock_bind_impl(int psockid, const struct in6_addr* address, uint16_t port)
{
    error_t rv;
    uint16_t oldport;
    mutex_lock(&tcp_lock);
    oldport = tcbls[psockid].lport;
    port = htons(port);
    tcbls[psockid].lport = 0;
    if (port == 0 || gnrc_tcp_freebsd_portisfree(port)) {
        tcbls[psockid].lport = port;
        if (memcmp(address, &in6addr_any, sizeof(struct in6_addr)) == 0) {
            address = get_default_ipv6_address();
        }
        memcpy(&tcbs[psockid].laddr, address, sizeof(struct in6_addr));
        rv = SUCCESS;
        goto done;
    }
    tcbls[psockid].lport = oldport;
    rv = EADDRINUSE;
done:
    mutex_unlock(&tcp_lock);
    return rv;
}

error_t psock_listen_impl(int psockid)
{
    mutex_lock(&tcp_lock);
    tcbls[psockid].t_state = TCPS_LISTEN;
    mutex_unlock(&tcp_lock);
    return SUCCESS;
}

error_t asock_connect_impl(int asockid, struct sockaddr_in6* addr, uint8_t* sendbuf, size_t sendbuflen, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    error_t rv;
    struct tcpcb* tp = &tcbs[asockid];
    mutex_lock(&tcp_lock);
    if (tp->t_state != TCP6S_CLOSED) { // This is a check that I added
        rv = EISCONN;
        goto done;
    }
    {
        // TODO: restructure code to avoid copying laddr like this?
        struct in6_addr laddr;
        memcpy(&laddr, &tp->laddr, sizeof(struct in6_addr));
        initialize_tcb(tp, &laddr, tp->lport, sendbuf, sendbuflen, recvbuf, recvbuflen, reassbmp);
    }
    rv = (error_t) tcp6_usr_connect(tp, addr);

done:
    mutex_unlock(&tcp_lock);
    return rv;
}

error_t asock_send_impl(int asockid, const uint8_t* data, size_t len, int moretocome, size_t* bytessent)
{
    error_t rv;
    struct tcpcb* tp = &tcbs[asockid];
    openthread_lock_coarse_mutex();
    mutex_lock(&tcp_lock);
    bool was_empty = cbuf_empty(&tp->sendbuf);
    rv = (error_t) tcp_usr_send(tp, moretocome, data, len, bytessent);
    if (was_empty && !cbuf_empty(&tp->sendbuf)) {
        //printf("rtt = %d, rttvar = %d\n", tp->t_srtt >> TCP_RTT_SHIFT, tp->t_rttvar >> TCP_RTTVAR_SHIFT);
        tcp_fast_poll_timed(asockid);
    }
    mutex_unlock(&tcp_lock);
    openthread_unlock_coarse_mutex();
    return rv;
}

error_t asock_receive_impl(int asockid, uint8_t* buffer, uint32_t len, size_t* bytesrcvd)
{
    error_t rv;
    struct tcpcb* tp = &tcbs[asockid];
    openthread_lock_coarse_mutex();
    mutex_lock(&tcp_lock);
    *bytesrcvd = cbuf_read(&tp->recvbuf, buffer, 0, len, 1, cbuf_copy_into_buffer);
    rv = (error_t) tcp_usr_rcvd(tp);
    mutex_unlock(&tcp_lock);
    openthread_unlock_coarse_mutex();
    return rv;
}

error_t asock_shutdown_impl(int asockid, bool shut_rd, bool shut_wr)
{
    int error = SUCCESS;
    openthread_lock_coarse_mutex();
    mutex_lock(&tcp_lock);
    if (shut_rd) {
        cbuf_pop(&tcbs[asockid].recvbuf, cbuf_used_space(&tcbs[asockid].recvbuf)); // remove all data from the cbuf
        // TODO We need to deal with bytes received out-of-order
        // Our strategy is to "pretend" that we got those extra bytes and ACK them.
        tpcantrcvmore(&tcbs[asockid]);
    }
    if (shut_wr) {
        error = tcp_usr_shutdown(&tcbs[asockid]);
    }
    mutex_unlock(&tcp_lock);
    openthread_unlock_coarse_mutex();
    return error;
}

error_t psock_close_impl(int psockid)
{
    mutex_lock(&tcp_lock);
    tcbls[psockid].t_state = TCP6S_CLOSED;
    mutex_unlock(&tcp_lock);
    return SUCCESS;
}

error_t asock_abort_impl(int asockid)
{
    openthread_lock_coarse_mutex();
    mutex_lock(&tcp_lock);
    tcp_usr_abort(&tcbs[asockid]);
    mutex_unlock(&tcp_lock);
    openthread_unlock_coarse_mutex();
    return SUCCESS;
}

/* The internal API. */

otMessage* new_message(void)
{
    otInstance* instance = openthread_get_instance();
    otMessage* message = otIp6NewMessageForTransport(instance, false);
    if (message == NULL) {
        printf("Message allocation failed for TCP\n");
    }
    return message;
}

void free_message(otMessage* pkt) {
    otMessageFree(pkt);
}

void send_message(otMessage* pkt, otMessageInfo* info)
{
    DEBUG("Sending TCP message: %p %p, payload_size = %d\n", pkt, info, otMessageGetLength(pkt));
    sent_pkts++;
    otInstance* instance = openthread_get_instance();
    otIp6SendAsTransport(instance, pkt, info, 6);
}

void tcp_freebsd_finalize_cksum(otMessage* pkt, uint16_t pseudoheader_cksum) {
    uint16_t cksum = otMessageChecksum(0x0000u, pkt);
    uint32_t sum = ((uint32_t) cksum) + ((uint32_t) pseudoheader_cksum);
    cksum = ((uint16_t) sum) + (uint16_t) (sum >> 16);
    cksum = ~htons(cksum);
    otMessageWrite(pkt, otMessageGetOffset(pkt) + 16, &cksum, 2);
}

uint64_t get_micros(void)
{
    return xtimer_now_usec64();
}

uint32_t get_millis(void)
{
    uint64_t micros = xtimer_now_usec64();
    return micros / 1000;
}

uint32_t get_ticks(void)
{
    return get_millis();
}


/*
 * The lock ordering for the timing code is that the TCP lock is always
 * acquired first, and then the timer lock.
 */
void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay)
{
    int task_id = (((int) tcb->index) << 2) | (int) timer_id;
    int64_t delay_micros = MICROS_PER_TICK * (int64_t) delay;

    DEBUG("Setting timer %d: %d\n", task_id, (int) (delay_micros / 1000));

    if (sched_task(&tcp_timer_sched, task_id, delay_micros) != 0) {
        DEBUG("sched_task failed!\n");
    }
}

void stop_timer(struct tcpcb* tcb, uint8_t timer_id)
{
    int task_id = (((int) tcb->index) << 2) | (int) timer_id;

    DEBUG("Stopping timer %d\n", task_id);

    if (cancel_task(&tcp_timer_sched, task_id) != 0) {
        DEBUG("cancel_task failed!\n");
    }
}
