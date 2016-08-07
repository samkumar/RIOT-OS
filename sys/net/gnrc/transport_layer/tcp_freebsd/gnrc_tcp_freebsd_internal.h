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
 * @brief       Internal API to the TCP frontend for GNRC
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * This file describes the API that the TCP frontend presents to the TCP
 * protocol logic. The protocol logic interacts with other parts of the
 * kernel (GNRC, xtimer, etc.) via this API.
 * @}
 */

#ifndef GNRC_TCP_FREEBSD_INTERNAL_H_
#define GNRC_TCP_FREEBSD_INTERNAL_H_

#include <stdio.h>
#include "bsdtcp/ip6.h"
#include "bsdtcp/tcp.h"
#include "bsdtcp/tcp_fsm.h"
#include "bsdtcp/tcp_timer.h"
#include "bsdtcp/tcp_var.h"

#define GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS 3
#define GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS 3

#define IANA_TCP PROTNUM_TCP

struct tcp_hdr {
  uint16_t srcport;
  uint16_t dstport;
  uint32_t seqno;
  uint32_t ackno;
  uint8_t offset;
  uint8_t flags;
  uint16_t window;
  uint16_t chksum;
  uint16_t urgent;
};

#define hz 1000 // number of ticks per second
#define MILLIS_PER_TICK 1 // number of milliseconds per tick

#define FRAMES_PER_SEG 3
#define FRAMECAP_6LOWPAN (122 - 22 - 12) // Fragmentation limit: maximum frame size of the IP and TCP headers

#define COMPRESSED_IP6HDR_SIZE (2 + 1 + 1 + 16 + 8) // IPHC header (2) + Next header (1) + Hop count (1) + Dest. addr (16) + Src. addr (8)

#define SIG_CONN_ESTABLISHED 0x01
#define SIG_RECVBUF_NOTEMPTY 0x02
#define SIG_RCVD_FIN         0x04

#define CONN_LOST_NORMAL 0 // errno of 0 means that the connection closed gracefully

struct ip6_packet {
    // Dummy for now
    struct ip6_hdr ip6_hdr;
    struct ip_iovec* ip6_data;
};

void send_message(struct tcpcb* tp, struct ip6_packet* msg, struct tcphdr* th, uint32_t tlen);
uint32_t get_ticks(void);
uint32_t get_millis(void);
void set_timer(struct tcpcb* tcb, uint8_t timer_id, uint32_t delay);
void stop_timer(struct tcpcb* tcb, uint8_t timer_id);
void accepted_connection(struct tcpcb_listen* tpl, struct in6_addr* addr, uint16_t port);
void connection_lost(struct tcpcb* tcb, uint8_t errnum);

/* For now */
void ip_free(void* ptr);

void* ip_malloc(size_t len);

#endif // GNRC_TCP_FREEBSD_INTERNAL_H_
