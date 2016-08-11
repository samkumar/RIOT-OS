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
 * @brief       TCP socket allocator for GNRC
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * The code that provides the "raw" API for usage of this TCP module; in other
 * words, the frontend of the TCP module.
 * @}
 */

#include "gnrc_tcp_freebsd_internal.h"
#include "bsdtcp/lbuf.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#define ENABLE_DEBUG (0)
#include "debug.h"

typedef void (*connectDone_t)(uint8_t, struct sockaddr_in6*, void*);
typedef void (*sendDone_t)(uint8_t, uint32_t, void*);
typedef void (*receiveReady_t)(uint8_t, int, void*);
typedef void (*connectionLost_t)(uint8_t, uint8_t, void*);
typedef void (*acceptDone_t)(uint8_t, struct sockaddr_in6*, int, void*);

typedef struct asock {
    connectDone_t connectDone;
    sendDone_t sendDone;
    receiveReady_t receiveReady;
    connectionLost_t connectionLost;
    void* context;
} active_socket_t;

typedef struct psock {
    int acceptinginto;
    acceptDone_t acceptDone;
    void* context;
} passive_socket_t;

active_socket_t activesockets[GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS];
passive_socket_t passivesockets[GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS];

/* Bitmasks to keep track of which sockets are allocated. */
uint8_t activemask[1 + ((GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS - 1) >> 3)];
uint8_t passivemask[1 + ((GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS - 1) >> 3)];

inline int _is_allocated(uint8_t* mask, int fd)
{
    return mask[fd >> 3] & (1 << (fd & 0x7));
}

inline void _force_alloc(uint8_t* mask, int fd)
{
    mask[fd >> 3] |= (1 << (fd & 0x7));
}

inline void _force_dealloc(uint8_t* mask, int fd)
{
    mask[fd >> 3] &= ~(1 << (fd & 0x7));
}

int alloc_fd(uint8_t* mask, int num_fds, bool (*isvalid)(int) ) {
    int i;
    for (i = 0; i < num_fds; i++) {
        if (!_is_allocated(mask, i) && isvalid(i)) {
            _force_alloc(mask, i);
            return i;
        }
    }
    return -1;
}

bool _always_true(int pi)
{
    return true;
}

bool _active_isclosed(int ai)
{
    return TCPS_CLOSED == asock_getState_impl(ai);
}

bool _active_istimewait(int ai)
{
    return TCPS_TIME_WAIT == asock_getState_impl(ai);
}

int alloc_pfd(void) {
    int pfd = alloc_fd(passivemask, GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS, _always_true);
    return pfd + GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS;
}

int alloc_afd(void) {
    int afd;
    // First, try to get a socket that's closed.
    afd = alloc_fd(activemask, GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS, _active_isclosed);
    if (afd == -1) {
        // If that failed, try to get a socket in TIME-WAIT, and end the TIME-WAIT early.
        afd = alloc_fd(activemask, GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS, _active_istimewait);
        asock_abort_impl(afd);
    }
    return afd;
}

/* External API */
int bsdtcp_active_socket(connectDone_t cd, sendDone_t sd, receiveReady_t rr, connectionLost_t cl)
{
    /* Return a socket handle. */
    return 0;
}

int bsdtcp_passive_socket(acceptDone_t ad)
{
    /* Return a passive socket handle. */
    return 0;
}

int bsdtcp_bind(int fd, uint16_t port)
{
    /* TODO */
    return 0;
}

int bsdtcp_connect(int fd, const struct sockaddr_in6* faddrport, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    /* TODO */
    return 0;
}

int bsdtcp_listenaccept(int fd, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp)
{
    /* TODO */
    return 0;
}

int bsdtcp_send(int fd, struct lbufent* data, int* status)
{
    /* TODO */
    return 0;
}

int bsdtcp_receive(int fd, uint8_t* buffer, size_t length, size_t* numbytes)
{
    /* TODO */
    return 0;
}

int bsdtcp_shutdown(int fd, int how)
{
    /* TODO */
    return 0;
}

int bsdtcp_close(int fd)
{
    /* TODO */
    return 0;
}

int bsdtcp_abort(int fd)
{
    /* TODO */
    return 0;
}

int bsdtcp_isestablished(int fd)
{
    /* TODO */
    return 0;
}

int bsdtcp_hasrcvdfin(int fd)
{
    /* TODO */
    return 0;
}

void bsdtcp_peerinfo(int fd, struct in6_addr** addrptr, uint16_t** portptr)
{
    /* TODO */
}

/* API to the TCP frontend. */
void event_acceptDone(uint8_t pi, struct sockaddr_in6* addr, int asockid)
{
    assert(pi >= 0 && pi < GNRC_TCP_FREEBSD_NUM_PASSIVE_SOCKETS);
    assert(_is_allocated(passivemask, pi + GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS));

    passive_socket_t* psock = &passivesockets[pi];
    assert(psock->acceptinginto == asockid);

    if (psock->acceptDone != NULL) {
        psock->acceptDone(pi, addr, psock->acceptinginto, psock->context);
    }
    psock->acceptinginto = -1;
}

void event_connectDone(uint8_t ai, struct sockaddr_in6* addr)
{
    assert(ai >= 0 && ai < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);
    assert(_is_allocated(activemask, ai));

    active_socket_t* asock = &activesockets[ai];

    if (asock->connectDone != NULL) {
        asock->connectDone(ai, addr, asock->context);
    }
}

void event_receiveReady(uint8_t ai, int gotfin)
{
    assert(ai >= 0 && ai < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);
    assert(_is_allocated(activemask, ai));

    active_socket_t* asock = &activesockets[ai];

    if (asock->receiveReady != NULL) {
        asock->receiveReady(ai, gotfin, asock->context);
    }
}

void event_sendDone(uint8_t ai, uint32_t numentries)
{
    assert(ai >= 0 && ai < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);
    assert(_is_allocated(activemask, ai));

    active_socket_t* asock = &activesockets[ai];

    if (asock->sendDone != NULL) {
        asock->sendDone(ai, numentries, asock->context);
    }
}

void event_connectionLost(uint8_t ai, uint8_t how)
{
    assert(ai >= 0 && ai < GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS);
    assert(_is_allocated(activemask, ai));

    active_socket_t* asock = &activesockets[ai];

    if (asock->connectionLost != NULL) {
        asock->connectionLost(ai, how, asock->context);
    }
}

void gnrc_tcp_freebsd_allocator_init(void) {
    memset(&activesockets, 0x00, sizeof(activesockets));
    memset(&passivesockets, 0x00, sizeof(passivesockets));
    memset(activemask, 0x00, sizeof(activemask));
    memset(passivemask, 0x00, sizeof(passivemask));
}
