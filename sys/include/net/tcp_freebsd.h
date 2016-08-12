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
 * @brief       External API to TCP Stack
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * The code that provides the "raw" event-based API to the TCP stack.
 * A cleaner version supporting the BSD Socket API will be implemented
 * in the conn module.
 * @}
 */

#ifndef TCP_FREEBSD_H_
#define TCP_FREEBSD_H_

#ifdef __cplusplus
extern "C" {
#endif

int bsdtcp_active_socket(connectDone_t cd, sendDone_t sd, receiveReady_t rr, connectionLost_t cl, void* ctx);
int bsdtcp_passive_socket(acceptDone_t ad, void* ctx);
int bsdtcp_bind(int fd, uint16_t port);
int bsdtcp_connect(int fd, struct sockaddr_in6* faddrport, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp);
int bsdtcp_listenaccept(int fd, uint8_t* recvbuf, size_t recvbuflen, uint8_t* reassbmp);
int bsdtcp_send(int fd, struct lbufent* data, int* status);
int bsdtcp_receive(int fd, uint8_t* buffer, size_t length, size_t* numbytes);
int bsdtcp_shutdown(int fd, int how);
int bsdtcp_close(int fd);
int bsdtcp_abort(int fd);
int bsdtcp_isestablished(int fd);
int bsdtcp_hasrcvdfin(int fd);
int bsdtcp_peerinfo(int fd, struct in6_addr** addrptr, uint16_t** portptr);

#ifdef __cplusplus
}
#endif

#endif

/** @} */
