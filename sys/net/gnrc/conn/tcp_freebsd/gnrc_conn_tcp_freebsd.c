/**
* This file is subject to the terms and conditions of the GNU Lesser
* General Public License v2.1. See the file LICENSE in the top level
* directory for more details.
*/

/**
 * @{
 *
 * @file
 * @brief       Implementation of conn API for GNRC TCP derived from FreeBSD
 *
 * @author  Sam Kumar <samkumar@berkeley.edu>
 */

#include <errno.h>
#include "net/af.h"
#include "net/gnrc/conn.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/tcp_freebsd.h"
#include "net/conn/tcp_freebsd.h"
#include "net/tcp_freebsd.h"

int conn_tcp_create(conn_tcp_freebsd_t *conn, const void *addr, size_t addr_len, int family,
                    uint16_t port)
{
    conn->l4_type = GNRC_NETTYPE_TCP;
    switch (family) {
#ifdef MODULE_GNRC_IPV6
        case AF_INET6:
            if (addr_len != sizeof(ipv6_addr_t)) {
                return -EINVAL;
            }
            if (gnrc_conn6_set_local_addr((uint8_t*) &conn->local_addr, addr)) {
                conn->l3_type = GNRC_NETTYPE_IPV6;
                conn->local_port = port;
                conn->asock = -1;
                conn->psock = -1;
            }
            else {
                return -EADDRNOTAVAIL;
            }
            break;
#endif
        default:
            (void)addr;
            (void)addr_len;
            (void)port;
            return -EAFNOSUPPORT;
    }
    return 0;
}

void conn_tcp_close(conn_tcp_freebsd_t *conn)
{
    assert(conn->asock == -1 || conn->psock == -1);
    if (conn->asock != -1)
    {
        bsdtcp_close(conn->asock);
        conn->asock = -1;
    }
    if (conn->psock != -1)
    {
        bsdtcp_close(conn->psock);
        conn->psock = -1;
    }
}

int conn_tcp_getlocaladdr(conn_tcp_freebsd_t *conn, void *addr, uint16_t *port)
{
    memcpy(addr, &conn->local_addr, sizeof(ipv6_addr_t));
    *port = conn->local_port;
    return 0;
}

int conn_tcp_getpeeraddr(conn_tcp_freebsd_t *conn, void *addr, uint16_t *port)
{
    struct in6_addr* addrptr;
    uint16_t* portptr;
    if (conn->asock == -1 || !bsdtcp_isestablished(conn->asock))
    {
        return -ENOTCONN;
    }
    bsdtcp_peerinfo(conn->asock, &addrptr, &portptr);
    return 0;
}

int conn_tcp_connect(conn_tcp_freebsd_t *conn, const void *addr, size_t addr_len, uint16_t port)
{
    /* TODO */
    return 0;
}

int conn_tcp_listen(conn_tcp_freebsd_t *conn, int queue_len)
{
    /* TODO */
    return 0;
}

int conn_tcp_accept(conn_tcp_freebsd_t *conn, conn_tcp_freebsd_t *out_conn)
{
    /* TODO */
    return 0;
}

int conn_tcp_recv(conn_tcp_freebsd_t *conn, void *data, size_t max_len)
{
    /* TODO */
    return 0;
}

int conn_tcp_send(conn_tcp_freebsd_t *conn, const void *data, size_t len)
{
    /* TODO */
    return 0;
}
