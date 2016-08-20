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

static void conn_tcp_freebsd_connectDone(uint8_t ai, struct sockaddr_in6* faddr, void* ctx) {
    (void) ai;
    (void) faddr;
    (void) ctx;
}

static void conn_tcp_freebsd_sendDone(uint8_t ai, uint32_t tofree, void* ctx) {
    (void) ai;
    (void) tofree;
    (void) ctx;
}

static void conn_tcp_freebsd_receiveReady(uint8_t ai, int gotfin, void* ctx) {
    (void) ai;
    (void) gotfin;
    (void) ctx;
}

static void conn_tcp_freebsd_connectionLost(uint8_t ai, uint8_t how, void* ctx) {
    (void) ai;
    (void) how;
    (void) ctx;
}

static void conn_tcp_freebsd_acceptDone(uint8_t pi, struct sockaddr_in6* faddr, int ai, void* ctx) {
    (void) pi;
    (void) faddr;
    (void) ai;
    (void) ctx;
}

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
                conn->errstat = 0;
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
    int rv;

    struct sockaddr_in6 faddrport;

    mutex_lock(&conn->lock);
    if (addr_len != sizeof(struct in6_addr)) {
        rv = -EAFNOSUPPORT;
        goto unlockreturn;
    }
    memcpy(&faddrport.sin6_addr, addr, addr_len);
    faddrport.sin6_port = htons(port);
    if (conn->psock != -1) {
        bsdtcp_close(conn->psock);
        conn->psock = -1;
    }
    if (conn->asock == -1) {
        conn->asock = bsdtcp_active_socket(conn_tcp_freebsd_connectDone,
            conn_tcp_freebsd_sendDone, conn_tcp_freebsd_receiveReady,
            conn_tcp_freebsd_connectionLost, conn);
        if (conn->asock == -1) {
            rv = -ENOMEM;
            goto unlockboth;
        }
    }

    mutex_lock(&conn->connect_lock);
    if (bsdtcp_isestablished(conn->asock)) {
        rv = -EISCONN;
        goto unlockboth;
    }
    conn->errstat = 0;
    /* TODO fix args*/
    int error = bsdtcp_connect(conn->asock, &faddrport, NULL, 800, NULL);
    if (error != 0) {
        rv = -error;
        goto unlockboth;
    }

    /* Wait until either connection done OR connection lost */
    cond_wait(&conn->connect_cond, &conn->lock);

    rv = conn->errstat;

unlockboth:
    mutex_unlock(&conn->connect_lock);
unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
}

int conn_tcp_listen(conn_tcp_freebsd_t *conn, int queue_len)
{
    int rv;
    mutex_lock(&conn->lock);
    if (conn->asock != -1) {
        bsdtcp_abort(conn->asock);
        conn->asock = -1;
    }
    if (conn->psock == -1) {
        conn->psock = bsdtcp_passive_socket(conn_tcp_freebsd_acceptDone, conn);
        if (conn->psock == -1) {
            rv = -ENOMEM;
            goto unlockreturn;
        }
    }

    conn->errstat = 0;

    /* TODO more to do, obviously */

    rv = conn->errstat;

unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
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
