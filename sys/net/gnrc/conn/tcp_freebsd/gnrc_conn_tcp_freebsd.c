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
#include "zone/gnrc_conn_tcp_freebsd_zalloc.h"

#define ENABLE_DEBUG (0)

#include "debug.h"

static void conn_tcp_freebsd_connectDone(uint8_t ai, struct sockaddr_in6* faddr, void* ctx)
{
    (void) ai;
    (void) faddr;
    conn_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    conn->errstat = 0;
    cond_signal(&conn->connect_cond);
    mutex_unlock(&conn->lock);
}

static void conn_tcp_freebsd_sendDone(uint8_t ai, uint32_t tofree, void* ctx)
{
    (void) ai;
    (void) tofree;
    (void) ctx;
}

static void conn_tcp_freebsd_receiveReady(uint8_t ai, int gotfin, void* ctx)
{
    (void) ai;
    (void) gotfin;
    conn_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    conn->errstat = 0;
    cond_signal(&conn->receive_cond);
    mutex_unlock(&conn->lock);
}

static void conn_tcp_freebsd_connectionLost(uint8_t ai, uint8_t how, void* ctx)
{
    (void) ai;
    (void) how;
    conn_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    conn->errstat = -((int) how);
    cond_broadcast(&conn->connect_cond);
    cond_broadcast(&conn->receive_cond);
    cond_broadcast(&conn->send_cond);
    mutex_unlock(&conn->lock);
}

static acceptArgs_t conn_tcp_freebsd_acceptReady(uint8_t pi, void* ctx)
{
    void* recvbuf = conn_tcp_freebsd_zalloc(864 + (864 >> 3));
    if (recvbuf == NULL) {
        DEBUG("Out of memory in acceptReady\n");
        acceptArgs_t args;
        args.asockid = -1;
        args.recvbuf = NULL;
        args.recvbuflen = 0;
        args.reassbmp = NULL;
        return args;
    }
    conn_tcp_freebsd_t* conn = ctx;
    conn->recvbuf = recvbuf;

    /* TODO fix context */
    int asockid = bsdtcp_active_socket(conn_tcp_freebsd_connectDone,
        conn_tcp_freebsd_sendDone, conn_tcp_freebsd_receiveReady,
        conn_tcp_freebsd_connectionLost, NULL);

    acceptArgs_t args;
    args.asockid = asockid;
    args.recvbuf = recvbuf;
    args.recvbuflen = 864;
    args.reassbmp = args.recvbuf + args.recvbuflen;
    return args;
}

static void conn_tcp_freebsd_acceptDone(uint8_t pi, struct sockaddr_in6* faddr, int ai, void* ctx)
{
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
        conn->psock = bsdtcp_passive_socket(conn_tcp_freebsd_acceptReady, conn_tcp_freebsd_acceptDone, conn);
        if (conn->psock == -1) {
            rv = -ENOMEM;
            goto unlockreturn;
        }
    }

    rv = -bsdtcp_listen(conn->psock);

unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
}

int conn_tcp_accept(conn_tcp_freebsd_t *conn, conn_tcp_freebsd_t *out_conn)
{
    assert(conn->psock != -1 && conn->asock == -1);
    /* TODO */
    return 0;
}

int conn_tcp_recv(conn_tcp_freebsd_t *conn, void *data, size_t max_len)
{
    size_t bytes_read;
    int error;

    assert(conn->asock != -1 && conn->psock == -1);
    mutex_lock(&conn->lock);

    conn->errstat = 0;
    error = bsdtcp_receive(conn->asock, data, max_len, &bytes_read);
    while (bytes_read == 0 && error == 0 && conn->errstat == 0) {
        cond_wait(&conn->receive_cond, &conn->lock);
        error = bsdtcp_receive(conn->asock, data, max_len, &bytes_read);
    }

    mutex_unlock(&conn->lock);

    if (error != 0) {
        return -error;
    } else if (conn->errstat != 0) {
        return conn->errstat;
    }
    return (int) bytes_read;
}

int conn_tcp_send(conn_tcp_freebsd_t *conn, const void *data, size_t len)
{
    /* TODO */
    return 0;
}
