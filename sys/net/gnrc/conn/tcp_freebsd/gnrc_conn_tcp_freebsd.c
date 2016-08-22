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

#define RECV_BUF_LEN 864
#define REASS_BMP_LEN ((RECV_BUF_LEN + 7) >> 3)

static void conn_tcp_freebsd_connectDone(uint8_t ai, struct sockaddr_in6* faddr, void* ctx)
{
    assert(ctx != NULL);
    (void) ai;
    (void) faddr;
    conn_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    conn->errstat = 0;
    cond_signal(&conn->sfields.active.connect_cond);
    mutex_unlock(&conn->lock);
}

static void conn_tcp_freebsd_sendDone(uint8_t ai, uint32_t tofree, void* ctx)
{
    assert(ctx != NULL);
    (void) ai;
    (void) tofree;
    (void) ctx;
}

static void conn_tcp_freebsd_receiveReady(uint8_t ai, int gotfin, void* ctx)
{
    // ctx might actually be NULL, in which case we just ignore this.
    (void) ai;
    (void) gotfin;
    conn_tcp_freebsd_t* conn = ctx;
    if (conn == NULL) {
        // We got data on a socket on the accept queue that hasn't been accepted yet
        return;
    }
    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    conn->errstat = 0;
    cond_signal(&conn->sfields.active.receive_cond);
    mutex_unlock(&conn->lock);
}

static void conn_tcp_freebsd_connectionLost(uint8_t ai, uint8_t how, void* ctx)
{
    (void) ai;
    (void) how;
    conn_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    conn->errstat = -((int) how);
    cond_broadcast(&conn->sfields.active.connect_cond);
    cond_broadcast(&conn->sfields.active.receive_cond);
    cond_broadcast(&conn->sfields.active.send_cond);
    mutex_unlock(&conn->lock);
}

static acceptArgs_t conn_tcp_freebsd_acceptReady(uint8_t pi, void* ctx)
{
    assert(ctx != NULL);
    conn_tcp_freebsd_t* conn = ctx;

    mutex_lock(&conn->lock);
    assert(conn->haspassive && !conn->hasactive);

    void* recvbuf = conn_tcp_freebsd_zalloc(RECV_BUF_LEN + REASS_BMP_LEN);
    if (recvbuf == NULL) {
        DEBUG("Out of memory in acceptReady\n");
        acceptArgs_t args;
        args.asockid = -1;
        args.recvbuf = NULL;
        args.recvbuflen = 0;
        args.reassbmp = NULL;
        mutex_unlock(&conn->lock);
        return args;
    }

    int asockid = bsdtcp_active_socket(conn_tcp_freebsd_connectDone,
        conn_tcp_freebsd_sendDone, conn_tcp_freebsd_receiveReady,
        conn_tcp_freebsd_connectionLost, NULL);

    acceptArgs_t args;
    args.asockid = asockid;
    args.recvbuf = recvbuf;
    args.recvbuflen = RECV_BUF_LEN;
    args.reassbmp = ((uint8_t*) args.recvbuf) + RECV_BUF_LEN;

    mutex_unlock(&conn->lock);
    return args;
}

static void conn_tcp_freebsd_acceptDone(uint8_t pi, struct sockaddr_in6* faddr, int ai, void* ctx)
{
    assert(ctx != NULL);
    (void) pi;
    (void) faddr;
    (void) ai;
    (void) ctx;
}


static void conn_tcp_general_init(conn_tcp_freebsd_t* conn, uint16_t port)
{
    conn->l3_type = GNRC_NETTYPE_IPV6;
    conn->l4_type = GNRC_NETTYPE_TCP;

    conn->local_port = port;

    mutex_init(&conn->lock);
    conn->errstat = 0;
    conn->hasactive = false;
    conn->haspassive = false;
}

static void conn_tcp_passive_clear(conn_tcp_freebsd_t* conn)
{
    if (conn->haspassive) {
        conn->haspassive = false;
        bsdtcp_close(conn->sfields.passive.psock);
        cond_broadcast(&conn->sfields.passive.accept_cond);
    }
}

static void conn_tcp_active_clear(conn_tcp_freebsd_t* conn)
{

    if (conn->hasactive) {
        conn->hasactive = false;
        mutex_lock(&conn->sfields.active.connect_lock);
        conn_tcp_freebsd_zfree(conn->sfields.active.recvbuf);
        bsdtcp_close(conn->sfields.active.asock);
        cond_broadcast(&conn->sfields.active.connect_cond);
        cond_broadcast(&conn->sfields.active.receive_cond);
        cond_broadcast(&conn->sfields.active.send_cond);
    }
}

static bool conn_tcp_active_set(conn_tcp_freebsd_t* conn)
{
    conn_tcp_passive_clear(conn);
    if (!conn->hasactive) {
        conn->hasactive = true;
        conn->sfields.active.asock = bsdtcp_active_socket(conn_tcp_freebsd_connectDone,
            conn_tcp_freebsd_sendDone, conn_tcp_freebsd_receiveReady,
            conn_tcp_freebsd_connectionLost, conn);
        if (conn->sfields.active.asock == -1) {
            conn->hasactive = false;
            return false;
        }
        conn->sfields.active.recvbuf = conn_tcp_freebsd_zalloc(RECV_BUF_LEN + REASS_BMP_LEN);
        if (conn->sfields.active.recvbuf == NULL) {
            conn->hasactive = false;
            bsdtcp_close(conn->sfields.active.asock);
            conn->sfields.active.asock = -1;
            return false;
        }
        mutex_init(&conn->sfields.active.connect_lock);
        cond_init(&conn->sfields.active.connect_cond);
        cond_init(&conn->sfields.active.receive_cond);
        cond_init(&conn->sfields.active.send_cond);
    }
    return true;
}

static bool conn_tcp_passive_set(conn_tcp_freebsd_t* conn)
{
    conn_tcp_active_clear(conn);
    if (!conn->haspassive) {
        conn->haspassive = true;
        conn->sfields.passive.psock = bsdtcp_passive_socket(conn_tcp_freebsd_acceptReady, conn_tcp_freebsd_acceptDone, conn);
        if (conn->sfields.passive.psock == -1) {
            conn->haspassive = false;
            return false;
        }
        cond_init(&conn->sfields.passive.accept_cond);
    }
    return true;
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
                conn_tcp_general_init(conn, port);
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
    mutex_lock(&conn->lock);
    assert(!(conn->hasactive && conn->haspassive));
    conn_tcp_active_clear(conn);
    conn_tcp_passive_clear(conn);
    mutex_unlock(&conn->lock);
}

int conn_tcp_getlocaladdr(conn_tcp_freebsd_t *conn, void *addr, uint16_t *port)
{
    mutex_lock(&conn->lock);
    memcpy(addr, &conn->local_addr, sizeof(ipv6_addr_t));
    *port = conn->local_port;
    mutex_unlock(&conn->lock);
    return 0;
}

int conn_tcp_getpeeraddr(conn_tcp_freebsd_t *conn, void *addr, uint16_t *port)
{
    struct in6_addr* addrptr;
    uint16_t* portptr;
    mutex_lock(&conn->lock);
    if (!conn->hasactive || !bsdtcp_isestablished(conn->sfields.active.asock))
    {
        mutex_unlock(&conn->lock);
        return -ENOTCONN;
    }
    bsdtcp_peerinfo(conn->sfields.active.asock, &addrptr, &portptr);
    mutex_unlock(&conn->lock);
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
    bool res = conn_tcp_active_set(conn);
    if (!res) {
        rv = -ENOMEM;
        goto unlockreturn;
    }

    mutex_lock(&conn->sfields.active.connect_lock);
    if (bsdtcp_isestablished(conn->sfields.active.asock)) {
        rv = -EISCONN;
        goto unlockboth;
    }
    conn->errstat = 0;
    int error = bsdtcp_connect(conn->sfields.active.asock, &faddrport,
        conn->sfields.active.recvbuf, RECV_BUF_LEN,
        ((uint8_t*) conn->sfields.active.recvbuf) + RECV_BUF_LEN);
    if (error != 0) {
        rv = -error;
        goto unlockboth;
    }

    /* Wait until either connection done OR connection lost */
    cond_wait(&conn->sfields.active.connect_cond, &conn->lock);

    rv = conn->errstat;

unlockboth:
    mutex_unlock(&conn->sfields.active.connect_lock);
unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
}

int conn_tcp_listen(conn_tcp_freebsd_t *conn, int queue_len)
{
    int rv;
    mutex_lock(&conn->lock);
    bool res = conn_tcp_passive_set(conn);
    if (!res) {
        rv = -ENOMEM;
        goto unlockreturn;
    }

    rv = -bsdtcp_listen(conn->sfields.passive.psock);

unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
}

int conn_tcp_accept(conn_tcp_freebsd_t *conn, conn_tcp_freebsd_t *out_conn)
{
    if (!conn->hasactive && conn->haspassive) {
        return -EINVAL;
    }
    /* TODO */
    return 0;
}

int conn_tcp_recv(conn_tcp_freebsd_t *conn, void *data, size_t max_len)
{
    size_t bytes_read;
    int error;

    assert(conn->hasactive && !conn->haspassive);
    mutex_lock(&conn->lock);

    conn->errstat = 0;
    error = bsdtcp_receive(conn->sfields.active.asock, data, max_len, &bytes_read);
    while (bytes_read == 0 && error == 0 && conn->errstat == 0) {
        cond_wait(&conn->sfields.active.receive_cond, &conn->lock);
        error = bsdtcp_receive(conn->sfields.active.asock, data, max_len, &bytes_read);
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
