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
#include "net/iana/portrange.h"
#include "net/af.h"
#include "net/sock.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/ipv6.h"
//#include "net/gnrc/tcp_freebsd.h"
//#include "net/sock/tcp_freebsd.h"
#include "sock_tcp_freebsd.h"
#include "tcp_freebsd.h"

#define ENABLE_DEBUG (0)

#include "debug.h"

#define NACTIVESOCKS 1
#define SEND_BUF_LEN 2310
#define RECV_BUF_LEN 100
#define REASS_BMP_LEN ((RECV_BUF_LEN + 7) >> 3)

struct buffers {
    uint8_t send_buffer[SEND_BUF_LEN];
    uint8_t recv_buffer[RECV_BUF_LEN];
    uint8_t reass_buffer[REASS_BMP_LEN];
    bool allocated;
};
static struct buffers buffer_pool[NACTIVESOCKS];

#define NPASSIVESOCKS 1
#define ACCEPT_QUEUE_LEN 4
#define ACCEPT_QUEUE_SHIFT 2

struct queues {
    uint8_t accept_queue[ACCEPT_QUEUE_LEN];
    bool allocated;
};
static struct queues queue_pool[NPASSIVESOCKS];

//#ifndef SOCK_HAS_IPV6
//#error "TCP FREEBSD requires IPv6"
//#endif

static void allocate_buffers(int asockid) {
    assert(asockid >= 0);
    assert(asockid < NACTIVESOCKS);
    assert(!buffer_pool[asockid].allocated);
    buffer_pool[asockid].allocated = true;
}

static void deallocate_buffers(int asockid) {
    assert(asockid >= 0);
    assert(asockid < NACTIVESOCKS);
    assert(buffer_pool[asockid].allocated);
    buffer_pool[asockid].allocated = false;
}

static void allocate_queues(int psockid) {
    assert(psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS >= 0);
    assert(psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS < NACTIVESOCKS);
    assert(!queue_pool[psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].allocated);
    queue_pool[psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].allocated = true;
}

static void deallocate_queues(int psockid) {
    assert(psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS >= 0);
    assert(psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS < NACTIVESOCKS);
    assert(queue_pool[psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].allocated);
    queue_pool[psockid - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].allocated = false;
}

#if 0
/* Cached copy buffer, which may help us avoid a dynamic memory allocation. */
struct sock_tcp_freebsd_send_state* extracopybuf = NULL;

static uint32_t _free_sendstates(sock_tcp_freebsd_t* conn, uint32_t howmany) {
    uint32_t totalbytesremoved = 0;
    uint32_t i;

    struct sock_tcp_freebsd_send_state* head;
    struct sock_tcp_freebsd_send_state* newhead;
    for (i = 0; (i < howmany) && (conn->sfields.active.send_head != NULL); i++) {
        head = conn->sfields.active.send_head;
        newhead = head->next;
        totalbytesremoved += (head->buflen - head->entry.extraspace);
        if (head->buflen == COPYBUFSIZE && extracopybuf == NULL) {
            /* Hang on to the reference, to avoid a future memory allocation. */
            extracopybuf = head;
        } else {
            sock_tcp_freebsd_zfree(head);
        }
        conn->sfields.active.send_head = newhead;
    }
    if (conn->sfields.active.send_head == NULL) {
        conn->sfields.active.send_tail = NULL;
    }
    assert(totalbytesremoved <= conn->sfields.active.in_send_buffer);
    conn->sfields.active.in_send_buffer -= totalbytesremoved;
    return totalbytesremoved;
}
#endif

static void sock_tcp_freebsd_connectDone(uint8_t ai, struct sockaddr_in6* faddr, void* ctx)
{
    assert(ctx != NULL);
    (void) ai;
    (void) faddr;
    sock_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    conn->errstat = 0;
    cond_signal(&conn->sfields.active.connect_cond);
    mutex_unlock(&conn->lock);
}

static void sock_tcp_freebsd_sendReady(uint8_t ai, void* ctx)
{
    sock_tcp_freebsd_t* conn = ctx;
    assert(conn != NULL);

    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    assert(conn->sfields.active.asock == ai);
    cond_broadcast(&conn->sfields.active.send_cond);
    mutex_unlock(&conn->lock);
}

static void sock_tcp_freebsd_receiveReady(uint8_t ai, int gotfin, void* ctx)
{
    // ctx might actually be NULL, in which case we just ignore this.
    (void) ai;
    (void) gotfin;
    sock_tcp_freebsd_t* conn = ctx;
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

static void sock_tcp_freebsd_connectionLost(acceptArgs_t* lost, uint8_t how, void* ctx)
{
    (void) how;
    if (ctx == NULL) {
        /*
         * This could happen if we get a SYN, so that acceptReady is called, but the
         * connection dies before a SYN-ACK is received, so the socket never hits
         * the accept queue.
         * In that case, we need to free the receive buffer, which we allocated.
         */
        deallocate_buffers(lost->asockid);
        return;
    }
    sock_tcp_freebsd_t* conn = ctx;
    mutex_lock(&conn->lock);
    assert(conn->hasactive && !conn->haspassive);
    conn->errstat = -((int) how);
    cond_broadcast(&conn->sfields.active.connect_cond);
    cond_broadcast(&conn->sfields.active.receive_cond);
    cond_broadcast(&conn->sfields.active.send_cond);
    mutex_unlock(&conn->lock);
}

static acceptArgs_t sock_tcp_freebsd_acceptReady(uint8_t pi, void* ctx)
{
    /* To be returned after filling in members. */
    acceptArgs_t args;

    assert(ctx != NULL);
    sock_tcp_freebsd_t* conn = ctx;

    mutex_lock(&conn->lock);
    assert(conn->haspassive && !conn->hasactive);

    int asockid = bsdtcp_active_socket(sock_tcp_freebsd_connectDone,
        sock_tcp_freebsd_sendReady, sock_tcp_freebsd_receiveReady,
        sock_tcp_freebsd_connectionLost, NULL);

    if (asockid == -1) {
        goto fail;
    }

    allocate_buffers(asockid);

    args.asockid = asockid;
    args.sendbuf = buffer_pool[asockid].send_buffer;
    args.sendbuflen = SEND_BUF_LEN;
    args.recvbuf = buffer_pool[asockid].recv_buffer;
    args.recvbuflen = RECV_BUF_LEN;
    args.reassbmp = buffer_pool[asockid].reass_buffer;

done:
    mutex_unlock(&conn->lock);
    return args;

fail:
    args.asockid = -1;
    args.sendbuf = NULL;
    args.sendbuflen = 0;
    args.recvbuf = NULL;
    args.recvbuflen = 0;
    args.reassbmp = NULL;

    goto done;
}

static bool sock_tcp_freebsd_acceptDone(uint8_t pi, struct sockaddr_in6* faddr, acceptArgs_t* accepted, void* ctx)
{
    (void) pi;
    (void) faddr;

    int putidx;

    sock_tcp_freebsd_t* conn = ctx;
    assert(conn != NULL);

    mutex_lock(&conn->lock);
    assert(conn->haspassive && !conn->hasactive);


    putidx = cib_put(&conn->sfields.passive.accept_cib);
    if (putidx == -1) {
        DEBUG("accept queue full\n");
        mutex_unlock(&conn->lock);
        return false;
    }

    queue_pool[conn->sfields.passive.psock - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].accept_queue[putidx] = (uint8_t) accepted->asockid;

    cond_signal(&conn->sfields.passive.accept_cond);

    mutex_unlock(&conn->lock);

    return true;
}


static void sock_tcp_freebsd_general_init(sock_tcp_freebsd_t* conn, uint16_t port)
{
    //conn->l3_type = GNRC_NETTYPE_IPV6;
    //conn->l4_type = GNRC_NETTYPE_TCP;

    conn->local_port = port;

    mutex_init(&conn->lock);
    conn->pending_ops = 0;
    cond_init(&conn->pending_cond);

    conn->errstat = 0;
    conn->hasactive = false;
    conn->haspassive = false;
}

/*
 * Note: conn->lock MUST be held when any of the four Functions
 * sock_tcp_freebsd_{active, passive}_{set, clear} are called.
 */

static void sock_tcp_freebsd_passive_clear(sock_tcp_freebsd_t* conn)
{
    if (conn->haspassive) {
        int asockidx;

        conn->haspassive = false;

        // All pending calls should exit with this error
        conn->errstat = EPIPE;

        cond_broadcast(&conn->sfields.passive.accept_cond);
        // Let any pending "accept" calls respond to the broadcast and exit.
        while (conn->pending_ops != 0) {
            cond_wait(&conn->pending_cond, &conn->lock);
        }

        bsdtcp_close(conn->sfields.passive.psock);

        while ((asockidx = cib_get(&conn->sfields.passive.accept_cib)) != -1) {
            int asock = (int) queue_pool[conn->sfields.passive.psock - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].accept_queue[asockidx];
            bsdtcp_close(asock);
            deallocate_buffers(asock);
        }
        deallocate_queues(conn->sfields.passive.psock);

        conn->errstat = 0;
    }
}

static void sock_tcp_freebsd_active_clear(sock_tcp_freebsd_t* conn)
{
    if (conn->hasactive) {
        conn->hasactive = false;

        // All pending calls should exit with this error
        conn->errstat = EPIPE;

        cond_broadcast(&conn->sfields.active.connect_cond);
        cond_broadcast(&conn->sfields.active.receive_cond);
        cond_broadcast(&conn->sfields.active.send_cond);

        /*
         * Let any pending "send", "receive", or "connect" calls respond to
         * the broadcast and exit.
         */
        while (conn->pending_ops != 0) {
            cond_wait(&conn->pending_cond, &conn->lock);
        }

        bsdtcp_close(conn->sfields.active.asock);
        deallocate_buffers(conn->sfields.active.asock);

        conn->errstat = 0;
    }
}

static bool sock_tcp_freebsd_active_set(sock_tcp_freebsd_t* conn, int asock)
{
    sock_tcp_freebsd_passive_clear(conn);
    if (!conn->hasactive) {
        conn->hasactive = true;
        if (asock == -1) {
            conn->sfields.active.asock = bsdtcp_active_socket(sock_tcp_freebsd_connectDone,
                sock_tcp_freebsd_sendReady, sock_tcp_freebsd_receiveReady,
                sock_tcp_freebsd_connectionLost, conn);
            if (conn->sfields.active.asock == -1) {
                conn->hasactive = false;
                return false;
            }

            allocate_buffers(conn->sfields.active.asock);

        } else {
            conn->sfields.active.asock = asock;
            /* How to get the recvbuf? */
        }
        bsdtcp_bind(conn->sfields.active.asock, (struct in6_addr*) &conn->local_addr, conn->local_port);

        conn->sfields.active.is_connecting = false;
        cond_init(&conn->sfields.active.connect_cond);
        cond_init(&conn->sfields.active.receive_cond);
        cond_init(&conn->sfields.active.send_cond);
    }
    return true;
}

static bool sock_tcp_freebsd_passive_set(sock_tcp_freebsd_t* conn, int queue_len)
{
    assert(queue_len >= 0 && queue_len < (1 << (8 * sizeof(int) - 2)));
    if (queue_len > ACCEPT_QUEUE_LEN) {
        queue_len = ACCEPT_QUEUE_LEN;
    }

    sock_tcp_freebsd_active_clear(conn);
    if (!conn->haspassive) {
        conn->haspassive = true;
        conn->sfields.passive.psock = bsdtcp_passive_socket(sock_tcp_freebsd_acceptReady, sock_tcp_freebsd_acceptDone, conn);
        if (conn->sfields.passive.psock == -1) {
            conn->haspassive = false;
            return false;
        }
        bsdtcp_bind(conn->sfields.passive.psock, (struct in6_addr*) &conn->local_addr, conn->local_port);

        cond_init(&conn->sfields.passive.accept_cond);

        /* Set adj_queue_len to the power of two above queue_len. */
        unsigned int adj_queue_len = 1;
        while (queue_len != 0) {
            queue_len >>= 1;
            adj_queue_len <<= 1;
        }
        adj_queue_len >>= 1;

        cib_init(&conn->sfields.passive.accept_cib, adj_queue_len);
        allocate_queues(conn->sfields.passive.psock);
    }
    return true;
}

/*
 * This used to be in sys/net/gnrc/conn/gnrc_conn.c, as the function
 * gnrc_conn6_set_local_addr. I'm duplicating the code here, as conn is
 * deprecated and so I don't want to pull it in as a dependency.
 */
bool sock_tcp_freebsd_set_local_ipv6_addr(uint8_t *conn_addr, const ipv6_addr_t *addr)
{
    /*ipv6_addr_t *tmp;*/
    if (!ipv6_addr_is_unspecified(addr) &&
        !ipv6_addr_is_loopback(addr)/* &&
        gnrc_ipv6_netif_find_by_addr(&tmp, addr) == KERNEL_PID_UNDEF*/) {
        return false;
    }
    else if (ipv6_addr_is_loopback(addr) || ipv6_addr_is_unspecified(addr)) {
        ipv6_addr_set_unspecified((ipv6_addr_t *)conn_addr);
    }
    else {
        memcpy(conn_addr, addr, sizeof(ipv6_addr_t));
    }
    return true;
}

#define IANA_DYNAMIC_PORTRANGE_NUM (IANA_DYNAMIC_PORTRANGE_MAX - IANA_DYNAMIC_PORTRANGE_MIN + 1)

#define PORTRANGE_OFFSET 17
#define PORTRANGE_ERROR 0

static uint16_t _dyn_port_next = 0;
/**
 * @brief   returns a UDP port, and checks for reuse if required
 * I copied this from the sock_udp module, with a minor modification.
 *
 * complies to RFC 6056, see https://tools.ietf.org/html/rfc6056#section-3.3.3
 */
static uint16_t _get_dyn_port(sock_tcp_freebsd_t *sock)
{
    uint16_t port;
    unsigned count = IANA_DYNAMIC_PORTRANGE_NUM;
    do {
        port = IANA_DYNAMIC_PORTRANGE_MIN +
               (_dyn_port_next * PORTRANGE_OFFSET) % IANA_DYNAMIC_PORTRANGE_NUM;
        _dyn_port_next++;
        if ((sock == NULL) || gnrc_tcp_freebsd_portisfree(port)) {
            return port;
        }
        --count;
    } while (count > 0);
    return PORTRANGE_ERROR;
}

int sock_tcp_freebsd_create(sock_tcp_freebsd_t *conn, const void *addr, size_t addr_len, int family,
                    uint16_t port)
{
    //conn->l4_type = GNRC_NETTYPE_TCP;
    switch (family) {
//#ifdef MODULE_GNRC_IPV6
        case AF_INET6:
            if (addr_len != sizeof(ipv6_addr_t)) {
                return -EINVAL;
            }
            if (port == 0) {
                port = _get_dyn_port(conn);
                if (port == PORTRANGE_ERROR) {
                    return -EADDRINUSE;
                }
            }
            if (sock_tcp_freebsd_set_local_ipv6_addr((uint8_t*) &conn->local_addr, addr)) {
                sock_tcp_freebsd_general_init(conn, port);
            }
            else {
                return -EADDRNOTAVAIL;
            }
            break;
//#endif
        default:
            (void)addr;
            (void)addr_len;
            (void)port;
            return -EAFNOSUPPORT;
    }
    return 0;
}

void sock_tcp_freebsd_close(sock_tcp_freebsd_t *conn)
{
    mutex_lock(&conn->lock);
    assert(!(conn->hasactive && conn->haspassive));
    sock_tcp_freebsd_active_clear(conn);
    sock_tcp_freebsd_passive_clear(conn);
    mutex_unlock(&conn->lock);
}

int sock_tcp_freebsd_getlocaladdr(sock_tcp_freebsd_t *conn, void *addr, uint16_t *port)
{
    mutex_lock(&conn->lock);
    memcpy(addr, &conn->local_addr, sizeof(ipv6_addr_t));
    *port = conn->local_port;
    mutex_unlock(&conn->lock);
    return 0;
}

int sock_tcp_freebsd_getpeeraddr(sock_tcp_freebsd_t *conn, void *addr, uint16_t *port)
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
    memcpy(addr, addrptr, sizeof(struct in6_addr));
    *port = *portptr;
    mutex_unlock(&conn->lock);
    return 0;
}

int sock_tcp_freebsd_connect(sock_tcp_freebsd_t *conn, const void *addr, size_t addr_len, uint16_t port)
{
    int rv;

    struct sockaddr_in6 faddrport;

    mutex_lock(&conn->lock);
    if (conn->sfields.active.is_connecting) {
        mutex_unlock(&conn->lock);
        return -EALREADY;
    }
    conn->sfields.active.is_connecting = true;

    conn->pending_ops += 1;

    if (addr_len != sizeof(struct in6_addr)) {
        rv = -EAFNOSUPPORT;
        goto unlockreturn;
    }
    memcpy(&faddrport.sin6_addr, addr, addr_len);
    faddrport.sin6_port = htons(port);
    bool res = sock_tcp_freebsd_active_set(conn, -1);
    if (!res) {
        rv = -ENOMEM;
        goto unlockreturn;
    }

    if (bsdtcp_isestablished(conn->sfields.active.asock)) {
        rv = -EISCONN;
        goto unlockreturn;
    }
    conn->errstat = 0;
    int error = bsdtcp_connect(conn->sfields.active.asock, &faddrport,
        buffer_pool[conn->sfields.active.asock].send_buffer, SEND_BUF_LEN,
        buffer_pool[conn->sfields.active.asock].recv_buffer, RECV_BUF_LEN,
        buffer_pool[conn->sfields.active.asock].reass_buffer);
    if (error != 0) {
        rv = -error;
        sock_tcp_freebsd_active_clear(conn);
        goto unlockreturn;
    }

    /* Wait until either connection done OR connection lost */
    cond_wait(&conn->sfields.active.connect_cond, &conn->lock);

    rv = conn->errstat;

unlockreturn:
    conn->sfields.active.is_connecting = false;
    conn->pending_ops -= 1;
    if (conn->pending_ops == 0) {
        cond_signal(&conn->pending_cond);
    }
    mutex_unlock(&conn->lock);
    return rv;
}

int sock_tcp_freebsd_listen(sock_tcp_freebsd_t *conn, int queue_len)
{
    int rv;
    mutex_lock(&conn->lock);
    bool res = sock_tcp_freebsd_passive_set(conn, queue_len);
    if (!res) {
        rv = -ENOMEM;
        goto unlockreturn;
    }

    rv = -bsdtcp_listen(conn->sfields.passive.psock);

unlockreturn:
    mutex_unlock(&conn->lock);
    return rv;
}

int sock_tcp_freebsd_accept(sock_tcp_freebsd_t* conn, sock_tcp_freebsd_t* out_conn)
{
    mutex_lock(&conn->lock);
    if (!conn->haspassive) {
        mutex_unlock(&conn->lock);
        return -EINVAL;
    }

    assert(!conn->hasactive);

    conn->pending_ops += 1;

    int asockidx;
    while ((asockidx = cib_get(&conn->sfields.passive.accept_cib)) == -1) {
        cond_wait(&conn->sfields.passive.accept_cond, &conn->lock);
    }

    int asock = (int) queue_pool[conn->sfields.passive.psock - GNRC_TCP_FREEBSD_NUM_ACTIVE_SOCKETS].accept_queue[asockidx];

    memcpy(&out_conn->local_addr, &conn->local_addr, sizeof(ipv6_addr_t));
    sock_tcp_freebsd_general_init(out_conn, conn->local_port);

    mutex_lock(&out_conn->lock);
    sock_tcp_freebsd_active_set(out_conn, asock);
    int rv = bsdtcp_set_ctx(asock, out_conn);
    assert(rv == 0);
    (void) rv;
    mutex_unlock(&out_conn->lock);

    conn->pending_ops -= 1;
    if (conn->pending_ops == 0) {
        cond_signal(&conn->pending_cond);
    }

    mutex_unlock(&conn->lock);
    return 0;
}

int sock_tcp_freebsd_recv(sock_tcp_freebsd_t *conn, void *data, size_t max_len)
{
    size_t bytes_read;
    int error;

    assert(conn->hasactive && !conn->haspassive);
    mutex_lock(&conn->lock);
    conn->pending_ops += 1;

    conn->errstat = 0;
    error = bsdtcp_receive(conn->sfields.active.asock, data, max_len, &bytes_read);
    while (bytes_read == 0 && error == 0 && conn->errstat == 0 && !bsdtcp_hasrcvdfin(conn->sfields.active.asock)) {
        cond_wait(&conn->sfields.active.receive_cond, &conn->lock);
        error = bsdtcp_receive(conn->sfields.active.asock, data, max_len, &bytes_read);
    }

    conn->pending_ops -= 1;
    if (conn->pending_ops == 0) {
        cond_signal(&conn->pending_cond);
    }

    mutex_unlock(&conn->lock);

    if (error != 0) {
        return -error;
    } else if (conn->errstat != 0) {
        return conn->errstat;
    }
    return (int) bytes_read;
}

/* SEND POLICY
 * If a buffer is smaller than or equal to SENDMAXCOPY bytes, then
 * COPYBUFSIZE bytes are allocated, and the buffer is copied into the
 * space. This allows the TCP stack to coalesce small buffers within the
 * remaining space in COPYBUFSIZE.
 * Otherwise, the TCP stack is provided a reference to the buffer, with no
 * extra space.
 */
int sock_tcp_freebsd_send(sock_tcp_freebsd_t *conn, const void* data, size_t len)
{
    int error = 0;
    //struct lbufent* bufent;
    //struct sock_tcp_freebsd_send_state* sstate;

    mutex_lock(&conn->lock);
    conn->pending_ops += 1;

    assert(conn->hasactive && !conn->haspassive);

    const uint8_t* buffer = data;

    while (len > 0) {
        /*
         * Try sending the data, and see if we can send all of it.
         */
        size_t bytessent;
        error = bsdtcp_send(conn->sfields.active.asock, buffer, len, &bytessent);
        if (error != 0) {
            goto unlockreturn;
        }

        buffer += bytessent;
        len -= bytessent;

        if (len != 0) {
            /* Send buffer is full; wait for space to become available. */
            cond_wait(&conn->sfields.active.send_cond, &conn->lock);

            /*
             * Now, the thread has been awakened. We need to check whether it
             * was due to an error, or because there is free space in the send
             * buffer.
             */
            if (conn->errstat != 0) {
                error = conn->errstat;
                goto unlockreturn;
            }
        }
    }

#if 0
    while (len > 0 && error == 0) {
        /*
         * Look at the remaining space in the send buffer to figure out how much
         * we can send.
         */
        while (conn->sfields.active.in_send_buffer >= SENDBUFSIZE) {
            assert(conn->sfields.active.in_send_buffer == SENDBUFSIZE);
            cond_wait(&conn->sfields.active.send_cond, &conn->lock);
        }
        size_t buflen = SENDBUFSIZE - conn->sfields.active.in_send_buffer;
        if (len < buflen) {
            buflen = len;
        }

        bool copy = (buflen <= SENDMAXCOPY);
        if (copy) {
            if (extracopybuf == NULL) {
                sstate = sock_tcp_freebsd_zalloc(sizeof(*sstate) + COPYBUFSIZE);
                if (sstate != NULL) {
                    sstate->buflen = COPYBUFSIZE;
                }
            } else {
                sstate = extracopybuf;
                assert(sstate->buflen == COPYBUFSIZE);
                extracopybuf = NULL;
            }
        } else {
            sstate = sock_tcp_freebsd_zalloc(sizeof(*sstate) + buflen);
            if (sstate != NULL) {
                sstate->buflen = buflen;
            }
        }

        if (sstate == NULL) {
            error = ENOMEM;
            goto unlockreturn;
        }
        sstate->next = NULL;

        bufent = &sstate->entry;
        bufent->iov.iov_next = NULL;
        bufent->iov.iov_len = buflen;

        bufent->iov.iov_base = (uint8_t*) (sstate + 1);
        bufent->extraspace = (copy ? (COPYBUFSIZE - buflen) : 0);
        memcpy(bufent->iov.iov_base, buffer, buflen);

        int state;

        error = (int) bsdtcp_send(conn->sfields.active.asock, bufent, &state);

        if (state == 1) {
            /* The TCP stack has a reference to this buffer, and we must keep track of it. */
            if (conn->sfields.active.send_tail == NULL) {
                conn->sfields.active.send_head = sstate;
            } else {
                conn->sfields.active.send_tail->next = sstate;
            }
            conn->sfields.active.send_tail = sstate;
        } else {
            /* Either the send failed, or this was copied into the last buffer already. */
            if (copy) {
                assert(extracopybuf == NULL);
                /* Cache this copy, to avoid another dynamic memory allocation */
                extracopybuf = sstate;
            } else {
                sock_tcp_freebsd_zfree(sstate);
            }
        }

        if (state != 0) {
            /* The send didn't fail, so we need to keep track of queued bytes. */
            conn->sfields.active.in_send_buffer += buflen;
        }

        buffer += buflen;
        len -= buflen;
    }
#endif

unlockreturn:
    conn->pending_ops -= 1;
    if (conn->pending_ops == 0) {
        cond_signal(&conn->pending_cond);
    }
    mutex_unlock(&conn->lock);
    return -error;
}
