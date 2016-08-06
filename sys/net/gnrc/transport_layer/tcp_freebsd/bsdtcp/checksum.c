/* This isn't from the BSD code.
 * This is taken from my implementation of TCP in PC userland.
 */
#include "tcp.h"

inline uint16_t deref_safe(uint16_t* unaligned) {
    return ((uint16_t) *((uint8_t*) unaligned))
        | (((uint16_t) *(((uint8_t*) unaligned) + 1)) << 8);
}

uint16_t get_checksum(struct in6_addr* src, struct in6_addr* dest,
                      struct ip_iovec* tcpseg, uint32_t len) {
    uint32_t total;
    uint16_t* current;
    uint16_t* end;
    uint8_t* currbuf;
    uint32_t currlen;
    int starthalf; // 1 if the end of the last iovec was not half-word aligned
    struct {
        struct in6_addr srcaddr;
        struct in6_addr destaddr;
        uint32_t tcplen;
        uint8_t reserved0;
        uint8_t reserved1;
        uint8_t reserved2;
        uint8_t protocol;
    } __attribute__((packed, aligned)) pseudoheader;
    memcpy(&pseudoheader.srcaddr, src, sizeof(struct in6_addr));
    memcpy(&pseudoheader.destaddr, dest, sizeof(struct in6_addr));
    pseudoheader.reserved0 = 0;
    pseudoheader.reserved1 = 0;
    pseudoheader.reserved2 = 0;
    pseudoheader.protocol = 6; // TCP
    pseudoheader.tcplen = (uint32_t) htonl(len);
    
    total = 0;
    for (current = (uint16_t*) &pseudoheader;
         current < (uint16_t*) (&pseudoheader + 1); current++) {
        total += (uint32_t) *current;
    }

    starthalf = 0;
    do {
        current = (uint16_t*) tcpseg->iov_base;
        currlen = (uint32_t) tcpseg->iov_len;
        if (starthalf && currlen > 0) {
            total += ((uint32_t) *((uint8_t*) current)) << 8;
            current = (uint16_t*) (((uint8_t*) current) + 1);
            currlen -= 1;
        }
        if (currlen & 0x1u) {
            // This iovec does not end on a half-word boundary
            end = (uint16_t*) (((uint8_t*) current) + currlen - 1);
            total += *((uint8_t*) end);
            starthalf = 1;
        } else {
            // This iovec ends on a half-word boundary
            end = (uint16_t*) (((uint8_t*) current) + currlen);
            starthalf = 0;
        }
        while (current != end) {
            // read the memory byte by byte, in case iovec isn't word-aligned 
            total += deref_safe(current++);
        }
        tcpseg = tcpseg->iov_next;
    } while (tcpseg != NULL);
        
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    
    return ~((uint16_t) total);
}
