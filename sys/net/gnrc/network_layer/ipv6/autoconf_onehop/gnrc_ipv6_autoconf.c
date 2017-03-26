/*
 * Copyright (C) 2017 Sam Kumar <samkumar@berkeley.edu>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */

#include <errno.h>
#include <string.h>

#include "net/gnrc/ipv6.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/autoconf_onehop.h"
#include "net/gnrc/ipv6/netif.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if ENABLE_DEBUG
/* For PRIu8 etc. */
#include <inttypes.h>

static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

kernel_pid_t gnrc_ipv6_autoconf_next_hop_l2addr(uint8_t *l2addr, uint8_t *l2addr_len, kernel_pid_t iface, ipv6_addr_t *dst) {
    ipv6_addr_t* longest_prefix_match;
    kernel_pid_t matching_iface_pid = gnrc_ipv6_netif_find_by_prefix(&longest_prefix_match, dst);
    if (matching_iface_pid == KERNEL_PID_UNDEF) {
        return KERNEL_PID_UNDEF;
    }

    uint8_t prefix_length_bits = ipv6_addr_match_prefix(longest_prefix_match, dst);
    if (prefix_length_bits < 64) {
        return KERNEL_PID_UNDEF;
    }

    *l2addr_len = sizeof(eui64_t);
    memcpy(l2addr, &dst->u8[8], sizeof(eui64_t));
    _revert_iid(l2addr);

    return matching_iface_pid;
}

/** @} */
