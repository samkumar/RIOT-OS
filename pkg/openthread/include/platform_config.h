/*
 * Copyright (C) Baptiste Clenet
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Implementation of OpenThread platform config
 *
 * @author      Baptiste Clenet <bapclenet@gmail.com>
 * @}
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS
 *
 * The number of message buffers in buffer pool
 */

#define OPENTHREAD_CONFIG_MESSAGE_BUFFER_SIZE 128

#if OPENTHREAD_ENABLE_NCP_UART
#define OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS       32
#define OPENTHREAD_ENABLE_NCP_VENDOR_HOOK           0
#define OPENTHREAD_CONFIG_ENABLE_PLATFORM_USEC_TIMER 1
#elif OPENTHREAD_MTD
#define OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS       32
#define OPENTHREAD_CONFIG_ENABLE_PLATFORM_USEC_TIMER 1
#elif OPENTHREAD_FTD
#define OPENTHREAD_CONFIG_NUM_MESSAGE_BUFFERS       32
#define OPENTHREAD_CONFIG_ENABLE_PLATFORM_USEC_TIMER 1
#endif

#define OPENTHREAD_CONFIG_LINK_RETRY_DELAY
#define OPENTHREAD_CONFIG_LINK_RETRY_DELAY_DIRECT (40000ul)
#define OPENTHREAD_CONFIG_MAX_TX_ATTEMPTS_DIRECT    10
#define OPENTHREAD_CONFIG_LINK_RETRY_DELAY_INDIRECT (20000ul)
#define OPENTHREAD_CONFIG_MAX_TX_ATTEMPTS_INDIRECT_PER_POLL 5

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_CONFIG_H */
