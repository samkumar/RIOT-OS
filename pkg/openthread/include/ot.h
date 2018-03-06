/*
 * Copyright (C) 2017 Fundacion Inria Chile
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    pkg_openthread_cli   OpenThread
 * @ingroup     pkg_openthread
 * @brief       An open source implementation of Thread stack
 * @see         https://github.com/openthread/openthread
 *
 * Thread if a mesh oriented network stack running for IEEE802.15.4 networks.
 * @{
 *
 * @file
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @author      Baptiste Clenet <bapclenet@gmail.com>
 */

#ifndef OT_H
#define OT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "net/netopt.h"
#include "net/ieee802154.h"
#include "net/ethernet.h"
#include "net/gnrc/netdev.h"
#include "thread.h"
#include "mutex.h"
#include "platform_config.h"
#include "openthread/types.h"

/**< event indicating the tasklet is non-empty */
#define OPENTHREAD_TASK_MSG_TYPE_EVENT                      (0x2235)
/**< milli-timer message receiver event */
#define OPENTHREAD_MILLITIMER_MSG_TYPE_EVENT                (0x2236)
/**< micro-timer message receiver event */
#define OPENTHREAD_MICROTIMER_MSG_TYPE_EVENT                (0x2237)
/**< event indicating a serial (UART) message was sent to OpenThread */
#define OPENTHREAD_SERIAL_MSG_TYPE_EVENT                    (0x2238)
/**< event for frame reception and transmission complete */
#define OPENTHREAD_NETDEV_MSG_TYPE_EVENT                    (0x2239)
/**< event for frame transmission failure (radio busy) */
#define OPENTHREAD_TX_FAIL_RADIO_BUSY                       (0x223A)
/**< event indicating an OT_JOB message */
#define OPENTHREAD_JOB_MSG_TYPE_EVENT                       (0x2241)
/**< number of serial reception buffer */
#define OPENTHREAD_NUMBER_OF_SERIAL_BUFFER                  (1U)
/**< sizeof in bytes the two first members of she serial structure */
#define OPENTHREAD_SIZEOF_LENGTH_AND_FREEBUFF               (4U)
#ifdef MODULE_OPENTHREAD_NCP_FTD
/**< sizeof the serial buffer */
#define OPENTHREAD_SERIAL_BUFFER_SIZE                       OPENTHREAD_SIZEOF_LENGTH_AND_FREEBUFF + 200
#else
/**< sizeof the serial buffer */
#define OPENTHREAD_SERIAL_BUFFER_SIZE                       OPENTHREAD_SIZEOF_LENGTH_AND_FREEBUFF + 100
#endif
/**< sizeof the spinel payload data */
#define OPENTHREAD_SERIAL_BUFFER__PAYLOAD_SIZE              OPENTHREAD_SERIAL_BUFFER_SIZE - OPENTHREAD_SIZEOF_LENGTH_AND_FREEBUFF
/**< error when no more buffer available */
#define OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER             -1
/**< serial buffer ready to use */
#define OPENTHREAD_SERIAL_BUFFER_STATUS_FREE                (0x0001)
/**< serial buffer ready for processsing */
#define OPENTHREAD_SERIAL_BUFFER_STATUS_READY_TO_PROCESS    (0x0002)
/**< serial buffer payload full */
#define OPENTHREAD_SERIAL_BUFFER_STATUS_FULL                (0x0004)
/**< Max length for IEEE802154 frame */
#define IEEE802154_MAX_LENGTH                               (127U)
/**< Max length for a netdev buffer  */
#define OPENTHREAD_NETDEV_BUFLEN                            (IEEE802154_MAX_LENGTH)


/**
 * @brief   Struct containing a serial message
 */
typedef struct {
    uint16_t length;                                        /**< length of the message */
    uint16_t serial_buffer_status;                            /**< status of the buffer */
    uint8_t buf[OPENTHREAD_SERIAL_BUFFER__PAYLOAD_SIZE];    /**< buffer containing the message */
} serial_msg_t;

/**
 * @brief   Struct containing an OpenThread job
 */
typedef struct {
    const char *command;                    /**< A pointer to the job name string. */
    void *arg;                              /**< arg for the job **/
    void *answer;                           /**< answer from the job **/
} ot_job_t;

/**
 * @brief Gets packet from driver and tells OpenThread about the reception.
 *
 * @param[in]  aInstance          pointer to an OpenThread instance
 */
void recv_pkt(otInstance *aInstance, netdev_t *dev);

/**
 * @brief   Inform OpenThread when tx is finished
 *
 * @param[in]  aInstance          pointer to an OpenThread instance
 * @param[in]  dev                pointer to a netdev interface
 * @param[in]  event              just occurred netdev event
 */
void sent_pkt(otInstance *aInstance, netdev_event_t event);

/**
 * @brief   Bootstrap OpenThread
 */
void openthread_bootstrap(void);

/**
 * @brief   Init OpenThread radio
 *
 * @param[in]  dev                pointer to a netdev interface
 */
void openthread_radio_init(netdev_t *dev);

/**
 * @brief   Starts OpenThread Preevent Thread.
 *
 * @param[in]  stack              pointer to the stack designed for OpenThread Preevent Thread
 * @param[in]  stacksize          size of the stack
 * @param[in]  priority           priority of the stack
 * @param[in]  name               name of the stack
 *
 * @return  PID of OpenThread Preevent Thread
 * @return  -EINVAL if there was an error creating the thread
 */
int openthread_preevent_init(char *stack, int stacksize, char priority, const char *name);

/**
 * @brief   Starts OpenThread Event Thread.
 *
 * @param[in]  stack              pointer to the stack designed for OpenThread Event Thread
 * @param[in]  stacksize          size of the stack
 * @param[in]  priority           priority of the stack
 * @param[in]  name               name of the stack
 *
 * @return  PID of OpenThread Event Thread
 * @return  -EINVAL if there was an error creating the thread
 */
int openthread_event_init(char *stack, int stacksize, char priority, const char *name);

/**
 * @brief   Starts OpenThread Task Thread.
 *
 * @param[in]  stack              pointer to the stack designed for OpenThread Task Thread
 * @param[in]  stacksize          size of the stack
 * @param[in]  priority           priority of the stack
 * @param[in]  name               name of the stack
 *
 * @return  PID of OpenThread Task Thread
 * @return  -EINVAL if there was an error creating the thread
 */
int openthread_task_init(char *stack, int stacksize, char priority, const char *name);

/**
 * @brief   get PID of OpenThread Preevent thread.
 *
 * @return  PID of OpenThread Preevent thread
 */
kernel_pid_t openthread_get_preevent_pid(void);

/**
 * @brief   get PID of OpenThread Event Thread.
 *
 * @return  PID of OpenThread Event Thread
 */
kernel_pid_t openthread_get_event_pid(void);

/**
 * @brief   get PID of OpenThread Task Thread.
 *
 * @return  PID of OpenThread Task Thread
 */
kernel_pid_t openthread_get_task_pid(void);

/**
 * @brief   get instance of OpenThread.
 *
 * @return  instance of OpenThread
 */
otInstance* openthread_get_instance(void);

/**
 * @brief   get millitimer of OpenThread.
 *
 * @return  millitimer of OpenThread
 */
xtimer_t* openthread_get_millitimer(void);

#ifdef MODULE_OPENTHREAD_FTD
/**
 * @brief   get microtimer of OpenThread.
 *
 * @return  microtimer of OpenThread
 */
xtimer_t* openthread_get_microtimer(void);
#endif

/**
 * @brief   get netdev of OpenThread.
 *
 * @return  netdev of OpenThread
 */
netdev_t* openthread_get_netdev(void);

/**
 * @brief   get radio mutex of OpenThread.
 *
 * @return  mutex for OpenThread buffer
 */
mutex_t* openthread_get_radio_mutex(void);

/**
 * @brief   lock buffer mutex of OpenThread.
 */
void openthread_lock_buffer_mutex(void);

/**
 * @brief   unlock buffer mutex of OpenThread.
 */
void openthread_unlock_buffer_mutex(void);

void openthread_event_thread_overflow_check(void);
void openthread_preevent_thread_overflow_check(void);
void openthread_task_thread_overflow_check(void);

/**
 * @brief   Init OpenThread random
 */
void ot_random_init(void);

/**
 * @brief   Execute OpenThread command. Call this function only in OpenThread thread
 *
 * @param[in]   ot_instance     OpenThread instance
 * @param[in]   command         OpenThread command name
 * @param[in]   arg             arg for the command
 * @param[out]  answer          answer for the command
 *
 * @return  0 on success, 1 on error
 */
uint8_t ot_exec_command(otInstance *ot_instance, const char* command, void *arg, void* answer);

/**
 * @brief   Call OpenThread command in same thread as OT core (due to concurrency).
 *
 * @note    An OpenThread command allows direct calls to OpenThread API (otXXX functions) without worrying about concurrency
 * issues. All API calls should be made in OT_JOB type functions.
 *
 * @param[in]   command         name of the command to call
 * @param[in]   arg             arg for the command
 * @param[out]  answer          answer for the command
 *
 * @return  0 on success, 1 on error
 */
uint8_t ot_call_command(char* command, void *arg, void* answer);

#ifdef __cplusplus
}
#endif

#endif /* OT_H */
/** @} */
