/*
 * Copyright (C) 2017 Fundacion Inria Chile
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 * @ingroup     net
 * @file
 * @brief       Implementation of OpenThread UART platform abstraction
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @author      Baptiste Clenet <bapclenet@gmail.com>
 * @}
 */

#include <stdint.h>
#include <stdio.h>

#include "periph/uart.h"
#include "openthread/types.h"
#include "openthread/platform/uart.h"
#include "ot.h"
#include "rethos.h"

ethos_t rethos;

#define ENABLE_DEBUG (0)
#include "debug.h"

#ifndef RETHOS_CHANNEL_WPANTUND
#define RETHOS_CHANNEL_WPANTUND 12
#endif

#ifdef UART_NUMOF
#define OPENTHREAD_UART_DEV                 UART_DEV(0)
#define OPENTHREAD_SPINEL_FRAME_MARKER      (0x7e)

static serial_msg_t * gSerialMessage[OPENTHREAD_NUMBER_OF_SERIAL_BUFFER];
static serial_msg_t gSerialBuff[OPENTHREAD_NUMBER_OF_SERIAL_BUFFER];
static uint16_t frameLength = 0;

#ifdef MODULE_OPENTHREAD_NCP_FTD
static int8_t currentSerialBufferNumber = 0;
static bool gOnGoingSpinelReception = false;

int8_t getFirstEmptySerialBuffer(void) {
    int8_t i = 0;
    for (i = 0; i < OPENTHREAD_NUMBER_OF_SERIAL_BUFFER; i++) {
        if (gSerialMessage[i]->serial_buffer_status == OPENTHREAD_SERIAL_BUFFER_STATUS_FREE) {
            break;
        }
    }

    if (i >= OPENTHREAD_NUMBER_OF_SERIAL_BUFFER) {
        return OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER;
    } else {
        return i;
    }
}

/* UART interrupt handler (required for OpenThread's NCP)*/
static void uart_handler(void* arg, char c)  {
    if ((c == OPENTHREAD_SPINEL_FRAME_MARKER) && (gOnGoingSpinelReception == false)) {      /* Start of Spinel Frame */
        currentSerialBufferNumber = getFirstEmptySerialBuffer();
        if (OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER == currentSerialBufferNumber) {
            DEBUG("SERIAL: ERROR => OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER found\n");
            return;
        }
        frameLength = 0;

        gSerialMessage[currentSerialBufferNumber]->buf[frameLength] = c;

        gOnGoingSpinelReception = true;
    }
    else if ((c == OPENTHREAD_SPINEL_FRAME_MARKER) && (gOnGoingSpinelReception == true)) {  /* End of Spinel Frame */
        if (currentSerialBufferNumber == OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER) {
            return;
        }
        if (frameLength == 1) {  /* It means that we handle the Start of a Spinel frame instead of the end */
            return;
        }
        if(gSerialMessage[currentSerialBufferNumber]->serial_buffer_status != OPENTHREAD_SERIAL_BUFFER_STATUS_FULL) {
            gSerialMessage[currentSerialBufferNumber]->buf[frameLength] = (uint8_t) c;
            gSerialMessage[currentSerialBufferNumber]->serial_buffer_status = OPENTHREAD_SERIAL_BUFFER_STATUS_READY_TO_PROCESS;
            gSerialMessage[currentSerialBufferNumber]->length = frameLength + 1;
            msg_t msg;
            msg.type = OPENTHREAD_SERIAL_MSG_TYPE_EVENT;
            msg.content.ptr = gSerialMessage[currentSerialBufferNumber];
            msg_send(&msg, openthread_get_event_pid());
        }
        else {
            gSerialMessage[currentSerialBufferNumber]->serial_buffer_status = OPENTHREAD_SERIAL_BUFFER_STATUS_FREE;
        }
        gOnGoingSpinelReception = false;
        frameLength = 0;
    }
    else if (gOnGoingSpinelReception == true) {         /* Payload of Spinel Frame */
        if (currentSerialBufferNumber == OPENTHREAD_ERROR_NO_EMPTY_SERIAL_BUFFER) {
            return;
        }
        if (gSerialMessage[currentSerialBufferNumber]->serial_buffer_status != OPENTHREAD_SERIAL_BUFFER_STATUS_FULL) {
            gSerialMessage[currentSerialBufferNumber]->buf[frameLength] = (uint8_t) c;
        }
    }

    if (gOnGoingSpinelReception == true) {
        frameLength++;
        if (frameLength >= OPENTHREAD_SERIAL_BUFFER__PAYLOAD_SIZE) {
            DEBUG("SERIAL: ERROR => OPENTHREAD_SERIAL_BUFFER__PAYLOAD_SIZE overflowed\n");
            gSerialMessage[currentSerialBufferNumber]->serial_buffer_status = OPENTHREAD_SERIAL_BUFFER_STATUS_FULL;
        }
    }
}

#else
/* UART interrupt handler (required for OpenThread's CLI)*/
static void uart_handler(void* arg, char c) {
    if (frameLength == 0 && gSerialMessage != NULL) {
        memset(gSerialMessage[0], 0, sizeof(serial_msg_t));
    }
    switch (c) {
        case '\r':
        case '\n':
            if (frameLength > 0) {
                gSerialMessage[0]->buf[frameLength] = c;
                frameLength++;
                gSerialMessage[0]->length = frameLength;
                msg_t msg;
                msg.type = OPENTHREAD_SERIAL_MSG_TYPE_EVENT;
                msg.content.ptr = gSerialMessage[0];
                msg_send_int(&msg, openthread_get_event_pid());
                frameLength = 0;
            }
            break;
        default:
            if (frameLength < OPENTHREAD_SERIAL_BUFFER_SIZE) {
                gSerialMessage[0]->buf[frameLength] = c;
                frameLength++;
            }
            break;
    }
}

#endif /* MODULE_OPENTHREAD_NCP_FTD */
#endif

static void wpantund_message_callback(ethos_t *dev, uint8_t channel, uint8_t *data, uint16_t length) {
    /* It may be possible to heavily optimize this. */
    for (uint16_t i = 0; i != length; i++) {
        uart_handler(NULL, data[i]);
    }
}

static rethos_handler_t wpantund_message_h = {.channel = RETHOS_CHANNEL_WPANTUND, .cb = wpantund_message_callback};

extern volatile bool rethos_queued;
void rethos_schedule_isr(ethos_t* dev) {
    if (rethos_queued) {
        return;
    }
    rethos_queued = true;

    msg_t msg;
    msg.type = OPENTHREAD_RETHOS_ISR_EVENT;
    msg.content.ptr = dev;
    msg_send(&msg, openthread_get_preevent_pid());
}

/* This executes on the preevent thread with interrupts disabled. */
void rethos_on_ack(ethos_t* dev, uint8_t channel) {
    (void) channel;

    msg_t msg;
    msg.type = OPENTHREAD_RETHOS_ACK_EVENT;
    msg.content.ptr = dev;
    msg_send(&msg, openthread_get_task_pid());
}

/* OpenThread will call this for enabling UART (required for OpenThread's CLI)*/
otError otPlatUartEnable(void)
{
    for (uint8_t i = 0; i < OPENTHREAD_NUMBER_OF_SERIAL_BUFFER; i++) {
        gSerialMessage[i] = (serial_msg_t*) &gSerialBuff[i];
        gSerialMessage[i]->serial_buffer_status = OPENTHREAD_SERIAL_BUFFER_STATUS_FREE;
    }

    /* Start REthos thread. */

    ethos_params_t p;
    p.uart      = RETHOS_UART;
    p.baudrate  = RETHOS_BAUDRATE;
    p.buf       = NULL;
    p.bufsize   = 0;
    p.call_rethos_service_isr_from_thread = rethos_schedule_isr;
    p.on_ack_callback = rethos_on_ack;
    rethos_setup(&rethos, &p);

    rethos_register_handler(&rethos, &wpantund_message_h);

    return OT_ERROR_NONE;
}

/* OpenThread will call this for disabling UART */
otError otPlatUartDisable(void)
{
    /* Not easy to do this with REthos, so I'm not going to try. */
    assert(false);
    return OT_ERROR_NONE;
}

/* OpenThread will call this for sending data through UART */
otError otPlatUartSend(const uint8_t *aBuf, uint16_t aBufLength)
{
    //printf("Sending REthos frame of length %d\n", (int) aBufLength);
    rethos_send_frame(&rethos, aBuf, aBufLength, RETHOS_CHANNEL_WPANTUND, RETHOS_FRAME_TYPE_DATA);

    /* Tell OpenThread the sending over UART is done */
    //otPlatUartSendDone();

    return OT_ERROR_NONE;
}

void handle_rethos_ack(void) {
    /* Tell OpenThread the sending over UART is done */
    otPlatUartSendDone();
}
