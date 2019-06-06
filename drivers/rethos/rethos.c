/*
 * Copyright (C) 2016 Michael Andersen <m.andersen@berkeley.edu>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     driver_ethos
 * @{
 *
 * @file
 * @brief       A re-implementation of ethos (originally by Kaspar Schleiser)
 *              that creates a reliable multi-channel duplex link over serial
 *
 * @author      Michael Andersen <m.andersen@berkeley.edu>
 *
 * @}
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "random.h"
#include "rethos.h"
#include "periph/uart.h"
#include "tsrb.h"
#include "irq.h"

#include <xtimer.h>

#ifdef USE_ETHOS_FOR_STDIO
#include "uart_stdio.h"
#include "isrpipe.h"
extern isrpipe_t uart_stdio_isrpipe;
#endif

#define ENABLE_DEBUG (0)
#include "debug.h"

static void ethos_isr(void *arg, uint8_t c);

static const uint8_t _esc_esc[] = {RETHOS_ESC_CHAR, RETHOS_LITERAL_ESC};
static const uint8_t _start_frame[] = {RETHOS_ESC_CHAR, RETHOS_FRAME_START};
static const uint8_t _end_frame[] = {RETHOS_ESC_CHAR, RETHOS_FRAME_END};

xtimer_t rexmit_timer;

void rethos_send_frame_seqno_norexmit(ethos_t *dev, const uint8_t *data, size_t len, uint8_t channel, uint16_t seqno, uint8_t frame_type);
void rethos_start_frame_seqno_norexmit(ethos_t* dev, const uint8_t* data, size_t thislen, uint8_t channel, uint16_t seqno, uint8_t frame_type);

static void fletcher16_add(const uint8_t *data, size_t bytes, uint16_t *sum1i, uint16_t *sum2i)
{
    uint16_t sum1 = *sum1i, sum2 = *sum2i;

    while (bytes) {
        size_t tlen = bytes > 20 ? 20 : bytes;
        bytes -= tlen;
        do {
            sum2 += sum1 += *data++;
        } while (--tlen);
        sum1 = (sum1 & 0xff) + (sum1 >> 8);
        sum2 = (sum2 & 0xff) + (sum2 >> 8);
    }
    *sum1i = sum1;
    *sum2i = sum2;
}

static uint16_t fletcher16_fin(uint16_t sum1, uint16_t sum2)
{
    sum1 = (sum1 & 0xff) + (sum1 >> 8);
    sum2 = (sum2 & 0xff) + (sum2 >> 8);
    return (sum2 << 8) | sum1;
}

static void sm_invalidate(ethos_t *dev)
{
    struct rethos_recv_ctx* r = &dev->recv_ctx[dev->recv_ctx_index];
    dev->state = SM_WAIT_FRAMESTART;
    r->rx_buffer_index = 0;
}
static void process_frame(ethos_t *dev, struct rethos_recv_ctx* r)
{
    if (r->rx_frame_type != RETHOS_FRAME_TYPE_DATA)
    {
        /* All ACKs and NACKs happen on the RETHOS-reserved channel. */
        if (r->rx_channel == RETHOS_CHANNEL_CONTROL)
        {
            if (r->rx_frame_type == RETHOS_FRAME_TYPE_ACK)
            {
                DEBUG("[rethos] ACK for seq = %d (expecting %d, %d)\n", r->rx_seqno, dev->rexmit_seqno, dev->rexmit_acked);
                if (r->rx_seqno == dev->rexmit_seqno)
                {
                    dev->rexmit_acked = true;
                    xtimer_remove(&rexmit_timer);
                    if (dev->on_ack != NULL) {
                        dev->on_ack(dev, dev->rexmit_channel);
                    }
                }
            }
            else if (r->rx_frame_type == RETHOS_FRAME_TYPE_NACK)
            {
                if (dev->rexmit_acked)
                {
                    /* They've already ACKed the last thing we sent, so either one of NACKs got
                     * corrupted or one of our ACKs got corrupted.
                     *
                     * Sending a NACK here could cause a NACK storm, so instead just ACK the last
                     * thing we received.
                     */
                    if (dev->received_data)
                    {
                        rethos_send_ack_frame(dev, dev->last_rcvd_seqno);
                    }
                }
                else
                {
                    /* Retransmit the last data frame we sent. */
                    DEBUG("[rethos] Retransmitting %d due to NACK\n", (int) dev->rexmit_seqno);
                    rethos_rexmit_data_frame(dev);
                }
            }
        }

        return; //Other types are internal to rethos
    }

    dev->received_data = true;

    if (dev->last_rcvd_seqno == r->rx_seqno) {
        return;
    }
    dev->last_rcvd_seqno = r->rx_seqno;

    /* ACK the frame we just received. */
    rethos_send_ack_frame(dev, r->rx_seqno);

    //Handle the special channels
    switch(r->rx_channel) {
    /* Sam: this fails to compile if we disable -DUSE_ETHOS_FOR_STDIO, so I'm removing it. */
    /*
      case RETHOS_CHANNEL_STDIO:
        for (size_t i = 0; i < dev->rx_buffer_index; i++)
        {
          //uart_stdio_rx_cb(NULL, dev->rx_buffer[i]);
          isrpipe_write_one(&uart_stdio_isrpipe, dev->rx_buffer[i]);
        }
        break;
    */
      default:
        break;
    }
    //And all registered handlers
    rethos_handler_t *h = dev->handlers;
    while (h != NULL)
    {
        if (h->channel == r->rx_channel) {
            h->cb(dev, r->rx_channel, r->rx_buffer, r->rx_buffer_index);
        }
        h = h->_next;
    }
}

static void sm_char(ethos_t *dev, uint8_t c)
{
    struct rethos_recv_ctx* r = &dev->recv_ctx[dev->recv_ctx_index];
    switch (dev->state)
    {
    case SM_WAIT_TYPE:
        r->rx_frame_type = c;
        fletcher16_add(&c, 1, &r->rx_cksum1, &r->rx_cksum2);
        dev->state = SM_WAIT_SEQ0;
        return;
    case SM_WAIT_SEQ0:
        r->rx_seqno = c;
        fletcher16_add(&c, 1, &r->rx_cksum1, &r->rx_cksum2);
        dev->state = SM_WAIT_SEQ1;
        return;
    case SM_WAIT_SEQ1:
        r->rx_seqno |= (((uint16_t)c)<<8);
        fletcher16_add(&c, 1, &r->rx_cksum1, &r->rx_cksum2);
        dev->state = SM_WAIT_CHANNEL;
        return;
    case SM_WAIT_CHANNEL:
        r->rx_channel = c;
        fletcher16_add(&c, 1, &r->rx_cksum1, &r->rx_cksum2);
        dev->state = SM_IN_FRAME;
        return;
    case SM_IN_FRAME:
        r->rx_buffer[r->rx_buffer_index] = c;
        fletcher16_add(&c, 1, &r->rx_cksum1, &r->rx_cksum2);
        if ((++r->rx_buffer_index) >= RETHOS_RX_BUF_SZ) {
            sm_invalidate(dev);
        }
        return;
    case SM_WAIT_CKSUM1:
        r->rx_expected_cksum = c;
        dev->state = SM_WAIT_CKSUM2;
        return;
    case SM_WAIT_CKSUM2:
        r->rx_expected_cksum |= (((uint16_t)c)<<8);
        if (r->rx_expected_cksum != r->rx_actual_cksum) {
            dev->stats_rx_cksum_fail++;
            dev->nack_ready = true;
            dev->schedule_service_isr(dev);
        } else {
            dev->stats_rx_frames++;
            dev->stats_rx_bytes += r->rx_buffer_index;

            /* Switch the active receive context so the next frame doesn't trample over this one (while it's being processed). */
            dev->recv_ctx_index = (dev->recv_ctx_index + 1) & (RETHOS_NUM_RX_CONTEXTS - 1);

            /* Schedule processing of received frame in a thread. */
            r->rx_ready = true;
            dev->rx_ready = true;
            dev->schedule_service_isr(dev);
        }
        sm_invalidate(dev);
        return;
    default:
        return;
    }
}
static void sm_frame_start(ethos_t *dev)
{
    struct rethos_recv_ctx* r = &dev->recv_ctx[dev->recv_ctx_index];
    //Drop everything, we are beginning a new frame reception
    r->rx_ready = false;
    dev->state = SM_WAIT_TYPE;
    r->rx_buffer_index = 0;
    r->rx_cksum1 = 0xFF;
    r->rx_cksum2 = 0xFF;
}
//This is not quite the real end of the frame, we still expect the checksum
static void sm_frame_end(ethos_t *dev)
{
    struct rethos_recv_ctx* r = &dev->recv_ctx[dev->recv_ctx_index];
    uint16_t cksum = fletcher16_fin(r->rx_cksum1, r->rx_cksum2);
    r->rx_actual_cksum = cksum;
    dev->state = SM_WAIT_CKSUM1;
}

static void ethos_isr(void *arg, uint8_t c)
{
    ethos_t *dev = (ethos_t *) arg;

    if (dev->state == SM_IN_ESCAPE) {
        switch (c) {
        case RETHOS_LITERAL_ESC:
            dev->state = dev->fromstate;
            sm_char(dev, RETHOS_ESC_CHAR);
            return;
        case RETHOS_FRAME_START:
            sm_frame_start(dev);
            return;
        case RETHOS_FRAME_END:
            if (dev->fromstate == SM_IN_FRAME) {
                sm_frame_end(dev);
                return;
            }
            /* fallthrough intentional */
        default:
            //any other character is invalid
            sm_invalidate(dev);
            return;
        }
    } else {
        switch(c) {
        case RETHOS_ESC_CHAR:
            dev->fromstate = dev->state;
            dev->state = SM_IN_ESCAPE;
            return;
        default:
            sm_char(dev, c);
            return;
        }
    }
}

// This is called from a thread to service (all) pending interrupts
void rethos_service_isr(ethos_t* dev)
{
    mutex_lock(&dev->out_mutex);
    int state = irq_disable();
    if (dev->nack_ready) {
        dev->nack_ready = false;
        rethos_send_nack_frame(dev);
    }
    if (dev->rx_ready) {
        dev->rx_ready = false;
        /* Process all frames in the buffer that are ready right now. */
        for (int i = 0; i != RETHOS_NUM_RX_CONTEXTS; i++) {
            struct rethos_recv_ctx* r = &dev->recv_ctx[i];
            if (r->rx_ready) {
                process_frame(dev, r);
            }
            r->rx_ready = false;
        }
    }
    if (dev->rexmit_ready) {
        dev->rexmit_ready = false;
        if (!dev->rexmit_acked) {
            DEBUG("[rethos] Retransmitting %d due to timeout\n", (int) dev->rexmit_seqno);
            rethos_rexmit_data_frame(dev);
            // rexmit timer is already scheduled by rethos_rexmit_data_frame
        }
    }
    irq_restore(state);
    mutex_unlock(&dev->out_mutex);
}

static void _write_escaped(uart_t uart, uint8_t c)
{
    uint8_t *out;
    int n;

    switch(c) {
        case RETHOS_ESC_CHAR:
            out = (uint8_t*)_esc_esc;
            n = 2;
            break;
        default:
            out = &c;
            n = 1;
    }

    uart_write(uart, out, n);
}

void rethos_rexmit_callback(void* arg)
{
    ethos_t* dev = (ethos_t*) arg;
    dev->rexmit_ready = true;
    //dev->rethos_service_isr(dev);
    dev->schedule_service_isr(dev);
}

void _start_frame_seqno(ethos_t* dev, const uint8_t* data, size_t thislen, uint8_t channel, uint16_t seqno, uint8_t frame_type)
{
    uint8_t preamble_buffer[6];

    dev->flsum1 = 0xFF;
    dev->flsum2 = 0xFF;

    preamble_buffer[0] = RETHOS_ESC_CHAR;
    preamble_buffer[1] = RETHOS_FRAME_START;
    //This is where the checksum starts
    preamble_buffer[2] = frame_type;
    preamble_buffer[3] = seqno & 0xFF; //Little endian cos im a rebel
    preamble_buffer[4] = seqno >> 8;
    preamble_buffer[5] = channel;

    dev->stats_tx_bytes += 4 + thislen;

    fletcher16_add(&preamble_buffer[2], 4, &dev->flsum1, &dev->flsum2);

    uart_write(dev->uart, preamble_buffer, 2);
    for (size_t i = 0; i < 4; i++)
    {
      _write_escaped(dev->uart, preamble_buffer[2+i]);
    }

    if (thislen > 0)
    {
      fletcher16_add(data, thislen, &dev->flsum1, &dev->flsum2);
      //todo replace with a little bit of chunking
      for (size_t i = 0; i<thislen; i++) {
        _write_escaped(dev->uart, data[i]);
      }
    }
}

void rethos_start_frame_seqno_norexmit(ethos_t* dev, const uint8_t* data, size_t thislen, uint8_t channel, uint16_t seqno, uint8_t frame_type)
{
    mutex_lock(&dev->out_mutex);

    _start_frame_seqno(dev, data, thislen, channel, seqno, frame_type);
}

void rethos_start_frame_seqno(ethos_t* dev, const uint8_t* data, size_t thislen, uint8_t channel, uint16_t seqno, uint8_t frame_type)
{
    mutex_lock(&dev->out_mutex);

    /* Store this data, in case we need to retransmit it. */
    dev->rexmit_seqno = seqno;
    dev->rexmit_channel = (uint8_t) channel;
    dev->rexmit_numbytes = thislen;
    memcpy(dev->rexmit_frame, data, thislen);
    dev->rexmit_acked = true; // We have a partial frame, so don't retransmit it on a NACK

    _start_frame_seqno(dev, data, thislen, channel, seqno, frame_type);
}

void rethos_start_frame(ethos_t *dev, const uint8_t *data, size_t thislen, uint8_t channel, uint8_t frame_type)
{
    uint16_t seqno = ++(dev->txseq);
    rethos_start_frame_seqno(dev, data, thislen, channel, seqno, frame_type);
}

void ethos_send_frame(ethos_t *dev, const uint8_t *data, size_t len, unsigned channel)
{
    rethos_send_frame(dev, data, len, channel, RETHOS_FRAME_TYPE_DATA);
}

void rethos_send_frame(ethos_t *dev, const uint8_t *data, size_t len, uint8_t channel, uint8_t frame_type)
{
    rethos_start_frame(dev, data, len, channel, frame_type);
    rethos_end_frame(dev, true);
}

/* We need to copy this because, apparently, both rethos_send_frame and rethos_start_frame are public... */
void rethos_send_frame_seqno(ethos_t *dev, const uint8_t *data, size_t len, uint8_t channel, uint16_t seqno, uint8_t frame_type)
{
    rethos_start_frame_seqno(dev, data, len, channel, seqno, frame_type);
    rethos_end_frame(dev, true);
}

void rethos_send_frame_seqno_norexmit(ethos_t *dev, const uint8_t *data, size_t len, uint8_t channel, uint16_t seqno, uint8_t frame_type)
{
    rethos_start_frame_seqno_norexmit(dev, data, len, channel, seqno, frame_type);
    rethos_end_frame(dev, false);
}

void rethos_rexmit_data_frame(ethos_t* dev)
{
    rethos_send_frame_seqno(dev, dev->rexmit_frame, dev->rexmit_numbytes, dev->rexmit_channel, dev->rexmit_seqno, RETHOS_FRAME_TYPE_DATA);
}

void rethos_send_ack_frame(ethos_t* dev, uint16_t seqno)
{
    rethos_send_frame_seqno_norexmit(dev, NULL, 0, RETHOS_CHANNEL_CONTROL, seqno, RETHOS_FRAME_TYPE_ACK);
}

void rethos_send_nack_frame(ethos_t* dev)
{
    rethos_send_frame_seqno_norexmit(dev, NULL, 0, RETHOS_CHANNEL_CONTROL, 0, RETHOS_FRAME_TYPE_NACK);
}

void rethos_continue_frame(ethos_t *dev, const uint8_t *data, size_t thislen)
{
    fletcher16_add(data, thislen, &dev->flsum1, &dev->flsum2);

    /* Check if we're going to overflow the rexmit buffer. */
    if (thislen + dev->rexmit_numbytes > RETHOS_TX_BUF_SZ) {
        /* Just stop transmitting data. The checksum should be corrupt anyway, so
         * the other side won't think this was valid. We just need to make sure we
         * never retransmit.
         */
        dev->rexmit_numbytes = RETHOS_TX_BUF_SZ + 1;
        return;
    }

    dev->stats_tx_bytes += thislen;
    //todo replace with a little bit of chunking
    for (size_t i = 0; i<thislen; i++) {
        _write_escaped(dev->uart, data[i]);
    }
}

void rethos_end_frame(ethos_t *dev, bool schedule_rexmit)
{
    uint16_t cksum = fletcher16_fin(dev->flsum1, dev->flsum2);
    uart_write(dev->uart, _end_frame, 2);
    _write_escaped(dev->uart, cksum & 0xFF);
    _write_escaped(dev->uart, cksum >> 8);
    dev->stats_tx_frames += 1;

    /* Enable retransmission and set the rexmit timer */
    if (schedule_rexmit && dev->rexmit_numbytes <= RETHOS_TX_BUF_SZ) {
        dev->rexmit_acked = false;
        rexmit_timer.arg = dev;
        xtimer_set(&rexmit_timer, (uint32_t) RETHOS_REXMIT_MICROS);
    }

    mutex_unlock(&dev->out_mutex);
}

void rethos_register_handler(ethos_t *dev, rethos_handler_t *handler)
{
    rethos_handler_t *h = dev->handlers;
    handler->_next = NULL;
    if (h == NULL) {
        dev->handlers = handler;
    } else {
        while (h->_next != NULL) {
            h = h->_next;
        }
        h->_next = handler;
    }
}

void rethos_setup(ethos_t *dev, const ethos_params_t *params)
{
    dev->schedule_service_isr = params->call_rethos_service_isr_from_thread;
    dev->on_ack = params->on_ack_callback;
    dev->uart = params->uart;
    dev->state = SM_WAIT_FRAMESTART;
    dev->recv_ctx_index = 0;
    for (int  i = 0; i != RETHOS_NUM_RX_CONTEXTS; i++) {
        dev->recv_ctx[i].rx_buffer_index = 0;
        dev->recv_ctx[i].rx_ready = false;
    }
    dev->handlers = NULL;
    dev->txseq = 0;
    dev->stats_tx_frames = 0;
    dev->stats_tx_retries = 0;
    dev->stats_tx_bytes = 0;
    dev->stats_rx_frames = 0;
    dev->stats_rx_cksum_fail = 0;
    dev->stats_rx_bytes = 0;

    dev->nack_ready = false;
    dev->rx_ready = false;
    dev->rexmit_ready = false;
    dev->rexmit_acked = true;
    dev->received_data = false;

    mutex_init(&dev->out_mutex);

    rexmit_timer.callback = rethos_rexmit_callback;

    uart_init(params->uart, params->baudrate, ethos_isr, (void*)dev);
}
