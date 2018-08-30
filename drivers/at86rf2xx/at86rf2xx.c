/*
 * Copyright (C) 2013 Alaeddine Weslati <alaeddine.weslati@inria.fr>
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     drivers_at86rf2xx
 * @{
 *
 * @file
 * @brief       Implementation of public functions for AT86RF2xx drivers
 *
 * @author      Alaeddine Weslati <alaeddine.weslati@inria.fr>
 * @author      Thomas Eichinger <thomas.eichinger@fu-berlin.de>
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */


#include "luid.h"
#include "byteorder.h"
#include "net/ieee802154.h"
#include "net/gnrc.h"
#include "at86rf2xx_registers.h"
#include "at86rf2xx_internal.h"
#include "at86rf2xx_netdev.h"
#include "xtimer.h"

#define ENABLE_DEBUG (0)
#include "debug.h"


void at86rf2xx_setup(at86rf2xx_t *dev, const at86rf2xx_params_t *params)
{
    netdev_t *netdev = (netdev_t *)dev;

    netdev->driver = &at86rf2xx_driver;
    /* initialize device descriptor */
    memcpy(&dev->params, params, sizeof(at86rf2xx_params_t));
    dev->idle_state = AT86RF2XX_STATE_TRX_OFF;
    /* radio state is P_ON when first powered-on */
    dev->state = AT86RF2XX_STATE_P_ON;
    dev->pending_tx = 0;
//#ifdef MODULE_OPENTHREAD_FTD
    dev->pending_irq = 0;
//#endif
}

void at86rf2xx_reset(at86rf2xx_t *dev)
{
    eui64_t addr_long;

    at86rf2xx_hardware_reset(dev);

    /* Reset state machine to ensure a known state */
    if (dev->state == AT86RF2XX_STATE_P_ON) {
        at86rf2xx_set_state(dev, AT86RF2XX_STATE_FORCE_TRX_OFF);
    }

    /* reset options and sequence number */
    dev->netdev.seq = 0;
    dev->netdev.flags = 0;

    /* get an 8-byte unique ID to use as hardware address */
    luid_get(addr_long.uint8, IEEE802154_LONG_ADDRESS_LEN);
    /* make sure we mark the address as non-multicast and not globally unique */

  //  addr_long.uint8[0] &= ~(0x01);
  //  addr_long.uint8[0] |=  (0x02);
    /* set short and long address */
    at86rf2xx_set_addr_long(dev, addr_long.uint64.u64);
    at86rf2xx_set_addr_short(dev, addr_long.uint16[3].u16);

    /* set default PAN id */
    at86rf2xx_set_pan(dev, AT86RF2XX_DEFAULT_PANID);
    /* set default channel */
    at86rf2xx_set_chan(dev, AT86RF2XX_DEFAULT_CHANNEL);
    /* set default TX power */
    at86rf2xx_set_txpower(dev, AT86RF2XX_DEFAULT_TXPOWER);
    /* set default options */
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_AUTOACK, true);
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_CSMA, true);
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_TELL_RX_START, false);
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_TELL_RX_END, true);
#ifdef MODULE_NETSTATS_L2
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_TELL_TX_END, true);
#endif
    /* set default protocol */
#ifdef MODULE_GNRC_SIXLOWPAN
    dev->netdev.proto = GNRC_NETTYPE_SIXLOWPAN;
#elif MODULE_GNRC
    dev->netdev.proto = GNRC_NETTYPE_UNDEF;
#endif
    /* enable safe mode (protect RX FIFO until reading data starts) */
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_CTRL_2,
                        AT86RF2XX_TRX_CTRL_2_MASK__RX_SAFE_MODE);
#ifdef MODULE_AT86RF212B
    at86rf2xx_set_page(dev, 0);
#endif

    /* don't populate masked interrupt flags to IRQ_STATUS register */
    uint8_t tmp = at86rf2xx_reg_read(dev, AT86RF2XX_REG__TRX_CTRL_1);
    tmp &= ~(AT86RF2XX_TRX_CTRL_1_MASK__IRQ_MASK_MODE);
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_CTRL_1, tmp);

    /* disable clock output to save power */
    tmp = at86rf2xx_reg_read(dev, AT86RF2XX_REG__TRX_CTRL_0);
    tmp &= ~(AT86RF2XX_TRX_CTRL_0_MASK__CLKM_CTRL);
    tmp &= ~(AT86RF2XX_TRX_CTRL_0_MASK__CLKM_SHA_SEL);
    tmp |= (AT86RF2XX_TRX_CTRL_0_CLKM_CTRL__OFF);
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_CTRL_0, tmp);

    at86rf2xx_set_option(dev, AT86RF2XX_OPT_CSMA, true);
#if MODULE_OPENTHREAD_FTD || MODULE_OPENTHREAD_MTD
    /* software CSMA */
    at86rf2xx_set_max_retries(dev, 0);
    at86rf2xx_set_csma_max_retries(dev, 0);
    at86rf2xx_set_csma_backoff_exp(dev, 0, 0);
#endif

#if HIGH_DATA_RATE
    /* provide 32us ACK time */
    tmp = at86rf2xx_reg_read(dev, AT86RF2XX_REG__XAH_CTRL_1);
    tmp |= AT86RF2XX_XAH_CTRL_1__AACK_ACK_TIME;
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__XAH_CTRL_1, tmp);

    /* filter packet below -94 dBm */
    tmp = at86rf2xx_reg_read(dev, AT86RF2XX_REG__RX_SYN);
    tmp &= ~(AT86RF2XX_RX_SYN__RX_PDT_LEVEL);
    tmp |= (0x01 & AT86RF2XX_RX_SYN__RX_PDT_LEVEL);
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__RX_SYN, tmp);

    /* high data rate (2Mbps) */
    tmp = at86rf2xx_reg_read(dev, AT86RF2XX_REG__TRX_CTRL_2);
    tmp |= AT86RF2XX_TRX_CTRL_2_MASK__OQPSK_DATA_RATE;
    tmp |= AT86RF2XX_TRX_CTRL_2_MASK__OQPSK_SCRAM_EN;
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_CTRL_2, tmp);
#endif

    /* enable interrupts */
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__IRQ_MASK,
                        AT86RF2XX_IRQ_STATUS_MASK__TRX_END);
    /* clear interrupt flags */
    at86rf2xx_reg_read(dev, AT86RF2XX_REG__IRQ_STATUS);

    /* go into RX state */
    at86rf2xx_set_state(dev, AT86RF2XX_STATE_RX_AACK_ON);

#ifdef CONTINUOUS_CCA
    /* Trigger an ED */
    at86rf2xx_set_option(dev, AT86RF2XX_OPT_TELL_CCA_ED_DONE, true);
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__PHY_ED_LEVEL, 1);
#endif

    DEBUG("at86rf2xx_reset(): reset complete.\n");
}

size_t at86rf2xx_send(at86rf2xx_t *dev, uint8_t *data, size_t len)
{
    /* check data length */
    if (len > AT86RF2XX_MAX_PKT_LENGTH) {
        DEBUG("[at86rf2xx] Error: data to send exceeds max packet size\n");
        return 0;
    }
    at86rf2xx_tx_prepare(dev);
    at86rf2xx_tx_load(dev, data, len, 0);
    at86rf2xx_tx_exec(dev);
    return len;
}

#ifdef RADIO_DUTYCYCLE_MONITOR
extern uint32_t radio_dutycycle_prev;
#endif

extern volatile uint8_t radio_send_state;

bool at86rf2xx_tx_prepare(at86rf2xx_t *dev)
{
    uint8_t old_state;
    dev->pending_tx++;

#if defined(MODULE_OPENTHREAD_FTD) || defined(MODULE_OPENTHREAD_MTD)
    uint8_t new_state;

    /* First, check if the radio busy (common failure case). */
    old_state = at86rf2xx_get_status(dev);
    assert(old_state != AT86RF2XX_STATE_TX_ARET_ON);
    if (old_state == AT86RF2XX_STATE_BUSY_RX_AACK ||
        old_state == AT86RF2XX_STATE_BUSY_TX_ARET) {
        /* We should NOT send right now. This CSMA attempt should fail. */
        DEBUG("[at86rf2xx] radio is busy (0x%x), failing\n", old_state);
        dev->pending_tx--;
        return false;
    }

    /*
     * Second, check if there is a pending RX interrupt to service (common
     * failure case).
     */
    int irq_state = irq_disable();
    if (dev->pending_irq != 0) {
        DEBUG("[at86rf2xx] pending_irq exists (#1), failing\n");
        irq_restore(irq_state);
        dev->pending_tx--;
        /*
         * If there are pending interrupts, we don't want to send just yet.
         * What if the interrupt is for a received packet?
         * Instead, we just return false. When we handle the interrupt, we will
         * check for a received packet, and then attempt this CSMA probe again.
         */
        return false;
    }
    irq_restore(irq_state);

    /*
     * Now, try to transition to TX state.
     */
#ifdef RADIO_DUTYCYCLE_MONITOR
    uint32_t transitionStartTime = 0;
    if (old_state == AT86RF2XX_STATE_SLEEP) {
        transitionStartTime = xtimer_now().ticks32;
    }
#endif
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_STATE, AT86RF2XX_STATE_TX_ARET_ON);
    do {
        new_state = at86rf2xx_get_status(dev);
    } while (new_state == AT86RF2XX_STATE_IN_PROGRESS);

    /*
     * Third, check if the radio started receiving a packet right before we
     * could transition to the TX state (uncommon failure case).
     */
    if (new_state != AT86RF2XX_STATE_TX_ARET_ON) {
        /*
         * This means we transitioned to a busy state at the very last
         * minute. Fail this CSMA attempt.
         */
        DEBUG("[at86rf2xx] new_state is 0x%x, reverting to 0x%x\n", new_state, old_state);
        at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_STATE, old_state);
        dev->pending_tx--;
        return false;
    }
    /*
     * We have transitioned state, so keep track of radio duty cycle.
     * This is probably not needed, since OpenThread will put is in listen
     * mode before sending. But, it's good to have anyway, just in case.
     */
    if (old_state == AT86RF2XX_STATE_SLEEP) {
        DEBUG("at86rf2xx: waking up from sleep mode\n");
#ifdef RADIO_DUTYCYCLE_MONITOR
        assert(transitionStartTime != 0);
        if (radio_dutycycle_prev == 0) {
            radio_dutycycle_prev = transitionStartTime;
        } else {
            uint32_t now = transitionStartTime;
            radioOffTime += (now - radio_dutycycle_prev);
            radio_dutycycle_prev = now;
        }
#endif
    }
    dev->state = new_state;
    DEBUG("[at86rf2xx] send: 0x%x -> 0x%x\n", old_state, new_state);

    /*
     * Fourth, check that a packet was not just finished being received before
     * we switched to TX mode (uncommon failure case).
     * After this, no receive interrupt can happen, because we are in TX state.
     *
     * Note: that last part isn't actually true, because there is apparently a
     * 9 us delay between reception being completed and the receive interrupt
     * being delivered. So a packet could *technically* be sitting the frame
     * buffer, and the radio could have switched to TX_ARET_ON, only for the
     * receive interrupt to fire later. If it fires before we initiate the send,
     * we safely drop the packet and clear the pending interrupt. If it fires
     * sometime after that, we take care to properly detect it and prevent it
     * from overflowing the task thread's queue.
     */
    irq_state = irq_disable();
    if (dev->pending_irq != 0) {
        DEBUG("[at86rf2xx] pending_irq exists (#2), failing\n");
        irq_restore(irq_state);
        at86rf2xx_set_state(dev, old_state);
        dev->pending_tx--;
        /* As above, we return false if there is a pending interrupt. */
        return false;
    }
    /*
     * This makes sure that if we get a delayed receive interrupt in between
     * now and actually initiating the send, that the packet will be dropped in
     * the interrupt handler. It's a partial mitigation to the "9 us" issue
     * mentioned above.
     */
    assert(radio_send_state == 0);
    radio_send_state = 1;
    irq_restore(irq_state);
#else
    /* make sure ongoing transmissions are finished */
    do {
        old_state = at86rf2xx_get_status(dev);
    } while (old_state == AT86RF2XX_STATE_BUSY_RX_AACK ||
             old_state == AT86RF2XX_STATE_BUSY_TX_ARET);

    at86rf2xx_set_state(dev, AT86RF2XX_STATE_TX_ARET_ON);
#endif

    if (old_state != AT86RF2XX_STATE_TX_ARET_ON) {
        dev->idle_state = old_state;
    }

    dev->tx_frame_len = IEEE802154_FCS_LEN;
    return true;
}

size_t at86rf2xx_tx_load(at86rf2xx_t *dev, uint8_t *data,
                         size_t len, size_t offset)
{
    dev->tx_frame_len += (uint8_t)len;
    at86rf2xx_sram_write(dev, offset + 1, data, len);
    return offset + len;
}

void at86rf2xx_tx_exec(at86rf2xx_t *dev)
{
    netdev_t *netdev = (netdev_t *)dev;

    /* write frame length field in FIFO */
    at86rf2xx_sram_write(dev, 0, &(dev->tx_frame_len), 1);

#if AUTO_CSMA_EN
#else
    while(!at86rf2xx_cca(dev)) {
      at86rf2xx_set_state(dev, AT86RF2XX_STATE_RX_AACK_ON); /* Listening during backoff */
      xtimer_usleep((rand()%(2^BE))*320);
      at86rf2xx_set_state(dev, AT86RF2XX_STATE_TX_ARET_ON);
      printf("CCA busy %u\n", (2^BE)*320);
      if (BE < MAX_BE) {
        BE++;
      }
    }
#endif

    /* trigger sending of pre-loaded frame */
    unsigned state = irq_disable();
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__TRX_STATE,
                        AT86RF2XX_TRX_STATE__TX_START);
#ifdef MODULE_OPENTHREAD
    radio_send_state = 2;
#endif
    irq_restore(state);
    DEBUG("[at86rf2xx] TX_EXEC\n");
    if (netdev->event_callback &&
        (dev->netdev.flags & AT86RF2XX_OPT_TELL_TX_START)) {
        netdev->event_callback(netdev, NETDEV_EVENT_TX_STARTED);
    }
}

bool at86rf2xx_cca(at86rf2xx_t *dev)
{
    uint8_t reg;
    uint8_t old_state = at86rf2xx_set_state(dev, AT86RF2XX_STATE_TRX_OFF);
    /* Disable RX path */
    uint8_t rx_syn = at86rf2xx_reg_read(dev, AT86RF2XX_REG__RX_SYN);
    reg = rx_syn | AT86RF2XX_RX_SYN__RX_PDT_DIS;
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__RX_SYN, reg);
    /* Manually triggered CCA is only possible in RX_ON (basic operating mode) */
    at86rf2xx_set_state(dev, AT86RF2XX_STATE_RX_ON);
    /* Perform CCA */
    reg = at86rf2xx_reg_read(dev, AT86RF2XX_REG__PHY_CC_CCA);
    reg |= AT86RF2XX_PHY_CC_CCA_MASK__CCA_REQUEST;
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__PHY_CC_CCA, reg);
    /* Spin until done (8 symbols + 12 µs = 128 µs + 12 µs for O-QPSK)*/
    do {
        reg = at86rf2xx_reg_read(dev, AT86RF2XX_REG__TRX_STATUS);
    } while ((reg & AT86RF2XX_TRX_STATUS_MASK__CCA_DONE) == 0);
    /* return true if channel is clear */
    bool ret = !!(reg & AT86RF2XX_TRX_STATUS_MASK__CCA_STATUS);
    /* re-enable RX */
    at86rf2xx_reg_write(dev, AT86RF2XX_REG__RX_SYN, rx_syn);
    /* Step back to the old state */
    at86rf2xx_set_state(dev, AT86RF2XX_STATE_TRX_OFF);
    at86rf2xx_set_state(dev, old_state);
    return ret;
}
