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
 * @brief       Implementation of OpenThread radio platform abstraction
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @}
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "byteorder.h"
#include "errno.h"
#include "irq.h"
#include "net/ethernet/hdr.h"
#include "net/ethertype.h"
#include "net/ieee802154.h"
#include "net/netdev/ieee802154.h"
#include "openthread/config.h"
#include "openthread/openthread.h"
#include "openthread/platform/diag.h"
#include "openthread/platform/platform.h"
#include "openthread/platform/radio.h"
#include "ot.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#define RADIO_IEEE802154_FCS_LEN    (2U)
#define IEEE802154_ACK_LENGTH (5)
#define IEEE802154_DSN_OFFSET (2)

static otRadioFrame sTransmitFrame;
static otRadioFrame sReceiveFrame;
static otRadioFrame sAckFrame;
static uint8_t rx_buf[OPENTHREAD_NETDEV_BUFLEN];
static uint8_t tx_buf[OPENTHREAD_NETDEV_BUFLEN];
static uint8_t ack_buf[IEEE802154_ACK_LENGTH];

static struct iovec pkt;

static int8_t Rssi;
static netdev_t *_dev;

static bool sDisabled;

static uint8_t short_address_list = 0;
static uint8_t ext_address_list = 0;

/* set 15.4 channel */
static int _set_channel(uint16_t channel)
{
    return _dev->driver->set(_dev, NETOPT_CHANNEL, &channel, sizeof(uint16_t));
}

/* set transmission power */
static int _set_power(int16_t power)
{
    return _dev->driver->set(_dev, NETOPT_TX_POWER, &power, sizeof(int16_t));
}

/* get transmission power */
static void _get_power(int16_t *power)
{
    _dev->driver->get(_dev, NETOPT_TX_POWER, power, sizeof(int16_t));
}

/* set IEEE802.15.4 PAN ID */
static int _set_panid(uint16_t panid)
{
    return _dev->driver->set(_dev, NETOPT_NID, &panid, sizeof(uint16_t));
}

/* set extended HW address */
static int _set_long_addr(uint8_t *ext_addr)
{
    return _dev->driver->set(_dev, NETOPT_ADDRESS_LONG, ext_addr, IEEE802154_LONG_ADDRESS_LEN);
}

/* set short address */
static int _set_addr(uint16_t addr)
{
    return _dev->driver->set(_dev, NETOPT_ADDRESS, &addr, sizeof(uint16_t));
}

/* check the state of promiscuous mode */
static netopt_enable_t _is_promiscuous(void)
{
    netopt_enable_t en;

    _dev->driver->get(_dev, NETOPT_PROMISCUOUSMODE, &en, sizeof(en));
    return en == NETOPT_ENABLE ? true : false;;
}

/* set the state of promiscuous mode */
static int _set_promiscuous(netopt_enable_t enable)
{
    return _dev->driver->set(_dev, NETOPT_PROMISCUOUSMODE, &enable, sizeof(enable));
}

/* wrapper for setting device state */
static void _set_state(netopt_state_t state)
{
    _dev->driver->set(_dev, NETOPT_STATE, &state, sizeof(netopt_state_t));
}

/* wrapper for getting device state */
static netopt_state_t _get_state(void)
{
    netopt_state_t state;
    _dev->driver->get(_dev, NETOPT_STATE, &state, sizeof(netopt_state_t));
    return state;
}

/* sets device state to SLEEP */
static void _set_sleep(void)
{
    _set_state(NETOPT_STATE_SLEEP);
}

/* set device state to IDLE */
static void _set_idle(void)
{
    _set_state(NETOPT_STATE_IDLE);
}

/* init framebuffers and initial state */
void openthread_radio_init(netdev_t *dev)
{
    sTransmitFrame.mPsdu = tx_buf;
    sTransmitFrame.mLength = 0;
    sReceiveFrame.mPsdu = rx_buf;
    sReceiveFrame.mLength = 0;
    sAckFrame.mPsdu = ack_buf;
    sAckFrame.mLength = IEEE802154_ACK_LENGTH;
    _dev = dev;
    int16_t otTxPower = OPENTHREAD_TXPOWER;
    _set_power(otTxPower);
}

/* OpenThread will call this for setting PAN ID */
void otPlatRadioSetPanId(otInstance *aInstance, uint16_t panid)
{
    DEBUG("otPlatRadioSetPanId: setting PAN ID to %04x\n", panid);
    _set_panid(panid);
}

/* OpenThread will call this for setting extended address */
void otPlatRadioSetExtendedAddress(otInstance *aInstance, const otExtAddress *aExtendedAddress)
{
    DEBUG("otPlatRadioSetExtendedAddr\n");
    uint8_t reversed_addr[IEEE802154_LONG_ADDRESS_LEN];
    for (int i = 0; i < IEEE802154_LONG_ADDRESS_LEN; i++) {
        reversed_addr[i] = aExtendedAddress->m8[IEEE802154_LONG_ADDRESS_LEN - 1 - i];
    }
    _set_long_addr(reversed_addr);
}

/* OpenThread will call this for setting short address */
void otPlatRadioSetShortAddress(otInstance *aInstance, uint16_t aShortAddress)
{
    DEBUG("otPlatRadioSetShortAddr: %04x\n", aShortAddress);
    _set_addr(((aShortAddress & 0xff) << 8) | ((aShortAddress >> 8) & 0xff));
}

/* OpenThread will call this for enabling the radio */
otError otPlatRadioEnable(otInstance *aInstance)
{
    DEBUG("otPlatRadioEnable\n");
    (void) aInstance;

    if (sDisabled) {
        sDisabled = false;
        _set_idle();
    }

    return OT_ERROR_NONE;
}

/* OpenThread will call this for disabling the radio */
otError otPlatRadioDisable(otInstance *aInstance)
{
    DEBUG("otPlatRadioDisable\n");
    (void) aInstance;

    if (!sDisabled) {
        sDisabled = true;
        _set_sleep();
    }
    return OT_ERROR_NONE;
}

bool otPlatRadioIsEnabled(otInstance *aInstance)
{
    DEBUG("otPlatRadioIsEnabled\n");
    (void) aInstance;
    netopt_state_t state = _get_state();
    if (state == NETOPT_STATE_OFF || state == NETOPT_STATE_SLEEP) {
        return false;
    } else {
        return true;
    }
}

/* OpenThread will call this for setting device state to SLEEP */
otError otPlatRadioSleep(otInstance *aInstance)
{
    DEBUG("otPlatRadioSleep\n");
    (void) aInstance;

    _set_sleep();
    return OT_ERROR_NONE;
}

/*OpenThread will call this for waiting the reception of a packet */
otError otPlatRadioReceive(otInstance *aInstance, uint8_t aChannel)
{
    //DEBUG("openthread: otPlatRadioReceive. Channel: %i\n", aChannel);
    (void) aInstance;
    _set_idle();
    _set_channel(aChannel);
    return OT_ERROR_NONE;
}

/* OpenThread will call this function to get the transmit buffer */
otRadioFrame *otPlatRadioGetTransmitBuffer(otInstance *aInstance)
{
    DEBUG("otPlatRadioGetTransmitBuffer\n");
    return &sTransmitFrame;
}

/* OpenThread will call this function to set the transmit power */
otError otPlatRadioSetTransmitPower(otInstance *aInstance, int8_t aPower)
{
    DEBUG("otPlatRadioSetTransmitPower\n");
    (void)aInstance;
    _set_power(aPower);

    return OT_ERROR_NONE;
}

/* OpenThread will call this function to get the transmit power */
otError otPlatRadioGetTransmitPower(otInstance *aInstance, int8_t *aPower)
{
    DEBUG("otPlatRadioGetTransmitPower\n");
    (void)aInstance;
    int16_t power = 0;
    _get_power(&power);
    *aPower = (int8_t) power;
    
    return OT_ERROR_NONE;
}

/* OpenThread will call this for transmitting a packet*/
otError otPlatRadioTransmit(otInstance *aInstance, otRadioFrame *aPacket)
{
    (void) aInstance;
    (void) aPacket;

    /* Populate iovec with transmit data
     * Unlike RIOT, OpenThread includes two bytes FCS (0x00 0x00) so
     * these bytes are removed
     */
    pkt.iov_base = sTransmitFrame.mPsdu;
    pkt.iov_len = sTransmitFrame.mLength - RADIO_IEEE802154_FCS_LEN;

    /*Set channel and power based on transmit frame */
    //DEBUG("otTx->channel: %i, length %d\n", (int) aPacket->mChannel, (int)aPacket->mLength);
    /*for (int i = 0; i < aPacket->mLength; ++i) {
        DEBUG("%x ", aPacket->mPsdu[i]);
    }
    DEBUG("\n");*/

    int success = -1;
    while(1) {
        mutex_lock(openthread_get_radio_mutex());
        printf("try->");
        //_set_channel(aPacket->mChannel);
        /* send packet though netdev */
        success = _dev->driver->send(_dev, &pkt, 1);
        printf("done %d\n", success);
        mutex_unlock(openthread_get_radio_mutex());
        if (success == -1) {
            /* Fail to send since the transceiver is busy (receiving).
             * Retry in a little bit. 
             */
            xtimer_usleep(1000+rand()%4000);
        } else {
            /* Succeed in sending */
            break;
        }
    }

    return OT_ERROR_NONE;
}

/* OpenThread will call this for getting the radio caps */
otRadioCaps otPlatRadioGetCaps(otInstance *aInstance)
{
    //DEBUG("openthread: otPlatRadioGetCaps\n");
#if MODULE_AT86RF231 | MODULE_AT86RF233
#ifdef MODULE_OPENTHREAD_FTD
    /* radio drivers do not support retransmission and CSMA for better performance */
    return OT_RADIO_CAPS_ACK_TIMEOUT;
#else
    /* radio drivers should handle retransmission and CSMA to minimize CPU run */
    return OT_RADIO_CAPS_ACK_TIMEOUT | OT_RADIO_CAPS_TRANSMIT_RETRIES | OT_RADIO_CAPS_CSMA_BACKOFF;
#endif
#else
    return OT_RADIO_CAPS_NONE;
#endif
}

/* OpenThread will call this for getting the state of promiscuous mode */
bool otPlatRadioGetPromiscuous(otInstance *aInstance)
{
    //DEBUG("openthread: otPlatRadioGetPromiscuous\n");
    return _is_promiscuous();
}

/* OpenThread will call this for setting the state of promiscuous mode */
void otPlatRadioSetPromiscuous(otInstance *aInstance, bool aEnable)
{
    //DEBUG("openthread: otPlatRadioSetPromiscuous\n");
    _set_promiscuous((aEnable) ? NETOPT_ENABLE : NETOPT_DISABLE);
}

int8_t otPlatRadioGetRssi(otInstance *aInstance)
{
    DEBUG("otPlatRadioGetRssi\n");
    (void) aInstance;
    return Rssi;
}

void otPlatRadioEnableSrcMatch(otInstance *aInstance, bool aEnable)
{
    DEBUG("otPlatRadioEnableSrcMatch\n");
    (void)aInstance;
    (void)aEnable;
}

/* OpenThread will call this for indirect transmission to a child node */
otError otPlatRadioAddSrcMatchShortEntry(otInstance *aInstance, const uint16_t aShortAddress)
{
    DEBUG("otPlatRadioAddSrcMatchShortEntry %u\n", short_address_list+1);
    (void)aInstance;
    (void)aShortAddress;
    short_address_list++;
    bool pending = true;
    _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool));
    return OT_ERROR_NONE;
}

/* OpenThread will call this for indirect transmission to a child node */
otError otPlatRadioAddSrcMatchExtEntry(otInstance *aInstance, const otExtAddress *aExtAddress)
{
    DEBUG("otPlatRadioAddSrcMatchExtEntry %u\n", ext_address_list+1);
    (void)aInstance;
    (void)aExtAddress;
    ext_address_list++;
    bool pending = true;
    _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool));
    return OT_ERROR_NONE;
}

/* OpenThread will call this to remove an indirect transmission entry */
otError otPlatRadioClearSrcMatchShortEntry(otInstance *aInstance, const uint16_t aShortAddress)
{
    DEBUG("otPlatRadioClearSrcMatchShortEntry %u\n", short_address_list-1);
    (void)aInstance;
    (void)aShortAddress;
    short_address_list--;
    if (ext_address_list == 0 && short_address_list == 0) {
        bool pending = false;
        _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool));
    }
    return OT_ERROR_NONE;
}

/* OpenThread will call this to remove an indirect transmission entry */
otError otPlatRadioClearSrcMatchExtEntry(otInstance *aInstance, const otExtAddress *aExtAddress)
{
    DEBUG("otPlatRadioClearSrcMatchExtEntry %u\n", ext_address_list-1);
    (void)aInstance;
    (void)aExtAddress;
    ext_address_list--;
    if (ext_address_list == 0 && short_address_list == 0) {
        bool pending = false;
        _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool));
    }
    return OT_ERROR_NONE;
}

/* OpenThread will call this to clear indirect transmission list */
void otPlatRadioClearSrcMatchShortEntries(otInstance *aInstance)
{
    DEBUG("otPlatRadioClearSrcMatchShortEntries\n");    
    (void)aInstance;
    short_address_list = 0;
    if (ext_address_list == 0 && short_address_list == 0) {
        bool pending = false;
        _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool));
    }
}

/* OpenThread will call this to clear indirect transmission list */
void otPlatRadioClearSrcMatchExtEntries(otInstance *aInstance)
{
    DEBUG("otPlatRadioClearSrcMatchExtEntries\n");
    (void)aInstance;
    ext_address_list = 0;
    if (ext_address_list == 0 && short_address_list == 0) {
        bool pending = false;
        _dev->driver->set(_dev, NETOPT_ACK_PENDING, &pending, sizeof(bool)); 
    }
}

otError otPlatRadioEnergyScan(otInstance *aInstance, uint8_t aScanChannel, uint16_t aScanDuration)
{
    DEBUG("otPlatRadioEnergyScan\n");
    (void)aInstance;
    (void)aScanChannel;
    (void)aScanDuration;
    return OT_ERROR_NOT_IMPLEMENTED;
}

void otPlatRadioGetIeeeEui64(otInstance *aInstance, uint8_t *aIeee64Eui64)
{
    _dev->driver->get(_dev, NETOPT_IPV6_IID, aIeee64Eui64, sizeof(eui64_t));
}

int8_t otPlatRadioGetReceiveSensitivity(otInstance *aInstance)
{
#if MODULE_AT86RF231 | MODULE_AT86RF233
    return -94;
#else
    return -100;
#endif
}


/* create a fake ACK frame */
// TODO: pass received ACK frame instead of generating one.
static inline void _create_fake_ack_frame(bool ackPending)
{
    sAckFrame.mPsdu[0] = IEEE802154_FCF_TYPE_ACK;
    if (ackPending) {
        sAckFrame.mPsdu[0] |= IEEE802154_FCF_FRAME_PEND;
    }
    sAckFrame.mPsdu[1] = 0;
    sAckFrame.mPsdu[2] = sTransmitFrame.mPsdu[IEEE802154_DSN_OFFSET];

    sAckFrame.mRssi = OT_RADIO_RSSI_INVALID;
}

/* Called upon TX event */
void sent_pkt(otInstance *aInstance, netdev_event_t event)
{
    /* Tell OpenThread transmission is done depending on the NETDEV event */
    switch (event) {
        case NETDEV_EVENT_TX_COMPLETE:
            DEBUG("TX_COMPLETE\n");
            _create_fake_ack_frame(false);
            otPlatRadioTxDone(aInstance, &sTransmitFrame, &sAckFrame, OT_ERROR_NONE);
            break;
        case NETDEV_EVENT_TX_COMPLETE_DATA_PENDING:
            DEBUG("TX_COMPLETE_DATA_PENDING\n");
            _create_fake_ack_frame(true);
            otPlatRadioTxDone(aInstance, &sTransmitFrame, &sAckFrame, OT_ERROR_NONE);
            break;
        case NETDEV_EVENT_TX_NOACK:
            DEBUG("TX_NOACK\n");
            otPlatRadioTxDone(aInstance, &sTransmitFrame, NULL, OT_ERROR_NO_ACK);
            break;
        case NETDEV_EVENT_TX_MEDIUM_BUSY:
            DEBUG("TX_MEDIUM_BUSY\n");
            otPlatRadioTxDone(aInstance, &sTransmitFrame, NULL, OT_ERROR_CHANNEL_ACCESS_FAILURE);
            break;
        default:
            break;
    }
}

/* Called upon NETDEV_EVENT_RX_COMPLETE event */
void recv_pkt(otInstance *aInstance, netdev_t *dev)
{
    netdev_ieee802154_rx_info_t rx_info;
    int res;

    /* Read frame length from driver */
    int len = dev->driver->recv(dev, NULL, 0, NULL);

    /* very unlikely */
    if ((len > (unsigned) UINT16_MAX)) {    
        DEBUG("Len too high: %d\n", len);
        res = -1;
        goto exit;
    }

    /* Fill OpenThread receive frame */
    /* Openthread needs a packet length with FCS included,
     * OpenThread do not use the data so we don't need to calculate FCS */
    sReceiveFrame.mLength = len + RADIO_IEEE802154_FCS_LEN;
    
    /* Read received frame */
    res = dev->driver->recv(dev, (char *) sReceiveFrame.mPsdu, len, &rx_info);

#if MODULE_AT86RF231 | MODULE_AT86RF233
    Rssi = (int8_t)rx_info.rssi - 94;
#else
    Rssi = (int8_t)rx_info.rssi;
#endif
    sReceiveFrame.mRssi = Rssi;

    DEBUG("\nRX: len %d, rssi %d\n", (int) sReceiveFrame.mLength, sReceiveFrame.mRssi);
    /*for (int i = 0; i < sReceiveFrame.mLength; ++i) {
        DEBUG("%x ", sReceiveFrame.mPsdu[i]);
    }
    DEBUG("\n");*/
exit:
    otPlatRadioReceiveDone(aInstance, res > 0 ? &sReceiveFrame : NULL, 
                           res > 0 ? OT_ERROR_NONE : OT_ERROR_ABORT);
}
