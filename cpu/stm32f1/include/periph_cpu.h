/*
 * Copyright (C) 2015-2016 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup         cpu_stm32f1
 * @{
 *
 * @file
 * @brief           CPU specific definitions for internal peripheral handling
 *
 * @author          Hauke Petersen <hauke.peterse@fu-berlin.de>
 */

#ifndef PERIPH_CPU_H
#define PERIPH_CPU_H

#include "periph_cpu_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Available number of ADC devices
 */
#define ADC_DEVS            (2U)

/**
 * @brief   All timers for the STM32F1 have 4 CC channels
 */
#define TIMER_CHANNELS      (4U)

/**
 * @brief   All timers have a width of 16-bit
 */
#define TIMER_MAXVAL        (0xffff)

/**
 * @brief   Generate GPIO mode bitfields
 *
 * We use 4 bit to determine the pin functions:
 * - bit 4: ODR value
 * - bit 2+3: in/out
 * - bit 1: PU enable
 * - bit 2: OD enable
 */
#define GPIO_MODE(mode, cnf, odr)       (mode | (cnf << 2) | (odr << 4))

#ifndef DOXYGEN
/**
 * @brief   Override GPIO mode options
 *
 * We use 4 bit to encode CNF and MODE.
 * @{
 */
#define HAVE_GPIO_MODE_T
typedef enum {
    GPIO_IN    = GPIO_MODE(0, 1, 0),    /**< input w/o pull R */
    GPIO_IN_PD = GPIO_MODE(0, 2, 0),    /**< input with pull-down */
    GPIO_IN_PU = GPIO_MODE(0, 2, 1),    /**< input with pull-up */
    GPIO_OUT   = GPIO_MODE(3, 0, 0),    /**< push-pull output */
    GPIO_OD    = GPIO_MODE(3, 1, 0),    /**< open-drain w/o pull R */
    GPIO_OD_PU = (0xff)                 /**< not supported by HW */
} gpio_mode_t;
/** @} */
#endif /* ndef DOXYGEN */

/**
 * @brief   Override values for pull register configuration
 * @{
 */
#define HAVE_GPIO_PP_T
typedef enum {
    GPIO_NOPULL = 4,        /**< do not use internal pull resistors */
    GPIO_PULLUP = 9,        /**< enable internal pull-up resistor */
    GPIO_PULLDOWN = 8       /**< enable internal pull-down resistor */
} gpio_pp_t;
/** @} */

#ifndef DOXYGEN
/**
 * @brief   Override flank configuration values
 * @{
 */
#define HAVE_GPIO_FLANK_T
typedef enum {
    GPIO_RISING = 1,        /**< emit interrupt on rising flank */
    GPIO_FALLING = 2,       /**< emit interrupt on falling flank */
    GPIO_BOTH = 3           /**< emit interrupt on both flanks */
} gpio_flank_t;
/** @} */
#endif /* ndef DOXYGEN */

/**
 * @brief   Available ports on the STM32F1 family
 */
enum {
    PORT_A = 0,             /**< port A */
    PORT_B = 1,             /**< port B */
    PORT_C = 2,             /**< port C */
    PORT_D = 3,             /**< port D */
    PORT_E = 4,             /**< port E */
    PORT_F = 5,             /**< port F */
    PORT_G = 6,             /**< port G */
};

/**
 * @brief   Define alternate function modes
 *
 * On this CPU, only the output pins have alternate function modes. The input
 * pins have to be configured using the default gpio_init() function.
 */
typedef enum {
    GPIO_AF_OUT_PP = 0xb,   /**< alternate function output - push-pull */
    GPIO_AF_OUT_OD = 0xf,   /**< alternate function output - open-drain */
} gpio_af_out_t;

/**
 * @brief   ADC channel configuration data
 */
typedef struct {
    gpio_t pin;             /**< pin connected to the channel */
    uint8_t dev;            /**< ADCx - 1 device used for the channel */
    uint8_t chan;           /**< CPU ADC channel connected to the pin */
} adc_conf_t;

/**
 * @brief   Timer configuration
 */
typedef struct {
    TIM_TypeDef *dev;       /**< timer device */
    uint32_t rcc_mask;      /**< corresponding bit in the RCC register */
    uint8_t bus;            /**< APBx bus the timer is clock from */
    uint8_t irqn;           /**< global IRQ channel */
} timer_conf_t;

/**
 * @brief   UART configuration options
 */
typedef struct {
    USART_TypeDef *dev;     /**< UART device */
    gpio_t rx_pin;          /**< TX pin */
    gpio_t tx_pin;          /**< RX pin */
    uint32_t rcc_pin;       /**< bit in the RCC register */
    uint8_t bus;            /**< peripheral bus */
    uint8_t irqn;           /**< interrupt number */
} uart_conf_t;

/**
 * @brief   DAC line configuration data
 */
typedef struct {
    gpio_t pin;             /**< pin connected to the line */
    uint8_t chan;           /**< DAC device used for this line */
} dac_conf_t;

/**
 * @brief   Configure the alternate function for the given pin
 *
 * @note    This is meant for internal use in STM32F1 peripheral drivers only
 *
 * @param[in] pin       pin to configure
 * @param[in] af        alternate function to use
 */
void gpio_init_af(gpio_t pin, gpio_af_out_t af);

#ifdef __cplusplus
}
#endif

#endif /* PERIPH_CPU_H_ */
/** @} */
