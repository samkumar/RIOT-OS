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
 * @brief       Implementation of OpenThread logging platform abstraction
 *
 * @author      Jose Ignacio Alamos <jialamos@uc.cl>
 * @author      Baptiste Clenet <bapclenet@gmail.com>
 * @}
 */

#include "openthread/config.h"
#include "openthread/platform/logging.h"
#if OPENTHREAD_ENABLE_CLI_LOGGING
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "utils/code_utils.h"
#include "cli/cli-uart.h"
#endif

#ifdef MODULE_OPENTHREAD_NCP_FTD
#define ENABLE_DEBUG (1)
#else
#define ENABLE_DEBUG (1)
#endif
#include <debug.h>

void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
{
    if (aLogRegion == OT_LOG_REGION_MEM || aLogRegion == OT_LOG_REGION_MLE) {
#if OPENTHREAD_ENABLE_CLI_LOGGING
    va_list args;
    va_start(args, aFormat);
    otCliLog(aLogLevel, aLogRegion, aFormat, args);
    va_end(args);
#else
    (void)aLogLevel;
    (void)aLogRegion;
    va_list args;
    va_start(args, aFormat);
    DEBUG_V(aFormat, args);
    va_end(args);
#endif /* OPENTHREAD_ENABLE_CLI_LOGGING */
    }
}
