/*
 * Copyright 2018, 2020, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "ax_reset.h"
#include "se_reset_config.h"
#include "sm_timer.h"

#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"

#if defined(MBEDTLS)
#include "ksdk_mbedtls.h"
#endif

#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"

#include "iot_wifi.h"
#include "wifi_config.h"

#include <nxp_iot_agent_status.h>

uint8_t Wifi_IP[4] = {0};

iot_agent_status_t network_init(void)
{
    const WIFINetworkParams_t pxNetworkParams = {
        .pcSSID = clientcredentialWIFI_SSID,
        .pcPassword = clientcredentialWIFI_PASSWORD,
        .xSecurity = clientcredentialWIFI_SECURITY,
    };

    if (WIFI_On() != eWiFiSuccess) {
        return IOT_AGENT_FAILURE;
    }

    if (WIFI_ConnectAP(&pxNetworkParams) != eWiFiSuccess) {
        return IOT_AGENT_FAILURE;
    }

    if (WIFI_GetIP(Wifi_IP) != eWiFiSuccess) {
        return IOT_AGENT_FAILURE;
    }
    return IOT_AGENT_SUCCESS;
}
