/*
 *  TCP/IP or UDP/IP networking functions
 *  modified for LWIP support on ESP8266
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Additions Copyright (C) 2015 Angus Gratton
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if defined(USE_RTOS) && USE_RTOS == 1

#include <sys/types.h>

#include "FreeRTOS.h"
#include "task.h"

#include "board.h"
#include "ksdk_mbedtls.h"
#include "nxLog_App.h"

#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"

#include "iot_wifi.h"
#include "wifi_config.h"
#include "atheros_stack_offload.h"
#include "qcom_api.h"

#include "mbedtls/net.h"



/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
    ctx->fd = -1;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx, const char *host, const char *port, int proto )
{
    SOCKADDR_T addr;
	A_STATUS status;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = ATH_AF_INET;
    addr.sin_port = atoi(port);
	
    status = qcom_dnsc_get_host_by_name((char *)host, &addr.sin_addr.s_addr );
    if (status != A_OK || addr.sin_addr.s_addr == 0) {
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }

    ctx->fd = qcom_socket(ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (ctx->fd == -1) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }

    status = (A_STATUS)qcom_connect(ctx->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (status != A_OK) {
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    }

	return 0;
}

/*
 * Set the socket blocking or non-blocking
 */
int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
	return -1;
}

int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
	return -1;
}

#if 0
static int socket_errno( const mbedtls_net_context *ctx )
{
    int sock_errno = 0;
    size_t optlen = sizeof(sock_errno);
    qcom_getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, &sock_errno, optlen);
    return sock_errno;
}
#endif


/* Read at most 'len' characters */
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len)
{
    QCA_CONTEXT_STRUCT * enetCtx =  Custom_Api_GetDriverCxt(0);
    A_STATUS xStatus;

    int fd = ((mbedtls_net_context *) ctx)->fd;

    char * buffLoc = NULL;
    int xRetVal = 0;

    for( ; ; )
    {
        // qcom_recv returns the status from cust_api_stack_offload:Api_recvfrom()
        // which returns -1 in case of non-blocking call AND in blocking call timeout.
        // Since blocking call timeout is hardcoded to 1ms (indirectly
        // in cust_api_stack_offload:Api_recvfrom() it is set to 0 and
        // in api_stack_offload.c:blockForResponse() it is set to 1.
        // This means we HAVE TO to a select here and only call recv in case 
        // data is available.

        /* Check if there is anything to be received on this socket. */
        xStatus = ( A_STATUS ) t_select( enetCtx, ( uint32_t ) fd, 1 );

        if( xStatus == A_OK ) /* Data available. */
        {
            xRetVal = qcom_recv( fd, &buffLoc, len, 0 );

            if( xRetVal > 0 ) /* Data received. */
            {
                memcpy( buf, buffLoc, xRetVal );
                break;
            }
            else /* Error occured. */
            {
                /*int errno = t_errno( wlan_get_context(), ( uint32_t ) pxContext->xSocket ); */
                xRetVal = MBEDTLS_ERR_NET_RECV_FAILED;
                break;
            }
        }
        else if( xStatus == A_ERROR ) /* A_ERROR is returned from t_select on timeout. */
        {
            vTaskDelay( pdMS_TO_TICKS( 5 ) );
        }
        else
        {
            xRetVal = MBEDTLS_ERR_NET_RECV_FAILED;
            break;
        }
    }

    if( buffLoc != NULL )
    {
        zero_copy_free( buffLoc );
    }

    return xRetVal;
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx, unsigned char *buf, size_t len,
                      uint32_t timeout )
{
	return mbedtls_net_recv(ctx, buf, len);
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    char* sendBuf = custom_alloc(len);

    if(sendBuf == NULL)
    {
        return -1;
    }

    memcpy(sendBuf, buf, len);

    ret = (int) qcom_send( fd, sendBuf, len , 0); // FIXME: Options

    if( ret < 0 )
    {
        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }

    custom_free( sendBuf );

    return( ret );
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
    if( ctx->fd == -1 )
        return;

    qcom_socket_close( ctx->fd );

    ctx->fd = -1;
}

#endif

