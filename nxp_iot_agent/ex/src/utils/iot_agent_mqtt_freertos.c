/* Copyright 2019, 2020, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fsl_sss_api.h>
#include <nxp_iot_agent_service.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent.h>

// #include "aws_bufferpool.h"
#include "iot_mqtt_agent.h"
#include "iot_mqtt_agent_config.h"
#include "iot_mqtt_agent_config_defaults.h"
#include "iot_secure_sockets.h"
#include "iot_default_root_certificates.h"
#include "iot_init.h"

#include "jsmn.h"

#include <mbedtls/pk.h>

#include "ex_sss_boot.h"

#if SSS_HAVE_ALT_SSS
#include "sss_mbedtls.h"
#endif

#include "sm_types.h"

#if SSS_HAVE_SSS
#include <fsl_sss_sscp.h>
#include <fsl_sss_api.h>
#endif

#include "nxLog_App.h"

extern ex_sss_cloud_ctx_t *pex_sss_demo_tls_ctx;

static iot_agent_status_t awsPubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor);

static iot_agent_status_t customPubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor);

static iot_agent_status_t azurePubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor);

static iot_agent_status_t associateKeyPair(mbedtls_pk_context *pk, sss_object_t* service_private_key,
        iot_agent_keystore_t* keystore, uint32_t key_id);

static iot_agent_status_t write_cert_to_keystore(iot_agent_keystore_t* keystore,
		const nxp_iot_ServiceDescriptor* service_descriptor, uint32_t cert_id);

static iot_agent_status_t pubSub(iot_agent_context_t* iot_agent_context,
		const nxp_iot_ServiceDescriptor* service_descriptor);

#if	(AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1)
static iot_agent_status_t pubSubCosOverRtp(iot_agent_context_t* iot_agent_context,
		const nxp_iot_ServiceDescriptor* service_descriptor);
#endif

typedef enum { NOT_ASSIGNED, ASSIGNING, ASSIGNED } registration_state;

// doc: trigger MQTT connection freertos - start
iot_agent_status_t iot_agent_verify_mqtt_connection_for_service(iot_agent_context_t* iot_agent_context, 
        const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    agent_status = pubSub(iot_agent_context, service_descriptor);
    AGENT_SUCCESS_OR_EXIT_MSG("MQTT connection test failed");
exit:
    return agent_status;
}

iot_agent_status_t iot_agent_verify_mqtt_connection(iot_agent_context_t* iot_agent_context)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    size_t number_of_services = 0U;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

    number_of_services = iot_agent_get_number_of_services(iot_agent_context);
    for (size_t i = 0U; i < number_of_services; i++)
    {
		agent_status = iot_agent_select_service_by_index(iot_agent_context, i, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();

		agent_status = iot_agent_verify_mqtt_connection_for_service(iot_agent_context, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
exit:
	iot_agent_free_service_descriptor(&service_descriptor);
    return agent_status;
}
// doc: trigger MQTT connection freertos - end

iot_agent_status_t iot_agent_cleanup_mqtt_config_files()
{
	return IOT_AGENT_SUCCESS;
}

#if	(AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1)
iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context,
		const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    agent_status = pubSubCosOverRtp(iot_agent_context, service_descriptor);
    AGENT_SUCCESS_OR_EXIT_MSG("MQTT connection test failed");
exit:
    return agent_status;
}

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp()
{
	return IOT_AGENT_SUCCESS;
}

iot_agent_status_t pubSubCosOverRtp(iot_agent_context_t* iot_agent_context,
        const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	iot_agent_keystore_t* keystore = NULL;
    sss_object_t service_private_key = {0};

	uint32_t key_id = (uint32_t) (service_descriptor->client_key_sss_ref.object_id);
	uint32_t cert_id = (uint32_t) (service_descriptor->client_certificate_sss_ref.object_id);

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

    mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	agent_status = associateKeyPair(&pk, &service_private_key, keystore, key_id);
	AGENT_SUCCESS_OR_EXIT();

	pex_sss_demo_tls_ctx->client_cert_index = cert_id;

    BaseType_t sdk_result;
    sdk_result = IotSdk_Init();
	ASSERT_OR_EXIT_MSG(sdk_result == pdPASS, "\nFailure at IotSdk_Init\n");

    if(service_descriptor->service_type == nxp_iot_ServiceType_AWSSERVICE)
	{
		agent_status = awsPubMqttMessage(service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
    else if (service_descriptor->service_type == nxp_iot_ServiceType_AZURESERVICE)
    {
        agent_status = azurePubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
    }
    else if (service_descriptor->service_type == nxp_iot_ServiceType_CUSTOMSERVICE)
    {
        agent_status = customPubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
    }

exit:
	IotSdk_Cleanup();
	mbedtls_pk_free(&pk);
	return agent_status;
}

#endif


iot_agent_status_t pubSub(iot_agent_context_t* iot_agent_context, 
        const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	iot_agent_keystore_t* keystore = NULL;
    sss_object_t service_private_key = {0};

	uint32_t key_id = (uint32_t) (service_descriptor->identifier | 0x80000000);
	uint32_t cert_id = (uint32_t) (service_descriptor->identifier | 0x40000000);

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

    mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	agent_status = associateKeyPair(&pk, &service_private_key, keystore, key_id);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = write_cert_to_keystore(keystore, service_descriptor, cert_id);
	AGENT_SUCCESS_OR_EXIT();

    BaseType_t sdk_result;
    sdk_result = IotSdk_Init();
	ASSERT_OR_EXIT_MSG(sdk_result == pdPASS, "\nFailure at IotSdk_Init\n");

    if(service_descriptor->service_type == nxp_iot_ServiceType_AWSSERVICE)
	{
		agent_status = awsPubMqttMessage(service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
    else if (service_descriptor->service_type == nxp_iot_ServiceType_AZURESERVICE)
    {
        agent_status = azurePubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
    }
    else if (service_descriptor->service_type == nxp_iot_ServiceType_CUSTOMSERVICE)
    {
        agent_status = customPubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
    }

exit:
	IotSdk_Cleanup();
	mbedtls_pk_free(&pk);
	return agent_status;
}

iot_agent_status_t write_cert_to_keystore(iot_agent_keystore_t* keystore,
		const nxp_iot_ServiceDescriptor* service_descriptor, uint32_t cert_id)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	sss_status_t sss_status = kStatus_SSS_Success;
	sss_object_t service_cert = { 0 };

	pex_sss_demo_tls_ctx->client_cert_index = cert_id;

    sss_status = sss_key_object_init(&service_cert, keystore->sss_context);
    SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_init for keyPair failed with 0x%08x", sss_status)

    size_t cert_size = service_descriptor->client_certificate->size;
    const uint8_t *cert_data = service_descriptor->client_certificate->bytes;

    sss_status = sss_key_object_get_handle(&service_cert, cert_id);
    if (sss_status != kStatus_SSS_Success)
    {
    	sss_status = sss_key_object_allocate_handle(&service_cert, cert_id,
        		kSSS_KeyPart_Default, kSSS_CipherType_Binary, cert_size, kKeyObject_Mode_Persistent);
    	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_allocate_handle failed with 0x%08x.", sss_status);
    }
    else
    {
    	sss_status = sss_key_store_erase_key(keystore->sss_context, &service_cert);
    	SSS_SUCCESS_OR_EXIT_MSG("sss_key_store_erase_key failed with 0x%08x.", sss_status);
    }

    sss_status = sss_key_store_set_key(keystore->sss_context, &service_cert, cert_data, cert_size,
    		cert_size * 8, NULL, 0);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_store_set_key failed with 0x%08x.", sss_status);
exit:
	return agent_status;
}

iot_agent_status_t associateKeyPair(mbedtls_pk_context *pk, sss_object_t* service_private_key,
        iot_agent_keystore_t* keystore, uint32_t key_id)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	sss_status_t sss_status = kStatus_SSS_Success;
	int ret;

    pex_sss_demo_tls_ctx->client_keyPair_index = key_id;

    sss_status = sss_key_object_init(service_private_key, keystore->sss_context);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_init failed with 0x%08x.", sss_status);

    sss_status = sss_key_object_get_handle(service_private_key, key_id);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_get_handle failed with 0x%08x.", sss_status);

    ret = sss_mbedtls_associate_keypair(pk, service_private_key);
    ASSERT_OR_EXIT_MSG(ret == 0, "sss_mbedtls_associate_keypair failed with 0x%08x.", ret)

exit:
    return agent_status;
}	

#define AWS_MQTT_TOPIC "sdk/test/cpp"
#define MQTT_DATA  "Hello from FreeRTOS";

static const int PUBLISH_ATTEMPTS = 4;

iot_agent_status_t awsPubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    BaseType_t mqtt_result = pdPASS;
    int retryCount = 1;
	uint32_t publishCount = PUBLISH_ATTEMPTS;

    MQTTAgentConnectParams_t xConnectParameters = {
        .pcURL = service_descriptor->hostname,
        .xFlags = mqttagentREQUIRE_TLS,
        .xURLIsIPAddress = pdFALSE,
        .usPort = service_descriptor->port,
        .pucClientId = (const uint8_t*) service_descriptor->client_id,
        .usClientIdLength = strlen(service_descriptor->client_id),
        .xSecuredConnection = pdFALSE,
        .pvUserData = NULL,
        .pxCallback = NULL,
		.pcCertificate = (char *)tlsCombi_ROOT_CERTIFICATE_PEM,
		.ulCertificateSize = tlsCombi_ROOT_CERTIFICATE_LENGTH,
        .cUserName = NULL,
        .uUsernamelength = 0,
        .p_password = NULL,
        .passwordlength = 0,
    };

    MQTTAgentHandle_t xMQTTHandle = NULL;
    MQTTAgentReturnCode_t xReturned;
    MQTTAgentPublishParams_t xPublishParameters_QOS0;
    bool connected = false;


    mqtt_result = MQTT_AGENT_Init();
    ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "MQTT_AGENT_Init failed with 0x%08lx.", mqtt_result);

    mqtt_result = SOCKETS_Init();
    ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "SOCKETS_Init failed with 0x%08lx.", mqtt_result);

    xReturned = MQTT_AGENT_Create(&xMQTTHandle);
    ASSERT_OR_EXIT_MSG(eMQTTAgentSuccess == xReturned, "MQTT_AGENT_Create failed with 0x%08x.", xReturned);

	while (! connected && retryCount <= 5) {
		IOT_AGENT_INFO("Attempt %d for connecting to AWS service '%s'...", retryCount, xConnectParameters.pucClientId);
		xReturned = MQTT_AGENT_Connect(xMQTTHandle, &xConnectParameters, (mqttconfigKEEP_ALIVE_ACTUAL_INTERVAL_TICKS * (1 + 2*retryCount)));
		connected = (xReturned == eMQTTAgentSuccess);
		retryCount ++;
	}
	ASSERT_OR_EXIT_MSG(connected, "Connect failed: Exiting");

	TickType_t timeout = pdMS_TO_TICKS(service_descriptor->timeout_ms);
	memset(&(xPublishParameters_QOS0), 0x00, sizeof(xPublishParameters_QOS0));
	xPublishParameters_QOS0.pucTopic = (const uint8_t *) AWS_MQTT_TOPIC;
	xPublishParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pucTopic);
	xPublishParameters_QOS0.pvData = MQTT_DATA;
	xPublishParameters_QOS0.ulDataLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pvData);
	xPublishParameters_QOS0.xQoS = eMQTTQoS0;

	int publishFails = 0;
	while (publishCount > 0)
	{
		vTaskDelay(pdMS_TO_TICKS(1000));
		xReturned = MQTT_AGENT_Publish(xMQTTHandle, &xPublishParameters_QOS0, timeout);

		if (xReturned == eMQTTAgentSuccess) {
			IOT_AGENT_INFO("Echo successfully published");
		}
		else {
			IOT_AGENT_INFO("ERROR: Echo failed to publish");
			publishFails++;
		}

		publishCount--;
	}
	ASSERT_OR_EXIT_MSG(publishFails < (PUBLISH_ATTEMPTS / 2),
			"More than or equal to %d publish attempts failed (%d).", (PUBLISH_ATTEMPTS / 2), publishFails);

exit:
	if (connected) {
	    MQTT_AGENT_Disconnect(xMQTTHandle, pdMS_TO_TICKS(2000));
	    connected = false;
	}
	if (xMQTTHandle != NULL) {
		MQTT_AGENT_Delete(xMQTTHandle);
		xMQTTHandle = NULL;
	}
    return agent_status;
}

#define WATSON_PUB_TOPIC "iot-2/evt/status/fmt/string"

#define CUSTOM_MQTT_USER_NAME "use-token-auth"
#define WATSON_ECHO_CLIENT_ID "dummy" //For IBM watson ClientID is optional (IBM verifies client from Device certificate)
#define WATSON_IOT_CLIENT_ID ((const uint8_t *)WATSON_ECHO_CLIENT_ID)

static const char tlsVERISIGN_ROOT_CERT_WATSON_PEM[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh\r\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\r\n"
"QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT\r\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg\r\n"
"U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n"
"ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83\r\n"
"nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd\r\n"
"KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f\r\n"
"/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX\r\n"
"kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0\r\n"
"/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C\r\n"
"AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY\r\n"
"aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6\r\n"
"Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1\r\n"
"oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD\r\n"
"QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\r\n"
"d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh\r\n"
"xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB\r\n"
"CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl\r\n"
"5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA\r\n"
"8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC\r\n"
"2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit\r\n"
"c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0\r\n"
"j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz\r\n"
"-----END CERTIFICATE-----\r\n";
static const uint32_t tlsVERISIGN_ROOT_CERT_WATSON_LENGTH = sizeof(tlsVERISIGN_ROOT_CERT_WATSON_PEM);

iot_agent_status_t customPubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	BaseType_t mqtt_result = pdPASS;
	int retryCount = 1;
	uint32_t publishCount = PUBLISH_ATTEMPTS;

    MQTTAgentConnectParams_t xConnectParameters = {
        .pcURL = service_descriptor->hostname,
        .xFlags = mqttagentREQUIRE_TLS,
        .xURLIsIPAddress = pdFALSE,
        .usPort = service_descriptor->port,
        .pucClientId =
            WATSON_IOT_CLIENT_ID,
        .usClientIdLength = (uint16_t)strlen((const char *)WATSON_IOT_CLIENT_ID),
        .xSecuredConnection = pdFALSE,
        .pvUserData = NULL,
        .pxCallback = NULL,
        .pcCertificate = (char *)tlsVERISIGN_ROOT_CERT_WATSON_PEM,
        .ulCertificateSize = tlsVERISIGN_ROOT_CERT_WATSON_LENGTH,
        .cUserName = CUSTOM_MQTT_USER_NAME,
        .uUsernamelength = 0,
        .p_password = NULL,
        .passwordlength = 0,
    };

	MQTTAgentHandle_t xMQTTHandle = NULL;
	MQTTAgentReturnCode_t xReturned;
	MQTTAgentPublishParams_t xPublishParameters_QOS0;
	bool connected = false;


	mqtt_result = MQTT_AGENT_Init();
	ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "MQTT_AGENT_Init failed with 0x%08lx.", mqtt_result);

	mqtt_result = SOCKETS_Init();
	ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "SOCKETS_Init failed with 0x%08lx.", mqtt_result);

	xReturned = MQTT_AGENT_Create(&xMQTTHandle);
	ASSERT_OR_EXIT_MSG(eMQTTAgentSuccess == xReturned, "MQTT_AGENT_Create failed with 0x%08x.", xReturned);

	while (!connected && retryCount <= 5) {
		IOT_AGENT_INFO("Attempt %d for connecting to Custom service '%s'...", retryCount, service_descriptor->hostname);
		xReturned = MQTT_AGENT_Connect(xMQTTHandle, &xConnectParameters, (mqttconfigKEEP_ALIVE_ACTUAL_INTERVAL_TICKS * (1 + 2 * retryCount)));
		connected = (xReturned == eMQTTAgentSuccess);
		retryCount++;
	}
	ASSERT_OR_EXIT_MSG(connected, "Connect failed: Exiting");

	TickType_t timeout = pdMS_TO_TICKS(service_descriptor->timeout_ms);
	memset(&(xPublishParameters_QOS0), 0x00, sizeof(xPublishParameters_QOS0));
	xPublishParameters_QOS0.pucTopic = (const uint8_t *)WATSON_PUB_TOPIC;
	xPublishParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pucTopic);
	xPublishParameters_QOS0.pvData = MQTT_DATA;
	xPublishParameters_QOS0.ulDataLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pvData);
	xPublishParameters_QOS0.xQoS = eMQTTQoS0;

	int publishFails = 0;
	while (publishCount > 0)
	{
		vTaskDelay(pdMS_TO_TICKS(1000));
		xReturned = MQTT_AGENT_Publish(xMQTTHandle, &xPublishParameters_QOS0, timeout);

		if (xReturned == eMQTTAgentSuccess) {
			IOT_AGENT_INFO("Echo successfully published");
		}
		else {
			IOT_AGENT_INFO("ERROR: Echo failed to publish");
			publishFails++;
		}

		publishCount--;
	}
	ASSERT_OR_EXIT_MSG(publishFails < (PUBLISH_ATTEMPTS / 2),
		"More than or equal to %d publish attempts failed (%d).", (PUBLISH_ATTEMPTS / 2), publishFails);

exit:
	if (connected) {
		MQTT_AGENT_Disconnect(xMQTTHandle, pdMS_TO_TICKS(2000));
		connected = false;
	}
	if (xMQTTHandle != NULL) {
		MQTT_AGENT_Delete(xMQTTHandle);
		xMQTTHandle = NULL;
	}
	return agent_status;
}


static const char AZURE_SERVER_ROOT_CERTIFICATE_PEM[] =
    /* DigiCert Baltimore Root */
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\r\n"
"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\r\n"
"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\r\n"
"DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\r\n"
"ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\r\n"
"VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\r\n"
"mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\r\n"
"IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\r\n"
"mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\r\n"
"XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\r\n"
"dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\r\n"
"jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\r\n"
"BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\r\n"
"DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\r\n"
"9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\r\n"
"jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\r\n"
"Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\r\n"
"ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\r\n"
"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
"-----END CERTIFICATE-----\r\n"
/*DigiCert Global Root CA*/
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\r\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\r\n"
"QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\r\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n"
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\r\n"
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\r\n"
"CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\r\n"
"nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\r\n"
"43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\r\n"
"T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\r\n"
"gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\r\n"
"BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\r\n"
"TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\r\n"
"DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\r\n"
"hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\r\n"
"06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\r\n"
"PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\r\n"
"YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\r\n"
"CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\r\n"
"-----END CERTIFICATE-----\r\n";

static const uint32_t AZURE_SERVER_ROOT_CERTIFICATE_PEM_LENGTH = sizeof(AZURE_SERVER_ROOT_CERTIFICATE_PEM);

#define AZURE_MQTT_REGISTER_HOSTNAME      "global.azure-devices-provisioning.net"
#define AZURE_MQTT_REGISTER_PORT          8883
#define AZURE_MQTT_REGISTRATION_MSG_TOPIC "$dps/registrations/PUT/iotdps-register/?$rid=1"
#define AZURE_MQTT_PUBLISH_MSG_OPID_AZURE "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="
#define AZURE_MQTT_SUBSCRIBE_MSG_TOPIC    "$dps/registrations/res/#"

typedef struct azure_registration_info_t
{
	char assignedHub[256];
	char deviceId[256];
	char registrationId[256];
	char operationId[256];
	char username[256];
	registration_state state;
} azure_registration_info_t;

typedef struct azure_connection_info
{
	char hostname[256];
	char topic[256];
	char username[256];
} azure_connection_info_t;

static iot_agent_status_t get_value_from_tag(char *js, const char * key, char * value)
{
	const size_t TOKEN_NO = 50;
	jsmn_parser p;
	jsmntok_t tokens[TOKEN_NO]; /* We expect no more than 10 JSON tokens */
	jsmn_init(&p);
	int count = jsmn_parse(&p, js, strlen(js), tokens, TOKEN_NO);
	for (int i = 1; i < count; i += 2)
	{
		jsmntok_t *t = &tokens[i];
		char *tag = js + t->start;
		if (!memcmp(tag, key, t->end - t->start))
		{
			t = &tokens[i + 1];
			memcpy(value, js + t->start, t->end - t->start);
			value[t->end - t->start] = '\0';
			return IOT_AGENT_SUCCESS;
		}
	}
	return IOT_AGENT_FAILURE;
}

static BaseType_t azureRegistrationCallback(void *pvUserData, const MQTTAgentCallbackParams_t *const pxCallbackParams)
{
	if(pxCallbackParams->xMQTTEvent == eMQTTAgentPublish)
	{
		IOT_AGENT_INFO("Publish message received on topic");

		char opid[256];
		char status[64];
		char* payload = pvPortMalloc(pxCallbackParams->u.xPublishData.ulDataLength + 1);

		memcpy(payload, pxCallbackParams->u.xPublishData.pvData, pxCallbackParams->u.xPublishData.ulDataLength);
		payload[pxCallbackParams->u.xPublishData.ulDataLength] = '\0';

		get_value_from_tag(payload, "operationId", opid);
		get_value_from_tag(payload, "status", status);

		azure_registration_info_t* reg_info = (azure_registration_info_t*) pvUserData;

		if(strcmp(status, "assigning") == 0)
		{
			IOT_AGENT_INFO("Device State is now ASSIGNING");
			strcpy(reg_info->operationId, AZURE_MQTT_PUBLISH_MSG_OPID_AZURE);
			strcat(reg_info->operationId, opid);

			reg_info->state = ASSIGNING;
		}
		else if(strcmp(status, "assigned") == 0)
		{
			IOT_AGENT_INFO("Device State is now ASSIGNED");

			get_value_from_tag(payload, "registrationId", reg_info->registrationId);
			get_value_from_tag(payload, "assignedHub", reg_info->assignedHub);
			get_value_from_tag(payload, "deviceId", reg_info->deviceId);

			reg_info->state = ASSIGNED;
		}

		vPortFree(payload);
	}
	else if(pxCallbackParams->xMQTTEvent == eMQTTAgentDisconnect)
	{
		IOT_AGENT_INFO("Disconnect message received");
	}
	else
	{
		IOT_AGENT_INFO("Unknown message received\r\n");
	}

	vPortFree(pxCallbackParams->u.xPublishData.xBuffer);
	return pdPASS;
}


static iot_agent_status_t formatRegistrationUsername(azure_registration_info_t* reg_info, const char* idscope, const char* deviceid)
{
	size_t n = snprintf(reg_info->username,
		sizeof(reg_info->username),
		"%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0",
		idscope,
		deviceid);

	if(n > sizeof(reg_info->username))
	{
		return IOT_AGENT_FAILURE;
	}

	return IOT_AGENT_SUCCESS;
}

bool formatConnectionOptions(azure_connection_info_t* conn_info, char* hubname, char* deviceid)
{
	size_t m = snprintf(conn_info->username,
		sizeof(conn_info->username),
		"%s/%s/?api-version=2018-06-30",
		hubname,
		deviceid);
	size_t n = snprintf(conn_info->topic,
		sizeof(conn_info->topic),
		"devices/%s/messages/events/",
		deviceid);

	if (n > sizeof(conn_info->topic) || m > sizeof(conn_info->username))
	{
		return IOT_AGENT_FAILURE;
	}
	return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t azureRegister(const nxp_iot_ServiceDescriptor* service_descriptor, azure_registration_info_t* reg_info)
{
    BaseType_t xResult;
    int retryCount = 0;
    int maxWaiting = 0;
    iot_agent_status_t status = IOT_AGENT_FAILURE;
	MQTTAgentHandle_t xMQTTHandle = NULL;

    formatRegistrationUsername(reg_info, service_descriptor->azure_id_scope, service_descriptor->azure_registration_id);

    MQTTAgentConnectParams_t xConnectParameters = {
        .pcURL = AZURE_MQTT_REGISTER_HOSTNAME,
        .xFlags = mqttagentREQUIRE_TLS,
        .xURLIsIPAddress = pdFALSE,
        .usPort = AZURE_MQTT_REGISTER_PORT,
        .pucClientId = (const uint8_t*) service_descriptor->azure_registration_id,
        .usClientIdLength = strlen((const char*) service_descriptor->azure_registration_id),
        .xSecuredConnection = pdFALSE,
        .pvUserData = (void* )reg_info,
        .pxCallback = azureRegistrationCallback,
		.pcCertificate = (char *)AZURE_SERVER_ROOT_CERTIFICATE_PEM,
		.ulCertificateSize = AZURE_SERVER_ROOT_CERTIFICATE_PEM_LENGTH,
        .cUserName = reg_info->username,
        .uUsernamelength = strlen((const char*) reg_info->username),
        .p_password = NULL,
        .passwordlength = 0,
    };

    MQTTAgentReturnCode_t xReturned;
    MQTTAgentPublishParams_t xPublishParameters_QOS0;
    MQTTAgentSubscribeParams_t xSubscribeParameters_QOS0;

    xResult = MQTT_AGENT_Init();
    if (xResult == pdPASS) {
            xResult = SOCKETS_Init();
    }

    xReturned = MQTT_AGENT_Create(&xMQTTHandle);

	if (xReturned == eMQTTAgentSuccess)
	{
		do
		{
			IOT_AGENT_INFO("\nMQTT attempting to register Azure Service '%s'...", xConnectParameters.pucClientId);

			xReturned = MQTT_AGENT_Connect(xMQTTHandle, &xConnectParameters, (mqttconfigKEEP_ALIVE_ACTUAL_INTERVAL_TICKS * (1 + 2*retryCount)));
			if (xReturned == eMQTTAgentSuccess)
			{
				break;
			}
			else
			{
				IOT_AGENT_ERROR("Connect failed: Retrying \r\n");
				retryCount ++;
			}
		} while (retryCount <= 5);

		if (xReturned != eMQTTAgentSuccess)
		{
			IOT_AGENT_ERROR(("Connect failed: Exiting\r\n"));
			goto exit;
		}

	}

	IOT_AGENT_INFO("MQTT connection successful");

	TickType_t timeout = pdMS_TO_TICKS(20000);

	memset(&(xSubscribeParameters_QOS0), 0x00, sizeof(xSubscribeParameters_QOS0));
	xSubscribeParameters_QOS0.pucTopic = (const uint8_t *) AZURE_MQTT_SUBSCRIBE_MSG_TOPIC;
	xSubscribeParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xSubscribeParameters_QOS0.pucTopic);
	xSubscribeParameters_QOS0.xQoS = eMQTTQoS0;

	xReturned = MQTT_AGENT_Subscribe(xMQTTHandle, &xSubscribeParameters_QOS0, timeout);
	if (xReturned != eMQTTAgentSuccess)
	{
		IOT_AGENT_ERROR(("MQTT_AGENT_Subscribe failed: Exiting\r\n"));
		goto disconnect;
	}

    memset(&(xPublishParameters_QOS0), 0x00, sizeof(xPublishParameters_QOS0));
    xPublishParameters_QOS0.pucTopic = (const uint8_t *) AZURE_MQTT_REGISTRATION_MSG_TOPIC;
    xPublishParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pucTopic);
    xPublishParameters_QOS0.xQoS = eMQTTQoS0;

    reg_info->state = NOT_ASSIGNED;

    xReturned = MQTT_AGENT_Publish(xMQTTHandle, &xPublishParameters_QOS0, timeout);
	if (xReturned != eMQTTAgentSuccess)
	{
		IOT_AGENT_ERROR(("MQTT_AGENT_Publish failed: Exiting\r\n"));
		goto disconnect;
	}

    while (reg_info->state != ASSIGNING && maxWaiting < 20)
    {
    	 vTaskDelay(pdMS_TO_TICKS(5000));
    	 maxWaiting++;
	}

    memset(&(xPublishParameters_QOS0), 0x00, sizeof(xPublishParameters_QOS0));
    xPublishParameters_QOS0.pucTopic = (const uint8_t *) reg_info->operationId;
    xPublishParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pucTopic);
    xPublishParameters_QOS0.xQoS = eMQTTQoS0;

    while (reg_info->state != ASSIGNED && maxWaiting < 20)
    {
    	vTaskDelay(pdMS_TO_TICKS(5000));

		xReturned = MQTT_AGENT_Publish(xMQTTHandle, &xPublishParameters_QOS0, pdMS_TO_TICKS(20000));
		if (xReturned != eMQTTAgentSuccess)
		{
			IOT_AGENT_ERROR(("MQTT_AGENT_Publish failed\r\n"));
			goto disconnect;
		}
    	 maxWaiting++;
	}

    if(reg_info->state == ASSIGNED)
    {
    	status = IOT_AGENT_SUCCESS;
    }

    IOT_AGENT_INFO("Disconnect MQTT connection...");

disconnect:
	MQTT_AGENT_Disconnect(xMQTTHandle, pdMS_TO_TICKS(2000));

exit:
	MQTT_AGENT_Delete(xMQTTHandle);

	return status;

}

static iot_agent_status_t azurePubSub(const nxp_iot_ServiceDescriptor* service_descriptor, azure_registration_info_t* reg_info)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	BaseType_t mqtt_result = pdPASS;
	int retryCount = 1;
	uint32_t publishCount = PUBLISH_ATTEMPTS;

    azure_connection_info_t conn_info;

    formatConnectionOptions(&conn_info, reg_info->assignedHub, reg_info->deviceId);

    MQTTAgentConnectParams_t xConnectParameters = {
        .pcURL = reg_info->assignedHub,
        .xFlags = mqttagentREQUIRE_TLS,
        .xURLIsIPAddress = pdFALSE,
        .usPort = AZURE_MQTT_REGISTER_PORT,
        .pucClientId = (const uint8_t*) reg_info->deviceId,
        .usClientIdLength = strlen((const char *) reg_info->deviceId),
        .xSecuredConnection = pdFALSE,
        .pvUserData = NULL,
        .pxCallback = NULL,
		.pcCertificate = (char *)AZURE_SERVER_ROOT_CERTIFICATE_PEM,
		.ulCertificateSize = AZURE_SERVER_ROOT_CERTIFICATE_PEM_LENGTH,
        .cUserName = conn_info.username,
        .uUsernamelength = strlen((const char*) conn_info.username),
        .p_password = NULL,
        .passwordlength = 0,
    };

	MQTTAgentHandle_t xMQTTHandle = NULL;
	MQTTAgentReturnCode_t xReturned;
	MQTTAgentPublishParams_t xPublishParameters_QOS0;
	bool connected = false;

	mqtt_result = MQTT_AGENT_Init();
	ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "MQTT_AGENT_Init failed with 0x%08lx.", mqtt_result);

	mqtt_result = SOCKETS_Init();
	ASSERT_OR_EXIT_MSG(pdPASS == mqtt_result, "SOCKETS_Init failed with 0x%08lx.", mqtt_result);

	xReturned = MQTT_AGENT_Create(&xMQTTHandle);
	ASSERT_OR_EXIT_MSG(eMQTTAgentSuccess == xReturned, "MQTT_AGENT_Create failed with 0x%08x.", xReturned);

	while (!connected && retryCount <= 5) {
		IOT_AGENT_INFO("Attempt %d for connecting to Azure service '%s'...", retryCount, xConnectParameters.pucClientId);
		xReturned = MQTT_AGENT_Connect(xMQTTHandle, &xConnectParameters, (mqttconfigKEEP_ALIVE_ACTUAL_INTERVAL_TICKS * (1 + 2 * retryCount)));
		connected = (xReturned == eMQTTAgentSuccess);
		retryCount++;
	}
	ASSERT_OR_EXIT_MSG(connected, "Connect failed: Exiting");

	TickType_t timeout = pdMS_TO_TICKS(service_descriptor->timeout_ms);
	memset(&(xPublishParameters_QOS0), 0x00, sizeof(xPublishParameters_QOS0));
	xPublishParameters_QOS0.pucTopic = (const uint8_t *)conn_info.topic;
	xPublishParameters_QOS0.usTopicLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pucTopic);
	xPublishParameters_QOS0.pvData = MQTT_DATA;
	xPublishParameters_QOS0.ulDataLength = (uint16_t)strlen((const char *)xPublishParameters_QOS0.pvData);
	xPublishParameters_QOS0.xQoS = eMQTTQoS0;

	int publishFails = 0;
    while (publishCount > 0)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
        xReturned = MQTT_AGENT_Publish(xMQTTHandle, &xPublishParameters_QOS0, timeout);

        if (xReturned == eMQTTAgentSuccess) {
            IOT_AGENT_INFO("Echo successfully published");
        }
        else {
            IOT_AGENT_INFO("ERROR: Echo failed to publish\r\n");
			publishFails++;
        }
		publishCount--;
	}
	ASSERT_OR_EXIT_MSG(publishFails < (PUBLISH_ATTEMPTS / 2),
		"More than or equal to %d publish attempts failed (%d).", (PUBLISH_ATTEMPTS / 2), publishFails);

exit:
	if (connected) {
		MQTT_AGENT_Disconnect(xMQTTHandle, pdMS_TO_TICKS(2000));
		connected = false;
	}
	if (xMQTTHandle != NULL) {
		MQTT_AGENT_Delete(xMQTTHandle);
		xMQTTHandle = NULL;
	}
	return agent_status;
}

iot_agent_status_t azurePubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor)
{
	azure_registration_info_t reg_info = { 0 };
	iot_agent_status_t status;
	status = azureRegister(service_descriptor, &reg_info);
	if(status != IOT_AGENT_SUCCESS)
	{
		return status;
	}

	status = azurePubSub(service_descriptor, &reg_info);
	if(status != IOT_AGENT_SUCCESS)
	{
		return status;
	}

	return IOT_AGENT_SUCCESS;
}


