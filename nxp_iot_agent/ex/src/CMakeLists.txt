# Copyright 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# TODO: Get rid of -Wno-format -Wno-format-security

IF(CMAKE_COMPILER_IS_GNUCC)
  ADD_DEFINITIONS("-Wno-unused-function -Wno-format -Wno-format-security")
ENDIF()


###################### nxp_iot_agent_demo

PROJECT(nxp_iot_agent_demo)

INCLUDE_DIRECTORIES(../inc/)
IF(WithHost_Win10IoT OR WithHost_PCWindows)
    INCLUDE_DIRECTORIES(../../ext/)
ENDIF()

IF(WithHost_Win10IoT)

SET(HEADER_FILES
    ../../ext/dirent_win32.h
    ../inc/iot_agent_config.h
    ../inc/iot_agent_claimcode_inject.h
    )

SET(SOURCE_FILES
    iot_agent_demo.c
    )

SET(ASSET_FILES
    ${PROJECT_NAME}_uwp/SmallLogo.png
    ${PROJECT_NAME}_uwp/SmallLogo44x44.png
    ${PROJECT_NAME}_uwp/SplashScreen.png
    ${PROJECT_NAME}_uwp/StoreLogo.png
    ${PROJECT_NAME}_uwp/Logo.png
    )

SET(CONTENT_FILES
    ${PROJECT_NAME}_uwp/package.appxManifest
    )

SET(RESOURCE_FILES
  ${CONTENT_FILES} ${ASSET_FILES}
  ${PROJECT_NAME}_uwp/Windows_TemporaryKey.pfx)

SET_PROPERTY(SOURCE ${CONTENT_FILES} PROPERTY VS_DEPLOYMENT_CONTENT 1)
SET_PROPERTY(SOURCE ${ASSET_FILES} PROPERTY VS_DEPLOYMENT_CONTENT 1)
SET_PROPERTY(SOURCE ${ASSET_FILES} PROPERTY VS_DEPLOYMENT_LOCATION "Assets")

SOURCE_GROUP("Source Files" FILES ${SOURCE_FILES})
SOURCE_GROUP("Header Files" FILES ${HEADER_FILES})
SOURCE_GROUP("Resource Files" FILES ${RESOURCE_FILES})

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} WIN32
    ${SOURCE_FILES}
    ${HEADER_FILES}
    ${RESOURCE_FILES}
)

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS /SUBSYSTEM:CONSOLE)

ELSE()
FILE(
    GLOB
    iot_agent_demo_files
    ../inc/iot_agent_config.h
    utils/iot_agent_claimcode_inject.c
    iot_agent_demo.c
)

IF(WithHostCrypto_OPENSSL)
SET(HEADER_FILES
    ../inc/iot_agent_mqtt_paho.h
    )
    LIST(
        APPEND
        iot_agent_demo_files
        utils/iot_agent_mqtt_paho.c
        ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/jsmn/jsmn.c
    )
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent
        PUBLIC
        ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/jsmn
    )
ENDIF()

IF(WithHost_frdmk64f OR WithHost_evkmimxrt1060)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_lwip.c
        utils/iot_agent_mqtt_freertos.c
    )
ENDIF()

IF(WithHost_lpcxpresso55s)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_qca.c
        utils/iot_agent_mqtt_freertos.c
    )
ENDIF()

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE}
    ${iot_agent_demo_files}
    ${iot_agent_demo_port_files}
)
ENDIF()

IF(BUILD_SHARED_LIBS)
    IF(WithHostCrypto_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs
        )
    ENDIF()
ELSE()
    IF(WithHostCrypto_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs-static
        )
    ENDIF()
ENDIF()


TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent
)

CREATE_BINARY(${PROJECT_NAME})

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### claimcode_inject

IF(WithHostCrypto_OPENSSL AND WithApplet_SE05X)
    PROJECT(claimcode_inject)

SET(HEADER_FILES
    ../inc/iot_agent_claimcode_inject.h
    )

ADD_EXECUTABLE(${PROJECT_NAME}
     utils/iot_agent_claimcode_inject.c
     apps/claimcode_inject_demo.c
   )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        nxp_iot_agent
        SSS_APIs
    )
    CREATE_BINARY(${PROJECT_NAME})
ENDIF()

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### remote_provisioning_client

IF(WithApplet_SE05X)
    PROJECT(remote_provisioning_client)

   ADD_EXECUTABLE(${PROJECT_NAME}
        apps/remote_provisioning_client.c
    )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        SSS_APIs
        rtp_client
        nxp_iot_agent
    )

    CREATE_BINARY(${PROJECT_NAME})
ENDIF()


###################### remote_provisioning_client_lib

IF(WithApplet_SE05X)
    PROJECT(rtp_client)

    IF(WithHost_PCLinux OR WithHost_iMXLinux)
        FIND_PACKAGE(Threads)
    ENDIF()

    IF(WithHost_frdmk64f)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_lwip.c
        )
    ENDIF()

    IF(WithHost_lpcxpresso55s)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_qca.c
        )
    ENDIF()

    IF(WithHost_evkmimxrt1060)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_lwip.c
        )
    ENDIF()

    SET(HEADER_FILES
        ../inc/iot_agent_rtp_client.h
    )

   ADD_LIBRARY(rtp_client STATIC ${KSDK_STARTUP_FILE}
        utils/iot_agent_rtp_client.c
        ${iot_agent_demo_port_files}
    )

    IF (WIN32)
        SET(LIBS_SYSTEM ws2_32)
    ENDIF()

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        SSS_APIs
        nxp_iot_agent
        ${LIBS_SYSTEM}
    )

ENDIF()

# all other projects are internal development/debugging and testing tools
IF(NXPInternal)

###################### object_dump

    IF(WithApplet_SE050_C AND WithHostCrypto_OPENSSL)
        PROJECT(object_dump)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/object_dump.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            nxp_iot_agent
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()


###################### nxp_iot_agent_fill_datastore

    IF(WithApplet_SE05X AND (WithHost_PCWindows OR WithHost_PCLinux64 OR WithHost_iMXLinux))
        PROJECT(nxp_iot_agent_fill_datastore)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/iot_agent_fill_datastore.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            nxp_iot_agent
            SSS_APIs
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()

###################### nxp_iot_agent_e2e

    IF(WithHostCrypto_OPENSSL)
        PROJECT(nxp_iot_agent_e2e)

        IF(WithHost_Win10IoT OR WithHost_PCWindows)
            INCLUDE_DIRECTORIES(../../ext/)
        ENDIF()

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/iot_agent_e2e.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            nxp_iot_agent
        )

        EXPOSE_SE05X_AUTH_STRATEGY()
        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()



###################### remote_runner_server

    IF(NOT((WithHost_LinuxLike OR WithHost_PCWindows) AND WithHostCrypto_MBEDTLS))
        IF(WithApplet_SE050_A OR WithApplet_SE050_B OR WithApplet_SE050_C)
            PROJECT(remote_runner_server)

            IF(WithHostCrypto_OPENSSL)
                FILE(
                    GLOB
                    iot_agent_remote_runner_files
                    apps/remote_runner_server.c
                    utils/iot_agent_mqtt_paho.c
                    ${SIMW_TOP_DIR}/ext/amazon-freertos/libraries/3rdparty/jsmn/jsmn.c
                )
            ENDIF()

            IF(WithHost_PCLinux OR WithHost_iMXLinux)
                FIND_PACKAGE(Threads)
            ENDIF()

            IF(WithHost_frdmk64f OR WithHost_evkmimxrt1060)
                FILE(
                    GLOB
                    iot_agent_remote_runner_files
                    apps/remote_runner_server.c
                    network/iot_agent_network_lwip.c
                    utils/iot_agent_mqtt_freertos.c
                )
            ENDIF()

            IF(WithHost_lpcxpresso55s)
                FILE(
                    GLOB
                    iot_agent_remote_runner_files
                    apps/remote_runner_server.c
                    network/iot_agent_network_qca.c
                    utils/iot_agent_mqtt_freertos.c
                )
            ENDIF()

            ADD_EXECUTABLE(${PROJECT_NAME} 
                ${KSDK_STARTUP_FILE}
                ${iot_agent_remote_runner_files}
            )

            IF(BUILD_SHARED_LIBS)
                IF(WithHostCrypto_OPENSSL)
                    TARGET_LINK_LIBRARIES(
                        ${PROJECT_NAME}
                        paho-mqtt3cs
                    )
                ENDIF()
            ELSE()
                IF(WithHostCrypto_OPENSSL)
                    TARGET_LINK_LIBRARIES(
                        ${PROJECT_NAME}
                        paho-mqtt3cs-static
                    )
                ENDIF()
            ENDIF()

            IF (WIN32)
                SET(LIBS_SYSTEM ws2_32)
            ENDIF()

            TARGET_LINK_LIBRARIES(
                ${PROJECT_NAME}
                SSS_APIs
                rtp_client
                nxp_iot_agent
                ${LIBS_SYSTEM}
            )

            TARGET_COMPILE_DEFINITIONS(
                ${PROJECT_NAME}
                PRIVATE PB_FIELD_32BIT
            )

            CREATE_BINARY(${PROJECT_NAME})
        ENDIF()
    ENDIF()

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
ENDIF()

###################### apdu player with stdin/stdout interface

   IF(WithApplet_SE05X AND (WithHost_PCWindows OR WithHost_PCLinux64))
        PROJECT(apdu_player_stdin)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/apdu_player_stdin.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            ex_common
            smCom
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()


###################### apdu player with stdin/stdout interface, selected and authenticated to 
# card manager (note, only build with platform SCP enabled, as the SCP03 code is required for
# authentication to the card manager).

IF(WithApplet_SE05X AND SSS_HAVE_SE05X_Auth_PlatfSCP03 
        AND (WithHost_PCWindows OR WithHost_PCLinux64))

        PROJECT(apdu_player_stdin_card_manager)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/apdu_player_stdin_card_manager.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            ex_common
            smCom
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()


IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
ENDIF()


ENDIF() # NXPInternal


