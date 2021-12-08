# Copyright 2019, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent_common LANGUAGES C)

FILE(
    GLOB
        NXP_IOT_AGENT_COMMON_FILES
        ../../inc/*.h
        ../../inc/*.h.in
        *.c
        ../../src/protobuf/*.h
        ../../src/protobuf/*.c
)

IF(WithHost_PCWindows)
    FILE(
        GLOB
            NXP_IOT_AGENT_WINDOWS_FILES
            ../../platform/windows/*.h
            ../../platform/windows/*.h.in
            ../../platform/windows/*.c
    )

    set(NXP_IOT_AGENT_COMMON_FILES ${NXP_IOT_AGENT_COMMON_FILES} ${NXP_IOT_AGENT_WINDOWS_FILES})
ENDIF()


ADD_LIBRARY(nxp_iot_agent_common ${NXP_IOT_AGENT_COMMON_FILES})

TARGET_COMPILE_DEFINITIONS(
    ${PROJECT_NAME}
    PUBLIC PB_FIELD_32BIT
)

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent_common
    PUBLIC ../../inc
    PUBLIC ../../platform
    PUBLIC ../../src/protobuf
    PUBLIC ../../../semslite/lib/inc
)

IF(WithKSDK)
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC port/ksdk
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC port/default
    )
ENDIF()

IF(WithHostCrypto_MBEDTLS)
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent_common
        mbedtls
    )
ENDIF()

IF(WithHost_PCWindows OR WithHost_Win10IoT)
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent_common
        PUBLIC ../../platform/windows
    )
ENDIF()


IF(WithApplet_SE05X)
    TARGET_LINK_LIBRARIES(
        nxp_iot_agent_common
        se05x
    )
ENDIF()


TARGET_COMPILE_DEFINITIONS(nxp_iot_agent_common PRIVATE PB_FIELD_32BIT)

TARGET_LINK_LIBRARIES(
    nxp_iot_agent_common
    smCom
    SSS_APIs
    ex_common
)


IF(WithHost_PCLinux OR WithHost_iMXLinux)
    INSTALL(TARGETS nxp_iot_agent_common DESTINATION lib)
ENDIF()
