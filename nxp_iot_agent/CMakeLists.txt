# Copyright 2019, 2020, 2021 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(nxp_iot_agent LANGUAGES C)

FILE(
    GLOB
	NXP_IOT_AGENT_FILES
	inc/*.h
	inc/*.h.in
	src/*.c
	src/protobuf/*.h
	src/protobuf/*.c
)

IF(WithApplet_A71CH)
    MESSAGE(FATAL_ERROR "A71CH is not supported anymore for nxp_iot_agent!!!")
ENDIF()

IF(WithHost_PCWindows)
    FILE(
	GLOB
	    NXP_IOT_AGENT_WINDOWS_FILES
	    platform/windows/*.h
	    platform/windows/*.h.in
	    platform/windows/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_WINDOWS_FILES})
ENDIF()


IF(WithHostCrypto_OPENSSL)
    FILE(
	GLOB
	    NXP_IOT_AGENT_OPENSSL_FILES
	    platform/openssl/*.h
	    platform/openssl/*.h.in
	    platform/openssl/*.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_OPENSSL_FILES})
ENDIF()

IF(WithHostCrypto_MBEDTLS)
    FILE(
	GLOB
	    NXP_IOT_AGENT_MBEDTLS_FILES
	    platform/mbedtls/network_mbedtls.h
	    platform/mbedtls/network_mbedtls.c
    )

    set(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_MBEDTLS_FILES})
ENDIF()

IF(WithHost_frdmk64f)
    FILE(
	GLOB
	NXP_IOT_AGENT_PORT_FILES
	platform/mbedtls/net_lwip.c
    )

	SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(WithHost_evkmimxrt1060)
    FILE(
	GLOB
	NXP_IOT_AGENT_PORT_FILES
	platform/mbedtls/net_lwip.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

IF(WithHost_lpcxpresso55s)
    FILE(
	GLOB
	NXP_IOT_AGENT_PORT_FILES
	platform/mbedtls/net_qca.c
    )

    SET(NXP_IOT_AGENT_FILES ${NXP_IOT_AGENT_FILES} ${NXP_IOT_AGENT_PORT_FILES})
ENDIF()

ADD_LIBRARY(nxp_iot_agent ${NXP_IOT_AGENT_FILES})

IF(
    CMAKE_CXX_COMPILER
    MATCHES
    ".*clang"
    OR CMAKE_CXX_COMPILER_ID
       STREQUAL
       "AppleClang"
)
    TARGET_COMPILE_OPTIONS(
	${PROJECT_NAME}
	PUBLIC -Wno-format
	PUBLIC -Wno-error=format)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    nxp_iot_agent
    PUBLIC inc
    PUBLIC platform
    PUBLIC src/protobuf
)

IF(WithKSDK)
    TARGET_INCLUDE_DIRECTORIES(
	nxp_iot_agent
	PUBLIC port/ksdk
    )
ELSE()
    TARGET_INCLUDE_DIRECTORIES(
	nxp_iot_agent
	PUBLIC port/default
    )
ENDIF()

IF(WithHostCrypto_MBEDTLS)
    TARGET_LINK_LIBRARIES(
	nxp_iot_agent
	mbedtls
    )
ENDIF()

IF(WithHost_PCWindows OR WithHost_Win10IoT)
    TARGET_INCLUDE_DIRECTORIES(
	nxp_iot_agent
	PUBLIC platform/windows
    )
ENDIF()


IF(WithHostCrypto_OPENSSL)
    TARGET_LINK_LIBRARIES(
	nxp_iot_agent
	${OPENSSL_LIBRARIES}
    )

    IF(WithHost_PCWindows)
	TARGET_LINK_LIBRARIES(
	    nxp_iot_agent
	    crypt32
	)
    ENDIF()

    TARGET_INCLUDE_DIRECTORIES(
	nxp_iot_agent
	PUBLIC platform/openssl
    )

    TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE OPENSSL_LOAD_CONF)

ENDIF()

IF(WithHostCrypto_MBEDTLS)
    TARGET_LINK_LIBRARIES(
	nxp_iot_agent
    )

    TARGET_INCLUDE_DIRECTORIES(
	nxp_iot_agent
	PUBLIC platform/mbedtls
    )

ENDIF()

IF(WithApplet_SE05X)
    TARGET_LINK_LIBRARIES(
	nxp_iot_agent
	se05x
    )
ENDIF()


TARGET_COMPILE_DEFINITIONS(nxp_iot_agent PRIVATE PB_FIELD_32BIT)

IF (WIN32)
    SET(LIBS_SYSTEM ws2_32)
ENDIF()

TARGET_LINK_LIBRARIES(
    nxp_iot_agent
    smCom
    ex_common
    SSS_APIs
    nxp_iot_agent_common
    ${LIBS_SYSTEM}
)

ADD_SUBDIRECTORY(ex)

IF(WithRTOS_Default AND NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()

IF(WithHost_PCLinux OR WithHost_iMXLinux)
    INSTALL(TARGETS nxp_iot_agent DESTINATION lib)
ENDIF()

IF("${CMAKE_CXX_COMPILER_ID}" MATCHES "MSVC")
    TARGET_COMPILE_OPTIONS(
	${PROJECT_NAME}
	PUBLIC
	    /wd4267 # '=': conversion from 'size_t' to 'int', possible loss of data
	PUBLIC
	    /wd4477 #  'printf' : format string '%d' requires an argument of type 'int', but variadic argument 1 has type 'size_t'
    )
    # 1900 matches VS2015
    IF(${MSVC_VERSION} LESS_EQUAL 1900)
	TARGET_COMPILE_OPTIONS(
	    ${PROJECT_NAME}
	    PUBLIC
		/wd4127 # conditional expression is constant
	)
    ENDIF()
ENDIF()

# TODO: Get rid of -Wno-format -Wno-format-security

IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  TARGET_COMPILE_OPTIONS(
    ${PROJECT_NAME}
    PRIVATE -Wno-error=format
    PRIVATE -Wno-format
    PRIVATE -Wno-error=format-security
    PRIVATE -Wno-format-security
    PRIVATE -Wno-address-of-packed-member
    PRIVATE -Wno-incompatible-pointer-types
    )
ENDIF()
