#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(SEMS_LITE_AGENT_APIs LANGUAGES C)


FILE(
    GLOB
        API_FILES
        lib/inc/*.h
        lib/src/*.c
        lib/src/*.h
)

IF(WithHost_Android)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${API_FILES})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${API_FILES})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC lib/inc
    PUBLIC ../nxp_iot_agent/src
    PUBLIC ../nxp_iot_agent/inc
    PUBLIC ../nxp_iot_agent/src/protobuf/
    PUBLIC ../hostlib/hostlib/inc
    PUBLIC ../hostlib/hostlib/libCommon
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
    nxp_iot_agent_common
)

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(WithLargePrograms)
    IF(NOT WithApplet_AUTH)
        ADD_SUBDIRECTORY(ex)
    ENDIF()
ENDIF()

IF(WithRTOS_Default AND NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()



IF(WithHost_LinuxLike)
    INSTALL(
        DIRECTORY
            inc/
            port/default/
        DESTINATION ${SIMW_INSTALL_INC_DIR}
        FILES_MATCHING
        PATTERN "*.h"
    )
ENDIF()
