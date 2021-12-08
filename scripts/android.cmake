# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

MACRO(CREATE_BINARY PROJECT_NAME)
    # Nothing here.
ENDMACRO()

MACRO(
    COPY_TO_SOURCEDIR
    PROJECT_NAME
    TARGET_DIRNAME
    TARGET_SUFFIX
)
    # Nothing here.
ENDMACRO()

IF(NXPInternal)
    ADD_DEFINITIONS(-Werror)
ENDIF()

ADD_DEFINITIONS("-Wno-main-return-type")
ADD_DEFINITIONS("-Wformat")
ADD_DEFINITIONS(-DFTR_FILE_SYSTEM)
