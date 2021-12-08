#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

ADD_SUBDIRECTORY(sems_lite_ex_update)

IF(WithHost_LinuxLike OR WithHost_PCWindows OR WithHost_Darwin)
    ADD_SUBDIRECTORY(sems_lite_cli_app)
ENDIF()
