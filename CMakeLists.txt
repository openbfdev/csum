# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
#

cmake_minimum_required(VERSION 3.9)
project(csum VERSION "1.0" LANGUAGES C)

set(CMAKE_MODULE_PATH
    ${PROJECT_SOURCE_DIR}/cmake
)

configure_file(
    ${CMAKE_MODULE_PATH}/config.h.in
    ${PROJECT_BINARY_DIR}/include/config.h
)

FILE(GLOB_RECURSE SRC_HEADER "include/*.h")
FILE(GLOB_RECURSE SRC_SOURCE "src/*.c")
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR}/include)

add_executable(${PROJECT_NAME} ${SRC_HEADER} ${SRC_SOURCE})
target_link_libraries(${PROJECT_NAME} bfdev)

install(TARGETS
    ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
