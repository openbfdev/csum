# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
#

cmake_minimum_required(VERSION 3.9)
project(csum VERSION "1.0" LANGUAGES C)

add_definitions(
    " -std=gnu17"
    " -Wall"
    " -Wextra"
    " -Wno-override-init"
    " -Wno-unused-parameter"
    " -Wno-sign-compare"
    " -Wno-pointer-sign"
    " -Wno-null-pointer-arithmetic"
)

FILE(GLOB_RECURSE SRC_HEADER "include/*.h")
FILE(GLOB_RECURSE SRC_SOURCE "src/*.c")
include_directories(${PROJECT_SOURCE_DIR}/include)
add_executable(${PROJECT_NAME} ${SRC_HEADER} ${SRC_SOURCE})

add_subdirectory(bfdev)
include_directories(${PROJECT_SOURCE_DIR}/bfdev/include)
include_directories(${PROJECT_BINARY_DIR}/bfdev/generated)
target_link_libraries(${PROJECT_NAME} bfdev)
