cmake_minimum_required(VERSION 2.6.0)
cmake_policy(SET CMP0011 NEW)

include_directories(${CHECK_INCLUDE_DIRS})

find_package(Check REQUIRED)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/messenger_test.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/friends_test.cmake)
