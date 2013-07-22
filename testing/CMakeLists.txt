cmake_minimum_required(VERSION 2.6.0)

cmake_policy(SET CMP0011 NEW)

#include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_cryptosendfiletest.cmake)
#include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_sendfiletest.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_test.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Lossless_UDP_testclient.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Lossless_UDP_testserver.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Messenger_test.cmake)
if(NOT WIN32)
	include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/nTox.cmake)
endif()
