cmake_minimum_required(VERSION 2.6.0)

cmake_policy(SET CMP0011 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_bootstrap.cmake)

if(NOT WIN32)
	add_subdirectory(bootstrap_serverdaemon)
endif()
