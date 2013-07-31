cmake_minimum_required(VERSION 2.6.0)
project(DHT_bootstrap_daemon C)

set(exe_name DHT_bootstrap_daemon)

find_package(LIBCONFIG REQUIRED)

include_directories(${LIBCONFIG_INCLUDE_DIR})

add_executable(${exe_name}
	DHT_bootstrap_daemon.c)

target_link_libraries(${exe_name}
	${LIBCONFIG_LIBRARY})

linkCoreLibraries(${exe_name})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")
find_package(LibConfig REQUIRED)
