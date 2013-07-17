cmake_minimum_required(VERSION 2.6.0)

if(NOT WIN32)
	if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang"))
		message(STATUS "==== ${CMAKE_C_COMPILER_ID} detected - Adding compiler flags ====")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
	endif()
endif()

if(WIN32)
	include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
endif()

set(core_sources
        core/DHT.c
        core/network.c
        core/Lossless_UDP.c
        core/net_crypto.c
        core/Messenger.c)

add_library(core ${core_sources})

macro(linkCoreLibraries exe_name)
	if(WIN32)
        	target_link_libraries(${exe_name} core
                	${CMAKE_SOURCE_DIR}/sodium/lib/libsodium.a
			ws2_32)
	else()
        	target_link_libraries(${exe_name} core
			sodium)
	endif()
endmacro()

cmake_policy(SET CMP0011 NEW)

ADD_SUBDIRECTORY(testing)
ADD_SUBDIRECTORY(other)