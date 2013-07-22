cmake_minimum_required(VERSION 2.6.0)
project(core C)

if(WIN32)
	include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
endif()

set(core_sources
        DHT.c
        network.c
        Lossless_UDP.c
        net_crypto.c
        friend_requests.c
        Messenger.c)

add_library(core ${core_sources})
