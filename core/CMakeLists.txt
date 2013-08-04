cmake_minimum_required(VERSION 2.6.0)
project(core C)

if(WIN32)
	include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
else(WIN32)
	include_directories(${SODIUM_INCLUDE_DIR})
endif()

set(core_sources
	DHT.c
	network.c
        lossless_UDP.c
	net_crypto.c
	friend_requests.c
	LAN_discovery.c
        state.c
        friends.c
        friends_internal.h
        connection.c
        messenger.c
        messenger_internal.h)

add_library(core ${core_sources})
