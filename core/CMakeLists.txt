cmake_minimum_required(VERSION 2.6.0)
project(toxcore C)

if(WIN32)
	include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
else(WIN32)
	include_directories(${SODIUM_INCLUDE_DIR})
endif()

set(core_sources
	DHT.c
	network.c
	Lossless_UDP.c
	net_crypto.c
	friend_requests.c
	LAN_discovery.c
	Messenger.c)

add_library(toxcore SHARED ${core_sources})
target_link_libraries(toxcore ${SODIUM_LIBRARY})

if(WIN32)
	target_link_libraries(toxcore ws2_32)
endif()
