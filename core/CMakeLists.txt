cmake_minimum_required(VERSION 2.6.0)
project(toxcore C)

set(core_sources
	DHT.c
	network.c
	Lossless_UDP.c
	net_crypto.c
	friend_requests.c
	LAN_discovery.c
	Messenger.c
	util.c
	ping.c)

if(SHARED_TOXCORE)
	add_library(toxcore SHARED ${core_sources})
else()
	add_library(toxcore ${core_sources})
endif()

target_link_libraries(toxcore ${LINK_CRYPTO_LIBRARY})

if(WIN32)
	target_link_libraries(toxcore ws2_32)
endif()
