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
	ping.c
        tox.c)

set(core_headers
	DHT.h
	network.h
	Lossless_UDP.h
	net_crypto.h
	friend_requests.h
	LAN_discovery.h
	Messenger.h
	util.h
	ping.h)

add_library(toxcore SHARED ${core_sources})
add_library(toxcore_static ${core_sources})
set_target_properties(toxcore_static PROPERTIES OUTPUT_NAME toxcore)

target_link_libraries(toxcore ${LINK_CRYPTO_LIBRARY})

install(TARGETS toxcore toxcore_static DESTINATION lib)
install(FILES ${core_headers} DESTINATION include)

if(WIN32)
	target_link_libraries(toxcore ws2_32)
endif()

execute_process(COMMAND git rev-list HEAD --count OUTPUT_VARIABLE COMMIT)

# Write pkgconfig-file:
include(InstallPkgConfigFile)
install_pkg_config_file(toxcore CFLAGS LIBS -ltoxcore REQUIRES VERSION 0.1.1_r${COMMIT})
 
