cmake_minimum_required(VERSION 2.6.0)
project(toxrtp C)

set(toxrtp_sources
	rtp_impl.c
	rtp_message.c
	rtp_helper.c
	)

if(SHARED_TOXCORE)
	add_library(toxrtp SHARED ${toxrtp_sources})
else()
	add_library(toxrtp ${toxrtp_sources})
endif()

target_link_libraries(toxrtp ${LINK_CRYPTO_LIBRARY})

if(WIN32)
	target_link_libraries(toxrtp ws2_32)
endif()
