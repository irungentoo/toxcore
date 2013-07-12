cmake_minimum_required(VERSION 2.6.0)
project(TOX C)
 
set(core_sources
        core/DHT.c
        core/network.c
        core/Lossless_UDP.c
        core/net_crypto.c
        core/Messenger.c)
	
set(test_sources
        testing/Messenger_test.c)
	
set(exe_name TOX-app)


add_executable(${exe_name}
	${core_sources}
	${test_sources})

if(WIN32)
	target_link_libraries(${exe_name} ws2_32 libsodium)
else(WIN32)
        target_link_libraries(libsodium)
endif(WIN32)

if(CMAKE_COMPILER_IS_GNUCC)
	message(STATUS "==== GCC detected - Adding compiler flags")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()