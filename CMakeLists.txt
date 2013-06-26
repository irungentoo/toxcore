cmake_minimum_required(VERSION 2.6.0)
project(TOX C)
 
set(core_sources
        core/DHT.c
        core/network.c)
	
set(test_sources
        testing/DHT_test.c)
	
set(exe_name TOX-app)
 
add_executable(${exe_name}
	${core_sources}
	${test_sources})

if(WIN32)
	target_link_libraries(${exe_name} ws2_32)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
	message(STATUS "==== GCC detected - Adding compiler flags")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()