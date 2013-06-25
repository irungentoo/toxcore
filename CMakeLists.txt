cmake_minimum_required(VERSION 2.6.0)
project(TOX)
 
set(core_sources
        core/DHT.c)
	
set(test_sources
        testing/DHT_test.c)
 
add_executable(TOX-app
	${core_sources}
	${test_sources})


if(WIN32)
	target_link_libraries(TOX-app ws2_32)
endif(WIN32)