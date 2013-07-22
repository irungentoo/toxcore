cmake_minimum_required(VERSION 2.6.0)

#MinGW prints more warnings for -Wall than gcc does, thus causing build to fail
if(NOT WIN32)
	if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang"))
		message(STATUS "==== ${CMAKE_C_COMPILER_ID} detected - Adding compiler flags ====")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
	endif()
endif()

macro(linkCoreLibraries exe_name)
	add_dependencies(${exe_name} core)
	if(WIN32)
		include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
		target_link_libraries(${exe_name} core
		${CMAKE_SOURCE_DIR}/sodium/lib/libsodium.a
			ws2_32)
	else()
		target_link_libraries(${exe_name} core
			sodium)
	endif()
endmacro()

cmake_policy(SET CMP0011 NEW)

add_subdirectory(core)
add_subdirectory(testing)
add_subdirectory(other)