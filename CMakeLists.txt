cmake_minimum_required(VERSION 2.6.0)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if(NOT WIN32)
	option(USE_NACL "Use NaCl library instead of libsodium")
endif()

if(USE_NACL)
	find_package(NaCl REQUIRED)

	include_directories(${NACL_INCLUDE_DIR})
	add_definitions(-DVANILLA_NACL)

	set(LINK_CRYPTO_LIBRARY ${NACL_LIBRARIES})
endif()

#MinGW prints more warnings for -Wall than gcc does, thus causing build to fail
if(NOT WIN32)
	if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang"))
		message(STATUS "==== ${CMAKE_C_COMPILER_ID} detected - Adding compiler flags ====")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
	endif()
	find_package(SODIUM REQUIRED)
endif()

if(NOT USE_NACL)
	 set(LINK_CRYPTO_LIBRARY ${SODIUM_LIBRARY})
endif()

macro(linkCoreLibraries exe_name)
	add_dependencies(${exe_name} core)
	if(WIN32)
		include_directories(${CMAKE_HOME_DIRECTORY}/sodium/include/)
		target_link_libraries(${exe_name} core
		${CMAKE_SOURCE_DIR}/sodium/lib/libsodium.a
			ws2_32)
	else()
		include_directories(${SODIUM_INCLUDE_DIR})
		target_link_libraries(${exe_name} core
			${LINK_CRYPTO_LIBRARY})

	endif()
endmacro()

cmake_policy(SET CMP0011 NEW)

add_subdirectory(core)
add_subdirectory(testing)
add_subdirectory(other)
add_subdirectory(docs)
