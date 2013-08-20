cmake_minimum_required(VERSION 2.6.0)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

message("==== Detected OS: ${CMAKE_SYSTEM_NAME} ====")



option(SHARED_TOXCORE "Build Core as a shared library")

if(("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows"))
	option(SHARED_LIBSODIUM "Links libsodium as a shared library")
else()
	option(USE_NACL "Use NaCl library instead of libsodium")
endif()

#OS X specific
if(("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin"))
	set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /opt/local/lib)
	set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} /opt/local/include)
	set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -I/opt/local/include" )
	set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -L/opt/local/lib")
endif()

if(("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux"))
	find_package(Curses REQUIRED)
endif()

if(USE_NACL)
	find_package(NaCl REQUIRED)

	include_directories(${NACL_INCLUDE_DIR})
	add_definitions(-DVANILLA_NACL)

	set(LINK_CRYPTO_LIBRARY ${NACL_LIBRARIES})
else()
	find_package(SODIUM REQUIRED)

	include_directories(${SODIUM_INCLUDE_DIR})

	set(LINK_CRYPTO_LIBRARY ${SODIUM_LIBRARIES})
endif()

#MinGW prints more warnings for -Wall than gcc does, thus causing build to fail
if(NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows"))
	if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang"))
		message(STATUS "==== ${CMAKE_C_COMPILER_ID} detected - Adding compiler flags ====")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
	endif()
endif()

macro(linkCoreLibraries exe_name)
	add_dependencies(${exe_name} toxcore)
	target_link_libraries(${exe_name} toxcore
		${LINK_CRYPTO_LIBRARY})

	if(("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows"))
		target_link_libraries(${exe_name} ws2_32)
	endif()
endmacro()

cmake_policy(SET CMP0011 NEW)

add_subdirectory(core)
add_subdirectory(testing)
add_subdirectory(other)
add_subdirectory(docs)
if(("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux"))
	add_subdirectory(auto_tests)
endif()
