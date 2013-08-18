cmake_minimum_required(VERSION 2.6.0)

cmake_policy(SET CMP0011 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_bootstrap.cmake)

if(WIN32)
#Setup standard file locations for windows
else()
  set(HOME "$ENV{HOME}")
  file(MAKE_DIRECTORY ${HOME}/.tox)
  file(INSTALL DHTservers DESTINATION ${HOME}/.tox)
endif()

if(LINUX)
	add_subdirectory(bootstrap_serverdaemon)
endif()
