cmake_minimum_required(VERSION 2.6.0)

cmake_policy(SET CMP0011 NEW)
SET(USER_NAME $ENV{USERNAME} CACHE STRING UserName)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/DHT_bootstrap.cmake)

if(WIN32)
  file(MAKE_DIRECTORY "C:/Users/${USER_NAME}/AppData/Roaming/.tox")
  file(INSTALL DHTservers DESTINATION "C:/Users/${USER_NAME}/AppData/Roaming/.tox")
else()
  set(HOME "$ENV{HOME}")
  if(APPLE)
    file(MAKE_DIRECTORY ${HOME}/Library/Application\ Support/.tox)
    file(INSTALL DHTservers DESTINATION ${HOME}/Library/Application\ Support/.tox)
  else()
    file(MAKE_DIRECTORY ${HOME}/.tox)
    file(INSTALL DHTservers DESTINATION ${HOME}/.tox)
  endif()
endif()

if(LINUX)
	add_subdirectory(bootstrap_serverdaemon)
endif()
