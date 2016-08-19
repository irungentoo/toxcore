cmake_minimum_required(VERSION 2.8.6)
project(toxcore)
include(CTest)

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION "0.0.0")


################################################################################
#
# :: Dependencies and configuration
#
################################################################################

set(CMAKE_MACOSX_RPATH ON)

option(LOGGING "Enable internal library logging" OFF)
if(LOGGING)
  add_definitions(
    -DTOX_LOGGER=1
    -DLOGGER_LEVEL=LOG_DEBUG
    -DLOGGER_OUTPUT_FILE="libtoxcore.log")
endif()

option(DEBUG "Enable assertions and other debugging facilities" OFF)
if(DEBUG)
  add_definitions(-DTOX_DEBUG=1)
endif()

option(ASSOC_DHT "Enable module to store currently unused ID <=> IP associations" OFF)
if(ASSOC_DHT)
  add_definitions(-DENABLE_ASSOC_DHT=1)
endif()

find_package(PkgConfig REQUIRED)
find_package(Threads   REQUIRED)

find_library(UTIL_LIBRARIES util)
find_library(RT_LIBRARIES   rt)

pkg_search_module(CHECK              check)
pkg_search_module(LIBCONFIG          libconfig)
pkg_search_module(LIBSODIUM REQUIRED libsodium)
pkg_search_module(OPUS      REQUIRED opus)
pkg_search_module(VPX       REQUIRED vpx)

if(CHECK_FOUND)
  link_directories(${CHECK_LIBRARY_DIRS})
endif()
if(LIBCONFIG_FOUND)
  link_directories(${LIBCONFIG_LIBRARY_DIRS})
endif()
link_directories(${LIBSODIUM_LIBRARY_DIRS})
link_directories(${OPUS_LIBRARY_DIRS})
link_directories(${VPX_LIBRARY_DIRS})

if(CHECK_FOUND)
  include_directories(${CHECK_INCLUDE_DIRS})
endif()
if(LIBCONFIG_FOUND)
  include_directories(${LIBCONFIG_INCLUDE_DIRS})
endif()
include_directories(${LIBSODIUM_INCLUDE_DIRS})
include_directories(${OPUS_INCLUDE_DIRS})
include_directories(${VPX_INCLUDE_DIRS})

if(CHECK_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CHECK_CFLAGS_OTHER}")
endif()
if(LIBCONFIG_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBCONFIG_CFLAGS_OTHER}")
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBSODIUM_CFLAGS_OTHER}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPUS_CFLAGS_OTHER}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${VPX_CFLAGS_OTHER}")

# Users can call cmake -DLIBTYPE=STATIC or -DLIBTYPE=SHARED to override this.
if(NOT LIBTYPE)
  if(WIN32)
    # Our win32 builds are fully static, since we use the MXE cross compiling
    # environment, which builds everything statically by default. Building
    # shared libraries will result in multiple definition errors, since multiple
    # tox libraries will link against libsodium and other libraries that are
    # built statically in MXE.
    set(LIBTYPE STATIC)
  else()
    set(LIBTYPE SHARED)
  endif()
endif()


################################################################################
#
# :: Tox Core Library
#
################################################################################

# LAYER 1: Crypto core
# --------------------
add_library(toxcrypto ${LIBTYPE}
  toxcore/crypto_core.c)
target_link_libraries(toxcrypto ${LIBSODIUM_LIBRARIES})

# LAYER 2: Basic networking
# -------------------------
add_library(toxnetwork ${LIBTYPE}
  toxcore/logger.c
  toxcore/network.c
  toxcore/util.c)
target_link_libraries(toxnetwork toxcrypto)
if(RT_LIBRARIES)
  target_link_libraries(toxnetwork ${RT_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-lrt")
endif()

# LAYER 3: Distributed Hash Table
# -------------------------------
add_library(toxdht ${LIBTYPE}
  toxcore/DHT.c
  toxcore/LAN_discovery.c
  toxcore/assoc.c
  toxcore/ping.c
  toxcore/ping_array.c)
target_link_libraries(toxdht toxnetwork)

# LAYER 4: Onion routing, TCP connections, crypto connections
# -----------------------------------------------------------
add_library(toxnetcrypto ${LIBTYPE}
  toxcore/TCP_client.c
  toxcore/TCP_connection.c
  toxcore/TCP_server.c
  toxcore/list.c
  toxcore/net_crypto.c
  toxcore/onion.c
  toxcore/onion_announce.c
  toxcore/onion_client.c)
target_link_libraries(toxnetcrypto toxdht)

# LAYER 5: Friend requests and connections
# ----------------------------------------
add_library(toxfriends ${LIBTYPE}
  toxcore/friend_connection.c
  toxcore/friend_requests.c)
target_link_libraries(toxfriends toxnetcrypto)

# LAYER 6: Tox messenger
# ----------------------
add_library(toxmessenger ${LIBTYPE}
  toxcore/Messenger.c)
target_link_libraries(toxmessenger toxfriends)

# LAYER 7: Group chats
# --------------------
add_library(toxgroup ${LIBTYPE}
  toxcore/group.c)
target_link_libraries(toxgroup toxmessenger)

# LAYER 8: Public API
# -------------------
add_library(toxcore ${LIBTYPE}
  toxcore/tox.c)
target_link_libraries(toxcore toxgroup)

target_link_libraries(toxcore ${CMAKE_THREAD_LIBS_INIT})
if(CMAKE_THREAD_LIBS_INIT)
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-l${CMAKE_THREAD_LIBS_INIT}")
endif()

if(WIN32)
  target_link_libraries(toxcore ws2_32 iphlpapi)
endif()


################################################################################
#
# :: Audio/Video Library
#
################################################################################

add_library(toxav ${LIBTYPE}
  toxav/audio.c
  toxav/bwcontroller.c
  toxav/group.c
  toxav/msi.c
  toxav/rtp.c
  toxav/toxav.c
  toxav/toxav_old.c
  toxav/video.c)
target_link_libraries(toxav toxcore ${OPUS_LIBRARIES} ${VPX_LIBRARIES})


################################################################################
#
# :: ToxDNS and block encryption libraries
#
################################################################################

add_library(toxdns ${LIBTYPE}
  toxdns/toxdns.c)
target_link_libraries(toxdns toxcore)

add_library(toxencryptsave ${LIBTYPE}
  toxencryptsave/toxencryptsave.c)
target_link_libraries(toxencryptsave toxcore)


################################################################################
#
# :: Automated regression tests
#
################################################################################

function(auto_test target)
  if(CHECK_FOUND)
    add_executable(auto_${target} auto_tests/${target}.c)
    target_link_libraries(auto_${target}
      toxcore
      toxav
      toxencryptsave
      ${CHECK_LIBRARIES})
    add_test(${target} auto_${target})
  endif()
endfunction()

auto_test(TCP_test)
auto_test(assoc_test)
auto_test(crypto_test)
auto_test(dht_test)
auto_test(encryptsave_test)
# This test doesn't link (missing symbol).
#auto_test(friends_test)
auto_test(messenger_test)
auto_test(network_test)
auto_test(onion_test)
auto_test(skeleton_test)
auto_test(tox_test)
auto_test(toxav_basic_test)
auto_test(toxav_many_test)


################################################################################
#
# :: Bootstrap daemon
#
################################################################################

add_executable(DHT_bootstrap
  other/DHT_bootstrap.c
  other/bootstrap_node_packets.c)
target_link_libraries(DHT_bootstrap toxnetcrypto)

if(LIBCONFIG_FOUND)
  add_executable(tox-bootstrapd
    other/bootstrap_daemon/src/command_line_arguments.c
    other/bootstrap_daemon/src/command_line_arguments.h
    other/bootstrap_daemon/src/config.c
    other/bootstrap_daemon/src/config_defaults.h
    other/bootstrap_daemon/src/config.h
    other/bootstrap_daemon/src/log.c
    other/bootstrap_daemon/src/log.h
    other/bootstrap_daemon/src/tox-bootstrapd.c
    other/bootstrap_daemon/src/global.h
    other/bootstrap_node_packets.c
    other/bootstrap_node_packets.h)

  target_link_libraries(tox-bootstrapd toxnetcrypto ${LIBCONFIG_LIBRARIES})
endif()


################################################################################
#
# :: Test programs
#
################################################################################

if(NOT WIN32)
  add_executable(nTox testing/nTox.c)
  target_link_libraries(nTox toxcore ncurses)
endif()

add_executable(DHT_test testing/DHT_test.c)
target_link_libraries(DHT_test toxdht)

add_executable(Messenger_test testing/Messenger_test.c)
target_link_libraries(Messenger_test toxmessenger)

add_executable(dns3_test testing/dns3_test.c)
target_link_libraries(dns3_test toxdns)

if(NOT WIN32)
  add_executable(tox_sync testing/tox_sync.c)
  target_link_libraries(tox_sync toxcore)
endif()

if(UTIL_LIBRARIES)
  add_executable(tox_shell testing/tox_shell.c)
  target_link_libraries(tox_shell toxcore ${UTIL_LIBRARIES})
endif()

if(NOT WIN32)
  add_executable(irc_syncbot testing/irc_syncbot.c)
  target_link_libraries(irc_syncbot toxcore)
endif()


################################################################################
#
# :: Installation and pkg-config
#
################################################################################

configure_file(
  "${CMAKE_SOURCE_DIR}/other/pkgconfig/toxav.pc.in"
  "${CMAKE_BINARY_DIR}/toxav.pc"
  @ONLY
)

configure_file(
  "${CMAKE_SOURCE_DIR}/other/pkgconfig/toxcore.pc.in"
  "${CMAKE_BINARY_DIR}/toxcore.pc"
  @ONLY
)

configure_file(
  "${CMAKE_SOURCE_DIR}/other/pkgconfig/toxdns.pc.in"
  "${CMAKE_BINARY_DIR}/toxdns.pc"
  @ONLY
)

configure_file(
  "${CMAKE_SOURCE_DIR}/other/pkgconfig/toxencryptsave.pc.in"
  "${CMAKE_BINARY_DIR}/toxencryptsave.pc"
  @ONLY
)


install(FILES
  ${CMAKE_BINARY_DIR}/toxav.pc
  ${CMAKE_BINARY_DIR}/toxcore.pc
  ${CMAKE_BINARY_DIR}/toxdns.pc
  ${CMAKE_BINARY_DIR}/toxencryptsave.pc
  DESTINATION "lib/pkgconfig")
install(TARGETS
  toxav
  toxcore
  toxcrypto
  toxdht
  toxdns
  toxencryptsave
  toxfriends
  toxgroup
  toxmessenger
  toxnetcrypto
  toxnetwork
  DESTINATION "lib")
install(FILES
  toxav/toxav.h
  toxcore/tox.h
  toxcore/tox_old.h
  toxdns/toxdns.h
  toxencryptsave/toxencryptsave.h
  DESTINATION "include/tox")
