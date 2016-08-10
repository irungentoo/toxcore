cmake_minimum_required(VERSION 2.8.6)
project(toxcore)
include(CTest)


################################################################################
#
# :: Dependencies and configuration.
#
################################################################################

set(CMAKE_MACOSX_RPATH ON)

find_package(PkgConfig REQUIRED)
find_package(Threads   REQUIRED)

find_library(UTIL_LIBRARIES util)

pkg_search_module(LIBSODIUM REQUIRED libsodium)
pkg_search_module(CHECK     REQUIRED check)
pkg_search_module(OPUS      REQUIRED opus)
pkg_search_module(VPX       REQUIRED vpx)

link_directories(${LIBSODIUM_LIBRARY_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})
link_directories(${OPUS_LIBRARY_DIRS})
link_directories(${VPX_LIBRARY_DIRS})

include_directories(${LIBSODIUM_INCLUDE_DIRS})
include_directories(${CHECK_INCLUDE_DIRS})
include_directories(${OPUS_INCLUDE_DIRS})
include_directories(${VPX_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBSODIUM_CFLAGS_OTHER}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CHECK_CFLAGS_OTHER}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPUS_CFLAGS_OTHER}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${VPX_CFLAGS_OTHER}")


################################################################################
#
# :: Libraries.
#
################################################################################

add_library(toxcore SHARED
  toxcore/DHT.c
  toxcore/LAN_discovery.c
  toxcore/Messenger.c
  toxcore/TCP_client.c
  toxcore/TCP_connection.c
  toxcore/TCP_server.c
  toxcore/assoc.c
  toxcore/crypto_core.c
  toxcore/friend_connection.c
  toxcore/friend_requests.c
  toxcore/group.c
  toxcore/list.c
  toxcore/logger.c
  toxcore/net_crypto.c
  toxcore/network.c
  toxcore/onion.c
  toxcore/onion_announce.c
  toxcore/onion_client.c
  toxcore/ping.c
  toxcore/ping_array.c
  toxcore/tox.c
  toxcore/util.c)

target_link_libraries(toxcore ${LIBSODIUM_LIBRARIES})
target_link_libraries(toxcore rt)

add_library(toxav SHARED
  toxav/audio.c
  toxav/bwcontroller.c
  toxav/group.c
  toxav/msi.c
  toxav/rtp.c
  toxav/toxav.c
  toxav/toxav_old.c
  toxav/video.c)

target_link_libraries(toxav toxcore)
target_link_libraries(toxav ${OPUS_LIBRARIES})
target_link_libraries(toxav ${VPX_LIBRARIES})

add_library(toxdns SHARED
  toxdns/toxdns.c)

target_link_libraries(toxdns toxcore)

add_library(toxencryptsave SHARED
  toxencryptsave/toxencryptsave.c)

target_link_libraries(toxencryptsave toxcore)


################################################################################
#
# :: Automated regression tests.
#
################################################################################

function(auto_test target)
  if(CHECK_FOUND)
    add_executable(auto_${target} auto_tests/${target}.c)
    target_link_libraries(auto_${target}
      toxcore
      toxav
      toxencryptsave
      ${CHECK_LIBRARIES}
      ${CMAKE_THREAD_LIBS_INIT})
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
# :: Test programs.
#
################################################################################

add_executable(nTox testing/nTox.c)
target_link_libraries(nTox toxcore ncurses ${CMAKE_THREAD_LIBS_INIT})

add_executable(DHT_test testing/DHT_test.c)
target_link_libraries(DHT_test toxcore ${CMAKE_THREAD_LIBS_INIT})

add_executable(Messenger_test testing/Messenger_test.c)
target_link_libraries(Messenger_test toxcore ${CMAKE_THREAD_LIBS_INIT})

add_executable(dns3_test testing/dns3_test.c)
target_link_libraries(dns3_test toxdns ${CMAKE_THREAD_LIBS_INIT})

add_executable(tox_sync testing/tox_sync.c)
target_link_libraries(tox_sync toxcore ${CMAKE_THREAD_LIBS_INIT})

add_executable(tox_shell testing/tox_shell.c)
target_link_libraries(tox_shell toxcore ${CMAKE_THREAD_LIBS_INIT} ${UTIL_LIBRARIES})

add_executable(irc_syncbot testing/irc_syncbot.c)
target_link_libraries(irc_syncbot toxcore ${CMAKE_THREAD_LIBS_INIT})
