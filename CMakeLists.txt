cmake_minimum_required(VERSION 2.8.6)
project(toxcore)
include(CTest)

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION "0.0.0")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

################################################################################
#
# :: Dependencies and configuration
#
################################################################################

include(CheckCCompilerFlag)
include(ModulePackage)

set(CMAKE_MACOSX_RPATH ON)

option(DEBUG "Enable assertions and other debugging facilities" OFF)
if(DEBUG)
  add_definitions(-DTOX_DEBUG=1)
  add_definitions(-DMIN_LOGGER_LEVEL=LOG_TRACE)
  check_c_compiler_flag("-g3" HAVE_G3)
  if(HAVE_G3)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3")
  endif()
endif()

option(ASSOC_DHT "Enable module to store currently unused ID <=> IP associations" OFF)
if(ASSOC_DHT)
  add_definitions(-DENABLE_ASSOC_DHT=1)
endif()

option(ASAN "Enable address-sanitizer to detect invalid memory accesses" OFF)
if(ASAN)
  set(SAFE_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
  set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
  check_c_compiler_flag("-fsanitize=address" HAVE_ASAN)
  if(HAVE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  endif()
  set(CMAKE_REQUIRED_LIBRARIES "${SAFE_CMAKE_REQUIRED_LIBRARIES}")
endif()

find_package(Threads   REQUIRED)

find_library(NCURSES_LIBRARIES      ncurses       )
find_library(UTIL_LIBRARIES         util          )
find_library(RT_LIBRARIES           rt            )

# For toxcore.
pkg_use_module(LIBSODIUM  REQUIRED  libsodium     )

# For toxav.
pkg_use_module(OPUS                 opus          )
pkg_use_module(VPX                  vpx           )

# For tox-bootstrapd.
pkg_use_module(LIBCONFIG            libconfig     )

# For auto tests.
pkg_use_module(CHECK                check         )

# For av_test.
pkg_use_module(OPENCV               opencv        )
pkg_use_module(PORTAUDIO            portaudio-2.0 )
pkg_use_module(SNDFILE              sndfile       )

if(OPUS_FOUND AND VPX_FOUND)
  set(BUILD_TOXAV TRUE)
else()
  set(BUILD_TOXAV FALSE)
endif()

################################################################################
#
# :: Tox Core Library
#
################################################################################

# toxcore_PKGCONFIG_LIBS is what's added to the Libs: line in toxcore.pc. It
# needs to contain all the libraries a program using toxcore should link against
# if it's statically linked. If it's dynamically linked, there is no need to
# explicitly link against all the dependencies, but it doesn't harm much(*)
# either.
#
# (*) It allows client code to use symbols from our dependencies without
#    explicitly linking against them.
set(toxcore_PKGCONFIG_LIBS)

# LAYER 1: Crypto core
# --------------------
add_module(toxcrypto
  toxcore/crypto_core.c)
target_link_modules(toxcrypto ${LIBSODIUM_LIBRARIES})
if(WIN32)
  target_link_modules(toxcrypto ws2_32) # for htonl
endif()

# LAYER 2: Basic networking
# -------------------------
add_module(toxnetwork
  toxcore/logger.c
  toxcore/network.c
  toxcore/util.c)
target_link_modules(toxnetwork toxcrypto)

if(CMAKE_THREAD_LIBS_INIT)
  target_link_modules(toxnetwork ${CMAKE_THREAD_LIBS_INIT})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-l${CMAKE_THREAD_LIBS_INIT}")
endif()

if(RT_LIBRARIES)
  target_link_modules(toxnetwork ${RT_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-lrt")
endif()

if(WIN32)
  target_link_modules(toxnetwork ws2_32 iphlpapi)
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-lws2_32 -liphlpapi")
endif()

# LAYER 3: Distributed Hash Table
# -------------------------------
add_module(toxdht
  toxcore/DHT.c
  toxcore/LAN_discovery.c
  toxcore/assoc.c
  toxcore/ping.c
  toxcore/ping_array.c)
target_link_modules(toxdht toxnetwork)

# LAYER 4: Onion routing, TCP connections, crypto connections
# -----------------------------------------------------------
add_module(toxnetcrypto
  toxcore/TCP_client.c
  toxcore/TCP_connection.c
  toxcore/TCP_server.c
  toxcore/list.c
  toxcore/net_crypto.c
  toxcore/onion.c
  toxcore/onion_announce.c
  toxcore/onion_client.c)
target_link_modules(toxnetcrypto toxdht)

# LAYER 5: Friend requests and connections
# ----------------------------------------
add_module(toxfriends
  toxcore/friend_connection.c
  toxcore/friend_requests.c)
target_link_modules(toxfriends toxnetcrypto)

# LAYER 6: Tox messenger
# ----------------------
add_module(toxmessenger
  toxcore/Messenger.c)
target_link_modules(toxmessenger toxfriends)

# LAYER 7: Group chats
# --------------------
add_module(toxgroup
  toxcore/group.c)
target_link_modules(toxgroup toxmessenger)

# LAYER 8: Public API
# -------------------
add_module(toxcore
  toxcore/tox.c)
target_link_modules(toxcore toxgroup)


################################################################################
#
# :: Audio/Video Library
#
################################################################################

if(BUILD_TOXAV)
  add_module(toxav
    toxav/audio.c
    toxav/bwcontroller.c
    toxav/group.c
    toxav/msi.c
    toxav/rtp.c
    toxav/toxav.c
    toxav/toxav_old.c
    toxav/video.c)
  target_link_modules(toxav toxcore ${OPUS_LIBRARIES} ${VPX_LIBRARIES})
endif()


################################################################################
#
# :: ToxDNS and block encryption libraries
#
################################################################################

add_module(toxdns
  toxdns/toxdns.c)
target_link_modules(toxdns toxcore)

add_module(toxencryptsave
  toxencryptsave/toxencryptsave.c)
target_link_modules(toxencryptsave toxcore)


################################################################################
#
# :: Automated regression tests
#
################################################################################

add_test(
  NAME format_test
  COMMAND ${CMAKE_SOURCE_DIR}/other/astyle/format-source "${CMAKE_SOURCE_DIR}")

function(auto_test target)
  if(CHECK_FOUND)
    add_c_executable(auto_${target} auto_tests/${target}.c)
    target_link_modules(auto_${target}
      toxcore
      toxencryptsave
      ${CHECK_LIBRARIES})
    if(BUILD_TOXAV)
      target_link_modules(auto_${target} toxav)
    endif()
    add_test(NAME ${target} COMMAND auto_${target})
  endif()
endfunction()

auto_test(TCP_test)
auto_test(assoc_test)
auto_test(crypto_test)
auto_test(dht_test)
auto_test(encryptsave_test)
auto_test(messenger_test)
auto_test(network_test)
auto_test(onion_test)
auto_test(skeleton_test)
auto_test(tox_test)
if(BUILD_TOXAV)
  auto_test(toxav_basic_test)
  auto_test(toxav_many_test)
endif()


################################################################################
#
# :: Bootstrap daemon
#
################################################################################

add_c_executable(DHT_bootstrap
  other/DHT_bootstrap.c
  other/bootstrap_node_packets.c)
target_link_modules(DHT_bootstrap toxnetcrypto)

if(LIBCONFIG_FOUND)
  add_c_executable(tox-bootstrapd
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
  target_link_modules(tox-bootstrapd toxnetcrypto ${LIBCONFIG_LIBRARIES})
endif()


################################################################################
#
# :: Test programs
#
################################################################################

if(NOT WIN32 AND BUILD_TOXAV AND SNDFILE_FOUND AND PORTAUDIO_FOUND AND OPENCV_FOUND)
  add_c_executable(av_test testing/av_test.c)
  target_link_modules(av_test
    toxav
    ${OPENCV_LIBRARIES}
    ${PORTAUDIO_LIBRARIES}
    ${SNDFILE_LIBRARIES})
endif()

if(NOT WIN32)
  add_c_executable(nTox testing/nTox.c)
  target_link_modules(nTox toxcore ${NCURSES_LIBRARIES})
endif()

add_c_executable(DHT_test testing/DHT_test.c)
target_link_modules(DHT_test toxdht)

add_c_executable(Messenger_test testing/Messenger_test.c)
target_link_modules(Messenger_test toxmessenger)

add_c_executable(dns3_test testing/dns3_test.c)
target_link_modules(dns3_test toxdns)

if(NOT WIN32)
  add_c_executable(tox_sync testing/tox_sync.c)
  target_link_modules(tox_sync toxcore)
endif()

if(UTIL_LIBRARIES)
  add_c_executable(tox_shell testing/tox_shell.c)
  target_link_modules(tox_shell toxcore ${UTIL_LIBRARIES})
endif()

if(NOT WIN32)
  add_c_executable(irc_syncbot testing/irc_syncbot.c)
  target_link_modules(irc_syncbot toxcore)
endif()


################################################################################
#
# :: Installation and pkg-config
#
################################################################################

if(BUILD_TOXAV)
  configure_file(
    "${CMAKE_SOURCE_DIR}/other/pkgconfig/toxav.pc.in"
    "${CMAKE_BINARY_DIR}/toxav.pc"
    @ONLY
  )
endif()

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
  ${CMAKE_BINARY_DIR}/toxcore.pc
  ${CMAKE_BINARY_DIR}/toxdns.pc
  ${CMAKE_BINARY_DIR}/toxencryptsave.pc
  DESTINATION "lib/pkgconfig")
install(FILES
  toxcore/tox.h
  toxdns/toxdns.h
  toxencryptsave/toxencryptsave.h
  DESTINATION "include/tox")

if(BUILD_TOXAV)
  install(FILES
    ${CMAKE_BINARY_DIR}/toxav.pc
    DESTINATION "lib/pkgconfig")
  install(FILES
    toxav/toxav.h
    DESTINATION "include/tox")
endif()

################################################################################
#
# :: Strict ABI
#
################################################################################

function(make_version_script header ns lib)
  execute_process(
    COMMAND sh -c "egrep '^\\w' ${header} | grep '${ns}_[a-z0-9_]*(' | grep -v '^typedef' | grep -o '${ns}_[a-z0-9_]*(' | egrep -o '\\w+' | sort -u"
    OUTPUT_VARIABLE ${lib}_SYMS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(REPLACE "\n" ";" ${lib}_SYMS ${${lib}_SYMS})

  set(${lib}_VERSION_SCRIPT "${CMAKE_BINARY_DIR}/${lib}.ld")

  file(WRITE ${${lib}_VERSION_SCRIPT}
    "{ global:\n")
  foreach(sym ${${lib}_SYMS})
    file(APPEND ${${lib}_VERSION_SCRIPT}
      "${sym};\n")
  endforeach(sym)
  file(APPEND ${${lib}_VERSION_SCRIPT}
    "local: *; };\n")

  set_target_properties(${lib}_shared PROPERTIES
    LINK_FLAGS -Wl,--version-script,${${lib}_VERSION_SCRIPT})
endfunction()

option(STRICT_ABI "Enforce strict ABI export in dynamic libraries" OFF)
if(WIN32 OR APPLE)
  # Windows and OSX don't have this linker functionality.
  set(STRICT_ABI OFF)
endif()

if(STRICT_ABI)
  if(BUILD_TOXAV)
    make_version_script(${CMAKE_SOURCE_DIR}/toxav/toxav.h toxav toxav)
  endif()
  make_version_script(${CMAKE_SOURCE_DIR}/toxcore/tox.h tox toxcore)
endif()
