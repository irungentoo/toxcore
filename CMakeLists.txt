################################################################################
#
# The main toxcore CMake build file.
#
# This file when processed with cmake produces:
# - A number of small libraries (.a/.so/...) containing independent components
#   of toxcore. E.g. the DHT has its own library, and the system/network
#   abstractions are in their own library as well. These libraries are not
#   installed on `make install`. The toxav, and toxencryptsave libraries are
#   also not installed.
# - A number of small programs, statically linked if possible.
# - One big library containing all of the toxcore, toxav, and toxencryptsave
#   code.
#
################################################################################

cmake_minimum_required(VERSION 2.8.12)
cmake_policy(VERSION 2.8.12)
project(toxcore)

list(APPEND CMAKE_MODULE_PATH ${toxcore_SOURCE_DIR}/cmake)

set_source_files_properties(
  other/bootstrap_daemon/src/tox-bootstrapd.c
  toxcore/mono_time.c
  toxcore/network.c
  toxcore/tox.c
  toxcore/util.c
  PROPERTIES SKIP_UNITY_BUILD_INCLUSION TRUE)

################################################################################
#
# :: Version management
#
################################################################################

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION_MAJOR "0")
set(PROJECT_VERSION_MINOR "2")
set(PROJECT_VERSION_PATCH "17")
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# set .so library version / following libtool scheme
# https://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_CURRENT REGEX "^CURRENT=[0-9]+$")
string(SUBSTRING "${SOVERSION_CURRENT}" 8 -1 SOVERSION_CURRENT)
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_REVISION REGEX "^REVISION=[0-9]+$")
string(SUBSTRING "${SOVERSION_REVISION}" 9 -1 SOVERSION_REVISION)
file(STRINGS ${toxcore_SOURCE_DIR}/so.version SOVERSION_AGE REGEX "^AGE=[0-9]+$")
string(SUBSTRING "${SOVERSION_AGE}" 4 -1 SOVERSION_AGE)
# account for some libtool magic, see other/version-sync script for details
math(EXPR SOVERSION_MAJOR ${SOVERSION_CURRENT}-${SOVERSION_AGE})
set(SOVERSION "${SOVERSION_MAJOR}.${SOVERSION_AGE}.${SOVERSION_REVISION}")
message("SOVERSION: ${SOVERSION}")

################################################################################
#
# :: Dependencies and configuration
#
################################################################################

include(CTest)
include(ModulePackage)
include(StrictAbi)
include(GNUInstallDirs)

if(APPLE)
  include(MacRpath)
endif()

enable_testing()

set(CMAKE_MACOSX_RPATH ON)

if(${CMAKE_VERSION} VERSION_LESS "3.1.0")
  if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  endif()
else()
  # Set standard version for compiler.
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_CXX_EXTENSIONS OFF)

  message(STATUS "Supported C compiler features = ${CMAKE_C_COMPILE_FEATURES}")
  message(STATUS "Supported C++ compiler features = ${CMAKE_CXX_COMPILE_FEATURES}")
endif()

set(MIN_LOGGER_LEVEL "" CACHE STRING "Logging level to use (TRACE, DEBUG, INFO, WARNING, ERROR)")
if(MIN_LOGGER_LEVEL)
  if(("${MIN_LOGGER_LEVEL}" STREQUAL "TRACE") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "DEBUG") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "INFO") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "WARNING") OR
     ("${MIN_LOGGER_LEVEL}" STREQUAL "ERROR"))
    add_definitions(-DMIN_LOGGER_LEVEL=LOGGER_LEVEL_${MIN_LOGGER_LEVEL})
  else()
    message(FATAL_ERROR "Unknown value provided for MIN_LOGGER_LEVEL: \"${MIN_LOGGER_LEVEL}\", must be one of TRACE, DEBUG, INFO, WARNING or ERROR")
  endif()
endif()

option(PROXY_TEST "Enable proxy test (needs HTTP/SOCKS5 proxy on port 8080/8081)" OFF)

option(USE_IPV6 "Use IPv6 in tests" ON)
if(NOT USE_IPV6)
  add_definitions(-DUSE_IPV6=0)
endif()

option(USE_STDERR_LOGGER "Enable logging to stderr when the logger is NULL" OFF)
if(USE_STDERR_LOGGER)
  add_definitions(-DUSE_STDERR_LOGGER=1)
endif()

option(NON_HERMETIC_TESTS "Whether to build and run tests that depend on an internet connection" OFF)

option(BUILD_TOXAV "Whether to build the tox AV library" ON)
option(MUST_BUILD_TOXAV "Fail the build if toxav cannot be built" OFF)

if(MSVC)
  option(MSVC_STATIC_SODIUM "Whether to link libsodium statically for MSVC" OFF)
  if(MSVC_STATIC_SODIUM)
    add_definitions(-DSODIUM_STATIC=1 -DSODIUM_EXPORT)
  endif()
endif()

include(Dependencies)

if(MUST_BUILD_TOXAV)
  set(NO_TOXAV_ERROR_TYPE SEND_ERROR)
else()
  set(NO_TOXAV_ERROR_TYPE WARNING)
endif()

if(BUILD_TOXAV)
  if(NOT OPUS_FOUND)
    message(${NO_TOXAV_ERROR_TYPE} "Option BUILD_TOXAV is enabled but required library OPUS was not found.")
    set(BUILD_TOXAV OFF)
  endif()
  if(NOT VPX_FOUND)
    message(${NO_TOXAV_ERROR_TYPE} "Option BUILD_TOXAV is enabled but required library VPX was not found.")
    set(BUILD_TOXAV OFF)
  endif()
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
# Requires: in pkg-config file.
set(toxcore_PKGCONFIG_REQUIRES)

# LAYER 1: Crypto core
# --------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/ccompat.c
  toxcore/ccompat.h
  toxcore/crypto_core.c
  toxcore/crypto_core.h)
set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${LIBSODIUM_LIBRARIES})
set(toxcore_PKGCONFIG_REQUIRES ${toxcore_PKGCONFIG_REQUIRES} libsodium)

# LAYER 2: Basic networking
# -------------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/logger.c
  toxcore/logger.h
  toxcore/mono_time.c
  toxcore/mono_time.h
  toxcore/network.c
  toxcore/network.h
  toxcore/state.c
  toxcore/state.h
  toxcore/util.c
  toxcore/util.h)

# LAYER 3: Distributed Hash Table
# -------------------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/DHT.c
  toxcore/DHT.h
  toxcore/LAN_discovery.c
  toxcore/LAN_discovery.h
  toxcore/ping.c
  toxcore/ping.h
  toxcore/ping_array.c
  toxcore/ping_array.h)

# LAYER 4: Onion routing, TCP connections, crypto connections
# -----------------------------------------------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/TCP_client.c
  toxcore/TCP_client.h
  toxcore/TCP_common.c
  toxcore/TCP_common.h
  toxcore/TCP_connection.c
  toxcore/TCP_connection.h
  toxcore/TCP_server.c
  toxcore/TCP_server.h
  toxcore/list.c
  toxcore/list.h
  toxcore/net_crypto.c
  toxcore/net_crypto.h
  toxcore/onion.c
  toxcore/onion.h
  toxcore/onion_announce.c
  toxcore/onion_announce.h
  toxcore/onion_client.c
  toxcore/onion_client.h)

# LAYER 5: Friend requests and connections
# ----------------------------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/friend_connection.c
  toxcore/friend_connection.h
  toxcore/friend_requests.c
  toxcore/friend_requests.h)

# LAYER 6: Tox messenger
# ----------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/Messenger.c
  toxcore/Messenger.h)

# LAYER 7: Group chats
# --------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/group.c
  toxcore/group.h)

# LAYER 8: Public API
# -------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/tox_api.c
  toxcore/tox.c
  toxcore/tox.h
  toxcore/tox_private.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxcore/tox.h^tox)

# LAYER 9: New async events API
# -------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/events/conference_connected.c
  toxcore/events/conference_invite.c
  toxcore/events/conference_message.c
  toxcore/events/conference_peer_list_changed.c
  toxcore/events/conference_peer_name.c
  toxcore/events/conference_title.c
  toxcore/events/file_chunk_request.c
  toxcore/events/file_recv.c
  toxcore/events/file_recv_chunk.c
  toxcore/events/file_recv_control.c
  toxcore/events/friend_connection_status.c
  toxcore/events/friend_lossless_packet.c
  toxcore/events/friend_lossy_packet.c
  toxcore/events/friend_message.c
  toxcore/events/friend_name.c
  toxcore/events/friend_read_receipt.c
  toxcore/events/friend_request.c
  toxcore/events/friend_status.c
  toxcore/events/friend_status_message.c
  toxcore/events/friend_typing.c
  toxcore/events/events_alloc.c
  toxcore/events/events_alloc.h
  toxcore/events/self_connection_status.c
  toxcore/bin_pack.c
  toxcore/bin_pack.h
  toxcore/bin_unpack.c
  toxcore/bin_unpack.h
  toxcore/tox_events.c
  toxcore/tox_events.h
  toxcore/tox_unpack.c
  toxcore/tox_unpack.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxcore/tox_events.h^tox)
set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${MSGPACK_LIBRARIES})
set(toxcore_PKGCONFIG_REQUIRES ${toxcore_PKGCONFIG_REQUIRES} msgpack)

# LAYER 10: Dispatch recorded events to callbacks.
# -------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/tox_dispatch.c
  toxcore/tox_dispatch.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxcore/tox_dispatch.h^tox)

################################################################################
#
# :: Audio/Video Library
#
################################################################################

if(BUILD_TOXAV)
  set(toxcore_SOURCES ${toxcore_SOURCES}
    toxav/audio.c
    toxav/audio.h
    toxav/bwcontroller.c
    toxav/bwcontroller.h
    toxav/groupav.c
    toxav/groupav.h
    toxav/msi.c
    toxav/msi.h
    toxav/ring_buffer.c
    toxav/ring_buffer.h
    toxav/rtp.c
    toxav/rtp.h
    toxav/toxav.c
    toxav/toxav.h
    toxav/toxav_old.c
    toxav/video.c
    toxav/video.h)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${OPUS_LIBRARIES} ${VPX_LIBRARIES})
  set(toxcore_PKGCONFIG_REQUIRES ${toxcore_PKGCONFIG_REQUIRES} opus vpx)

  set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxav/toxav.h^toxav)
endif()

################################################################################
#
# :: Block encryption libraries
#
################################################################################

set(toxcore_SOURCES ${toxcore_SOURCES}
  toxencryptsave/toxencryptsave.c
  toxencryptsave/toxencryptsave.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxencryptsave/toxencryptsave.h^tox)

################################################################################
#
# :: System dependencies
#
################################################################################

# These need to come after other dependencies, since e.g. libvpx may depend on
# pthread, but doesn't list it in VPX_LIBRARIES. We're adding it here, after
# any potential libvpx linking.
message("CMAKE_THREAD_LIBS_INIT: ${CMAKE_THREAD_LIBS_INIT}")
if(CMAKE_THREAD_LIBS_INIT)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${CMAKE_THREAD_LIBS_INIT})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} ${CMAKE_THREAD_LIBS_INIT})
endif()


if(NSL_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${NSL_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lnsl)
endif()

if(RT_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${RT_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lrt)
endif()

if(SOCKET_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${SOCKET_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lsocket)
endif()

if(WIN32)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ws2_32 iphlpapi)
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} -lws2_32 -liphlpapi)
endif()

################################################################################
#
# :: All layers together in one library for ease of use
#
################################################################################

# Create combined library from all the sources.
add_module(toxcore ${toxcore_SOURCES})

# Link it to all dependencies.
target_link_modules(toxcore ${toxcore_LINK_MODULES})

# Make version script (on systems that support it) to limit symbol visibility.
make_version_script(toxcore ${toxcore_API_HEADERS})

# Generate pkg-config file, install library to "${CMAKE_INSTALL_LIBDIR}" and install headers to
# "${CMAKE_INSTALL_INCLUDEDIR}/tox".
install_module(toxcore DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tox)

################################################################################
#
# :: Unit tests: no networking, just pure function calls.
#
################################################################################

include(CompileGTest)

# The actual unit tests follow.
#
unit_test(toxav ring_buffer)
unit_test(toxav rtp)
unit_test(toxcore DHT)
unit_test(toxcore crypto_core)
unit_test(toxcore mono_time)
unit_test(toxcore ping_array)
unit_test(toxcore tox)
unit_test(toxcore util)

################################################################################
#
# :: Automated regression tests: create a tox network and run integration tests
#
################################################################################

set(misc_tools_SOURCES
  testing/misc_tools.c
  testing/misc_tools.h)
add_library(misc_tools ${misc_tools_SOURCES})
target_link_modules(misc_tools toxcore)

set(TEST_TIMEOUT_SECONDS "" CACHE STRING "Limit runtime of each test to the number of seconds specified")

option(AUTOTEST "Enable autotests (mainly for CI)" OFF)

if(AUTOTEST)
  add_library(auto_test_support
    auto_tests/auto_test_support.c
    auto_tests/auto_test_support.h)
  target_link_modules(auto_test_support toxcore misc_tools)
endif()

function(auto_test target)
  if(AUTOTEST AND NOT (MSVC AND ARGV1 STREQUAL "MSVC_DONT_BUILD"))
    add_executable(auto_${target}_test auto_tests/${target}_test.c)
    target_link_modules(auto_${target}_test toxcore misc_tools auto_test_support)
    if(NOT ARGV1 STREQUAL "DONT_RUN")
      add_test(NAME ${target} COMMAND ${CROSSCOMPILING_EMULATOR} auto_${target}_test)
      set_tests_properties(${target} PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
      set_property(TEST ${target} PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${target}.profraw")
    endif()
  endif()
endfunction()

auto_test(TCP)
auto_test(conference)
auto_test(conference_double_invite)
auto_test(conference_invite_merge)
auto_test(conference_peer_nick)
auto_test(conference_simple)
auto_test(conference_two)
auto_test(crypto)
auto_test(dht_getnodes_api)
auto_test(encryptsave)
auto_test(file_transfer)
auto_test(file_saving)
auto_test(friend_connection)
auto_test(friend_request)
auto_test(friend_request_spam)
auto_test(invalid_tcp_proxy)
auto_test(invalid_udp_proxy)
auto_test(lan_discovery)
auto_test(lossless_packet)
auto_test(lossy_packet)
auto_test(network)
auto_test(onion)
auto_test(overflow_recvq)
auto_test(overflow_sendq)
auto_test(reconnect)
auto_test(save_friend)
auto_test(save_load)
auto_test(send_message)
auto_test(set_name)
auto_test(set_status_message)
auto_test(tox_dispatch)
auto_test(tox_events)
auto_test(tox_many)
auto_test(tox_many_tcp)
auto_test(tox_strncasecmp)
auto_test(typing)
auto_test(version)
auto_test(save_compatibility)

if(PROXY_TEST)
  auto_test(proxy)
endif()

if(NON_HERMETIC_TESTS)
  auto_test(bootstrap)
  auto_test(tcp_relay)
endif()

if(BUILD_TOXAV)
  auto_test(conference_av MSVC_DONT_BUILD)
  auto_test(toxav_basic)
  auto_test(toxav_many)
endif()

################################################################################
#
# :: Bootstrap daemon
#
################################################################################

option(DHT_BOOTSTRAP "Enable building of DHT_bootstrap" ON)
if(DHT_BOOTSTRAP)
  add_executable(DHT_bootstrap
    other/DHT_bootstrap.c
    other/bootstrap_node_packets.c)
  target_link_modules(DHT_bootstrap toxcore misc_tools)
  install(TARGETS DHT_bootstrap RUNTIME DESTINATION bin)
endif()

option(BOOTSTRAP_DAEMON "Enable building of tox-bootstrapd" ON)
if(BOOTSTRAP_DAEMON AND WIN32)
  message(WARNING "Building tox-bootstrapd for Windows is not supported")
  set(BOOTSTRAP_DAEMON OFF)
endif()
if(BOOTSTRAP_DAEMON)
  if(NOT LIBCONFIG_FOUND)
    message(WARNING "Option BOOTSTRAP_DAEMON is enabled but required library LIBCONFIG was not found.")
    set(BOOTSTRAP_DAEMON OFF)
  else()
    add_executable(tox-bootstrapd
      other/bootstrap_daemon/src/command_line_arguments.c
      other/bootstrap_daemon/src/command_line_arguments.h
      other/bootstrap_daemon/src/config.c
      other/bootstrap_daemon/src/config.h
      other/bootstrap_daemon/src/config_defaults.h
      other/bootstrap_daemon/src/global.h
      other/bootstrap_daemon/src/log.c
      other/bootstrap_daemon/src/log.h
      other/bootstrap_daemon/src/log_backend_stdout.c
      other/bootstrap_daemon/src/log_backend_stdout.h
      other/bootstrap_daemon/src/log_backend_syslog.c
      other/bootstrap_daemon/src/log_backend_syslog.h
      other/bootstrap_daemon/src/tox-bootstrapd.c
      other/bootstrap_node_packets.c
      other/bootstrap_node_packets.h)
    target_link_modules(tox-bootstrapd toxcore ${LIBCONFIG_LIBRARIES})
    install(TARGETS tox-bootstrapd RUNTIME DESTINATION bin)
    install(FILES other/bootstrap_daemon/bash-completion/completions/tox-bootstrapd DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions")
  endif()
endif()

################################################################################
#
# :: Test programs
#
################################################################################

option(BUILD_MISC_TESTS "Build additional tests" OFF)
if (BUILD_MISC_TESTS)
  add_executable(Messenger_test testing/Messenger_test.c)
  target_link_modules(Messenger_test toxcore misc_tools)

  add_executable(random_testing testing/random_testing.cc)
  target_link_modules(random_testing toxcore misc_tools)

  add_executable(save-generator other/fun/save-generator.c)
  target_link_modules(save-generator toxcore misc_tools)

  if(NOT MSVC)
    add_executable(cracker other/fun/cracker.c)
    target_link_modules(cracker ${LIBSODIUM_LIBRARIES})
    find_package(OpenMP)
    if(OpenMP_C_FOUND)
        target_link_libraries(cracker OpenMP::OpenMP_C)
    endif()
  endif()
endif()

# Enabling this breaks all other tests and no network connections will be possible
option(BUILD_FUZZ_TESTS "Build fuzzing harnesses" OFF)
if (BUILD_FUZZ_TESTS)
  # For coverage tests
  target_compile_definitions(toxcore_static PUBLIC "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION")

  # Override network and random functions
  add_library(fuzz_adapter testing/fuzzing/fuzz_adapter.c)

  # Fuzzes the toxsave API
  add_executable(toxsave_fuzzer testing/fuzzing/toxsave_harness.cc)
  target_link_libraries(toxsave_fuzzer toxcore_static fuzz_adapter -fsanitize=fuzzer)

  # Fuzzes the bootstrap process
  add_executable(bootstrap_fuzzer testing/fuzzing/bootstrap_harness.cc)
  target_link_libraries(bootstrap_fuzzer toxcore_static fuzz_adapter -fsanitize=fuzzer)
endif()
