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

set(CMAKE_MODULE_PATH ${toxcore_SOURCE_DIR}/cmake)

################################################################################
#
# :: Version management
#
################################################################################

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION_MAJOR "0")
set(PROJECT_VERSION_MINOR "2")
set(PROJECT_VERSION_PATCH "0")
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

include(AddCompilerFlag)
include(ApiDsl)
include(ModulePackage)
include(StrictAbi)
include(GNUInstallDirs)

if(APPLE)
  include(MacRpath)
endif()

enable_testing()

set(CMAKE_MACOSX_RPATH ON)

if(${CMAKE_VERSION} VERSION_LESS "3.1.0")
  add_cflag("-std=c99")
  add_cxxflag("-std=c++11")
else()
  # Set standard version for compiler.
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_C_EXTENSIONS OFF)
  set(CMAKE_CXX_EXTENSIONS OFF)

  message(STATUS "Supported C compiler features = ${CMAKE_C_COMPILE_FEATURES}")
  message(STATUS "Supported C++ compiler features = ${CMAKE_CXX_COMPILE_FEATURES}")
endif()

if(NOT MSVC)
  # Warn on non-ISO C.
  add_cflag("-pedantic")

  option(ERROR_ON_WARNING "Make compilation error on a warning" OFF)
  if(ERROR_ON_WARNING)
    add_flag("-Werror")
  endif()

  option(DEBUG "Enable assertions and other debugging facilities" OFF)
  if(DEBUG)
    set(MIN_LOGGER_LEVEL DEBUG)
    add_cflag("-g3")
    if(MINGW)
      # Allows wine to display source code file names and line numbers on crash in its backtrace
      add_flag("-gdwarf-2")
    endif()
  endif()

  option(WARNINGS "Enable additional compiler warnings" ON)
  if(WARNINGS)
    # Add all warning flags we can.
    add_flag("-Wall")
    add_flag("-Wextra")
    add_flag("-Weverything")

    # Disable specific warning flags for both C and C++.
    add_flag("-Wno-cast-align")
    add_flag("-Wno-conversion")
    add_flag("-Wno-covered-switch-default")
    # Due to clang's tolower() macro being recursive https://github.com/TokTok/c-toxcore/pull/481
    add_flag("-Wno-disabled-macro-expansion")
    add_flag("-Wno-documentation-deprecated-sync")
    add_flag("-Wno-format-nonliteral")
    add_flag("-Wno-missing-field-initializers")
    add_flag("-Wno-missing-prototypes")
    add_flag("-Wno-packed")
    add_flag("-Wno-padded")
    add_flag("-Wno-parentheses")
    add_flag("-Wno-reserved-id-macro")
    add_flag("-Wno-return-type")
    add_flag("-Wno-sign-compare")
    add_flag("-Wno-sign-conversion")
    # Our use of mutexes results in a false positive, see 1bbe446
    add_flag("-Wno-thread-safety-analysis")
    add_flag("-Wno-type-limits")
    add_flag("-Wno-undef")
    add_flag("-Wno-unreachable-code")
    add_flag("-Wno-unused-macros")
    add_flag("-Wno-unused-parameter")
    add_flag("-Wno-vla")

    # Disable specific warning flags for C.
    add_cflag("-Wno-assign-enum")
    add_cflag("-Wno-bad-function-cast")
    add_cflag("-Wno-double-promotion")
    add_cflag("-Wno-gnu-zero-variadic-macro-arguments")
    add_cflag("-Wno-packed")
    add_cflag("-Wno-shadow")
    add_cflag("-Wno-shorten-64-to-32")
    add_cflag("-Wno-unreachable-code-return")
    add_cflag("-Wno-unused-but-set-variable")
    add_cflag("-Wno-used-but-marked-unused")

    # Disable specific warning flags for C++.
    add_cxxflag("-Wno-c++98-compat")
    add_cxxflag("-Wno-c++98-compat-pedantic")
    add_cxxflag("-Wno-c99-extensions")
    add_cxxflag("-Wno-double-promotion")
    add_cxxflag("-Wno-narrowing")
    add_cxxflag("-Wno-old-style-cast")
    add_cxxflag("-Wno-shadow")
    add_cxxflag("-Wno-used-but-marked-unused")
    add_cxxflag("-Wno-variadic-macros")
    add_cxxflag("-Wno-vla-extension")

    # Downgrade to warning so we still see it.
    add_flag("-Wno-error=unused-variable")
  endif()
endif()

option(TRACE "Enable TRACE level logging (expensive, for network debugging)" OFF)
if(TRACE)
  set(MIN_LOGGER_LEVEL TRACE)
endif()

if(MIN_LOGGER_LEVEL)
  add_definitions(-DMIN_LOGGER_LEVEL=LOG_${MIN_LOGGER_LEVEL})
endif()

option(ASAN "Enable address-sanitizer to detect invalid memory accesses" OFF)
if(ASAN)
  set(SAFE_CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
  set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
  add_cflag("-fsanitize=address")
  set(CMAKE_REQUIRED_LIBRARIES "${SAFE_CMAKE_REQUIRED_LIBRARIES}")
else()
  # Forbid undefined symbols in shared libraries. This is incompatible with
  # asan, so it's in the else branch here.
  add_dllflag("-Wl,-z,defs")
endif()

option(USE_IPV6 "Use IPv6 in tests" ON)
if(NOT USE_IPV6)
  add_definitions(-DUSE_IPV6=0)
endif()

option(BUILD_TOXAV "Whether to build the tox AV library" ON)

include(Dependencies)

if(BUILD_TOXAV)
  if(NOT OPUS_FOUND)
    message(WARNING "Option BUILD_TOXAV is enabled but required library OPUS was not found.")
    set(BUILD_TOXAV OFF)
  endif()
  if(NOT VPX_FOUND)
    message(WARNING "Option BUILD_TOXAV is enabled but required library VPX was not found.")
    set(BUILD_TOXAV OFF)
  endif()
endif()

################################################################################
#
# :: Tox Core Library
#
################################################################################

# LAYER 1: Crypto core
# --------------------
apidsl(toxcore/crypto_core.api.h)
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/ccompat.h
  toxcore/crypto_core.c
  toxcore/crypto_core.h
  toxcore/crypto_core_mem.c)
include(CheckFunctionExists)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)
set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${LIBSODIUM_LIBRARIES})
set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} libsodium)

# LAYER 2: Basic networking
# -------------------------
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/logger.c
  toxcore/logger.h
  toxcore/network.c
  toxcore/network.h
  toxcore/util.c
  toxcore/util.h)

message("CMAKE_THREAD_LIBS_INIT: ${CMAKE_THREAD_LIBS_INIT}")
if(CMAKE_THREAD_LIBS_INIT)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${CMAKE_THREAD_LIBS_INIT})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} ${CMAKE_THREAD_LIBS_INIT})
endif()

if(RT_LIBRARIES)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ${RT_LIBRARIES})
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-lrt")
endif()

if(WIN32)
  set(toxcore_LINK_MODULES ${toxcore_LINK_MODULES} ws2_32 iphlpapi)
  set(toxcore_PKGCONFIG_LIBS ${toxcore_PKGCONFIG_LIBS} "-lws2_32 -liphlpapi")
endif()

# LAYER 3: Distributed Hash Table
# -------------------------------
apidsl(toxcore/LAN_discovery.api.h)
apidsl(toxcore/ping.api.h)
apidsl(toxcore/ping_array.api.h)
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
apidsl(toxcore/tox.api.h)
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxcore/tox_api.c
  toxcore/tox.c
  toxcore/tox.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxcore/tox.h^tox)

################################################################################
#
# :: Audio/Video Library
#
################################################################################

if(BUILD_TOXAV)
  apidsl(toxav/toxav.api.h)
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

apidsl(toxencryptsave/toxencryptsave.api.h)
set(toxcore_SOURCES ${toxcore_SOURCES}
  toxencryptsave/toxencryptsave.c
  toxencryptsave/toxencryptsave.h)
set(toxcore_API_HEADERS ${toxcore_API_HEADERS} ${toxcore_SOURCE_DIR}/toxencryptsave/toxencryptsave.h^tox)

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
unit_test(toxav rtp)
unit_test(toxcore crypto_core)
unit_test(toxcore util)

################################################################################
#
# :: Automated regression tests: create a tox network and run integration tests
#
################################################################################

set(TEST_TIMEOUT_SECONDS "" CACHE STRING "Limit runtime of each test to the number of seconds specified")

option(FORMAT_TEST "Require the format_test to be executed; fail cmake if it can't" OFF)

if(APIDSL AND ASTYLE)
  add_test(
    NAME format_test
    COMMAND ${toxcore_SOURCE_DIR}/other/astyle/format-source
      "${toxcore_SOURCE_DIR}"
      "${APIDSL}"
      "${ASTYLE}")
  set_tests_properties(format_test PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
elseif(FORMAT_TEST)
  message(FATAL_ERROR "format_test can not be run, because either APIDSL (${APIDSL}) or ASTYLE (${ASTYLE}) could not be found")
endif()

function(auto_test target)
  if(NOT (MSVC AND ARGV1 STREQUAL "MSVC_DONT_BUILD"))
    add_executable(auto_${target}_test auto_tests/${target}_test.c)
    target_link_modules(auto_${target}_test toxcore)
    if(NOT ARGV1 STREQUAL "DONT_RUN")
      add_test(NAME ${target} COMMAND ${CROSSCOMPILING_EMULATOR} auto_${target}_test)
      set_tests_properties(${target} PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
    endif()
  endif()
endfunction()

if(BUILD_TOXAV)
  add_definitions(-D__STDC_LIMIT_MACROS=1)
  add_executable(auto_monolith_test
    auto_tests/monolith_test.cpp
    ${ANDROID_CPU_FEATURES})
  target_link_libraries(auto_monolith_test ${toxcore_LINK_MODULES})
  add_test(NAME monolith COMMAND ${CROSSCOMPILING_EMULATOR} auto_monolith_test)

  if(ANDROID_CPU_FEATURES)
    target_compile_definitions(auto_monolith_test PRIVATE -Dtypeof=__typeof__)
  endif()
endif()

auto_test(TCP)
auto_test(bootstrap)
auto_test(conference)
auto_test(crypto                        MSVC_DONT_BUILD)
auto_test(dht                           MSVC_DONT_BUILD)
auto_test(encryptsave)
auto_test(file_transfer)
auto_test(friend_request)
auto_test(lan_discovery)
auto_test(lossless_packet)
auto_test(lossy_packet)
auto_test(messenger                     MSVC_DONT_BUILD)
auto_test(network)
auto_test(onion)
auto_test(resource_leak)
auto_test(save_friend)
auto_test(save_load)
auto_test(send_message)
auto_test(set_name)
auto_test(set_status_message)
auto_test(simple_conference)
auto_test(skeleton)
auto_test(tox_many)
auto_test(tox_many_tcp)
auto_test(tox_one)
auto_test(tox_strncasecmp)
auto_test(typing)
auto_test(version)
# TODO(iphydf): These tests are broken. The code needs to be fixed, as the
# tests themselves are correct.
auto_test(selfname_change_conference    DONT_RUN)
auto_test(self_conference_title_change  DONT_RUN)

if(BUILD_TOXAV)
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
  target_link_modules(DHT_bootstrap toxcore)
endif()

option(BOOTSTRAP_DAEMON "Enable building of tox-bootstrapd" ON)
if(BOOTSTRAP_DAEMON AND WIN32)
  message(WARNING "Building tox-bootstrapd for Windows is not supported")
  set(BOOTSTRAP_DAEMON OFF)
endif()
if(BOOTSTRAP_DAEMON)
  if(LIBCONFIG_FOUND)
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
  endif()
endif()

################################################################################
#
# :: Test programs
#
################################################################################

option(BUILD_AV_TEST "Build toxav test" ON)
if(NOT WIN32
  AND BUILD_AV_TEST AND BUILD_TOXAV
  AND SNDFILE_FOUND AND PORTAUDIO_FOUND AND OPENCV_FOUND)
  add_executable(av_test testing/av_test.c)
  target_link_modules(av_test
    toxcore
    ${OPENCV_LIBRARIES}
    ${PORTAUDIO_LIBRARIES}
    ${SNDFILE_LIBRARIES})
  # Due to https://github.com/opencv/opencv/issues/6585, we need to compile
  # av_test as C++ for newer OpenCV versions.
  if(NOT OPENCV_VERSION VERSION_LESS 3)
    set_source_files_properties(testing/av_test.c PROPERTIES LANGUAGE CXX)
  endif()
endif()

add_executable(DHT_test testing/DHT_test.c)
target_link_modules(DHT_test toxcore)

add_executable(Messenger_test testing/Messenger_test.c)
target_link_modules(Messenger_test toxcore)
