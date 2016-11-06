cmake_minimum_required(VERSION 2.8.6)
project(toxcore)
include(CTest)

# This version is for the entire project. All libraries (core, av, ...) move in
# versions in a synchronised way.
set(PROJECT_VERSION_MAJOR "0")
set(PROJECT_VERSION_MINOR "0")
set(PROJECT_VERSION_PATCH "3")
set(PROJECT_VERSION
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

################################################################################
#
# :: Dependencies and configuration
#
################################################################################

include(ApiDsl)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(MacRpath)
include(ModulePackage)

set(CMAKE_MACOSX_RPATH ON)

function(add_cflag flag)
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_C${var})
    message(STATUS "checking for C compiler flag: ${flag}")
  endif()
  set(CMAKE_REQUIRED_QUIET TRUE)

  check_c_compiler_flag("${flag}" HAVE_C${var} QUIET)
  if(HAVE_C${var})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function(add_cxxflag flag)
  string(REGEX REPLACE "[^a-zA-Z0-9_]" "_" var ${flag})
  if(NOT DEFINED HAVE_CXX${var})
    message(STATUS "checking for C++ compiler flag: ${flag}")
  endif()
  set(CMAKE_REQUIRED_QUIET TRUE)

  check_cxx_compiler_flag("${flag}" HAVE_CXX${var} QUIET)
  if(HAVE_CXX${var})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

macro(add_flag flag)
  add_cflag(${flag})
  add_cxxflag(${flag})
endmacro()

option(WARNINGS "Enable additional compiler warnings" ON)
if(WARNINGS)
  # Set standard version for compiler.
  add_cflag("-std=gnu99")
  add_cxxflag("-std=c++98")

  # Add all warning flags we can.
  add_flag("-Wall")
  add_flag("-Wextra")
  add_flag("-Weverything")
  add_flag("-pedantic")

  # Set error-on-warn for C compilation. C++ compilation can't use this because
  # treating 'c' input as 'c++' when in C++ mode is deprecated in clang and
  # there is no way to turn that warning off.
  add_cflag("-Werror")

  # Disable specific warning flags for both C and C++.
  add_flag("-Wno-cast-align")
  add_flag("-Wno-conversion")
  add_flag("-Wno-covered-switch-default")
  add_flag("-Wno-format-nonliteral")
  add_flag("-Wno-missing-field-initializers")
  add_flag("-Wno-missing-prototypes")
  add_flag("-Wno-padded")
  add_flag("-Wno-sign-compare")
  add_flag("-Wno-sign-conversion")
  add_flag("-Wno-tautological-constant-out-of-range-compare")
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
  add_cflag("-Wno-reserved-id-macro")
  add_cflag("-Wno-shadow")
  add_cflag("-Wno-shorten-64-to-32")
  add_cflag("-Wno-unreachable-code-return")
  add_cflag("-Wno-used-but-marked-unused")

  # Disable specific warning flags for C++.
  add_cxxflag("-Wno-c++11-compat-reserved-user-defined-literal")
  add_cxxflag("-Wno-c++11-extensions")
  add_cxxflag("-Wno-c++11-narrowing")
  add_cxxflag("-Wno-c99-extensions")
  add_cxxflag("-Wno-old-style-cast")
  add_cxxflag("-Wno-variadic-macros")
  add_cxxflag("-Wno-vla-extension")
endif()

option(DEBUG "Enable assertions and other debugging facilities" OFF)
if(DEBUG)
  set(MIN_LOGGER_LEVEL DEBUG)
  add_definitions(-DTOX_DEBUG=1)
  add_cflag("-g3")
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
  toxcore/crypto_core.c
  toxcore/crypto_core.h)
target_link_modules(toxcrypto ${LIBSODIUM_LIBRARIES})
if(WIN32)
  target_link_modules(toxcrypto ws2_32) # for htonl
endif()

# LAYER 2: Basic networking
# -------------------------
add_module(toxnetwork
  toxcore/logger.c
  toxcore/logger.h
  toxcore/network.c
  toxcore/network.h
  toxcore/util.c
  toxcore/util.h)
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
  toxcore/DHT.h
  toxcore/LAN_discovery.c
  toxcore/LAN_discovery.h
  toxcore/ping.c
  toxcore/ping.h
  toxcore/ping_array.c
  toxcore/ping_array.h)
target_link_modules(toxdht toxnetwork)

# LAYER 4: Onion routing, TCP connections, crypto connections
# -----------------------------------------------------------
add_module(toxnetcrypto
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
target_link_modules(toxnetcrypto toxdht)

# LAYER 5: Friend requests and connections
# ----------------------------------------
add_module(toxfriends
  toxcore/friend_connection.c
  toxcore/friend_connection.h
  toxcore/friend_requests.c
  toxcore/friend_requests.h)
target_link_modules(toxfriends toxnetcrypto)

# LAYER 6: Tox messenger
# ----------------------
add_module(toxmessenger
  toxcore/Messenger.c
  toxcore/Messenger.h)
target_link_modules(toxmessenger toxfriends)

# LAYER 7: Group chats
# --------------------
add_module(toxgroup
  toxcore/group.c
  toxcore/group.h)
target_link_modules(toxgroup toxmessenger)

# LAYER 8: Public API
# -------------------
apidsl(
  toxcore/tox.api.h)
add_module(toxcore
  toxcore/misc_tools.h
  toxcore/tox.c
  toxcore/tox.h)
target_link_modules(toxcore toxgroup)

################################################################################
#
# :: Audio/Video Library
#
################################################################################

if(BUILD_TOXAV)
  apidsl(
    toxav/toxav.api.h)
  add_module(toxav
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

set(TEST_TIMEOUT_SECONDS "" CACHE STRING "Limit runtime of each test to the number of seconds specified")

option(FORMAT_TEST "Require the format_test to be executed; fail cmake if it can't" OFF)

if(APIDSL AND ASTYLE)
  add_test(
    NAME format_test
    COMMAND ${CMAKE_SOURCE_DIR}/other/astyle/format-source
      "${CMAKE_SOURCE_DIR}"
      "${APIDSL}"
      "${ASTYLE}")
  set_tests_properties(format_test PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
elseif(FORMAT_TEST)
  message(FATAL_ERROR "format_test can not be run, because either APIDSL (${APIDSL}) or ASTYLE (${ASTYLE}) could not be found")
endif()

function(auto_test target)
  if(CHECK_FOUND)
    add_c_executable(auto_${target}_test auto_tests/${target}_test.c)
    target_link_modules(auto_${target}_test
      toxcore
      toxencryptsave
      ${CHECK_LIBRARIES})
    if(BUILD_TOXAV)
      target_link_modules(auto_${target}_test toxav)
    endif()
    add_test(NAME ${target} COMMAND auto_${target}_test)
    set_tests_properties(${target} PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
  endif()
endfunction()

auto_test(TCP)
auto_test(conference)
auto_test(crypto)
auto_test(dht)
auto_test(encryptsave)
auto_test(messenger)
auto_test(network)
auto_test(onion)
auto_test(skeleton)
auto_test(tox)
auto_test(tox_many)
auto_test(tox_many_tcp)
auto_test(tox_one)
if(BUILD_TOXAV)
  auto_test(toxav_basic)
  auto_test(toxav_many)
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

option(BOOTSTRAP_DAEMON "Enable building of tox-bootstrapd" ON)
if(BOOTSTRAP_DAEMON)
  if(WIN32)
    message(FATAL_ERROR "Building tox-bootstrapd for Windows is not supported")
  endif()
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
  # Due to https://github.com/opencv/opencv/issues/6585, we need to compile
  # av_test as C++ for newer OpenCV versions.
  if(NOT OPENCV_VERSION VERSION_LESS 3)
    set_source_files_properties(testing/av_test.c PROPERTIES LANGUAGE CXX)
  endif()
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
# :: Update versions in various places
#
################################################################################

find_program(SH NAMES sh dash bash zsh)

if(SH)
  execute_process(
    COMMAND ${SH} ${CMAKE_SOURCE_DIR}/other/version-sync
      ${CMAKE_SOURCE_DIR}
      ${PROJECT_VERSION_MAJOR}
      ${PROJECT_VERSION_MINOR}
      ${PROJECT_VERSION_PATCH})
endif()

################################################################################
#
# :: Strict ABI
#
################################################################################

function(make_version_script header ns lib)
  execute_process(
    COMMAND ${SH} -c "egrep '^\\w' ${header} | grep '${ns}_[a-z0-9_]*(' | grep -v '^typedef' | grep -o '${ns}_[a-z0-9_]*(' | egrep -o '\\w+' | sort -u"
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

if(STRICT_ABI AND SH)
  if(BUILD_TOXAV)
    make_version_script(${CMAKE_SOURCE_DIR}/toxav/toxav.h toxav toxav)
  endif()
  make_version_script(${CMAKE_SOURCE_DIR}/toxcore/tox.h tox toxcore)
endif()
