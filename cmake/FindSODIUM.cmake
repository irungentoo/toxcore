# - Try to find SODIUM
# Once done this will define
#
#  SODIUM_ROOT_DIR - Set this variable to the root installation of CMocka
#
# Read-Only variables:
#  SODIUM_FOUND - system has SODIUM
#  SODIUM_INCLUDE_DIR - the SODIUM include directory
#  SODIUM_LIBRARIES - Link these to use SODIUM
#  SODIUM_DEFINITIONS - Compiler switches required for using SODIUM
#
#=============================================================================
#  Copyright (c) 2013 Andreas Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

set(_SODIUM_ROOT_HINTS
)

set(_SODIUM_ROOT_PATHS
    "$ENV{PROGRAMFILES}/sodium"
    "${CMAKE_SOURCE_DIR}/sodium"
)

find_path(SODIUM_ROOT_DIR
    NAMES
        include/sodium.h
    HINTS
        ${_SODIUM_ROOT_HINTS}
    PATHS
        ${_SODIUM_ROOT_PATHS}
)
mark_as_advanced(SODIUM_ROOT_DIR)

find_path(SODIUM_INCLUDE_DIR
    NAMES
        sodium.h
    PATHS
        ${SODIUM_ROOT_DIR}/include
)

if(SHARED_LIBSODIUM)
        set(WIN32_LIBSODIUM_FILENAME libsodium.dll.a)
else()
        set(WIN32_LIBSODIUM_FILENAME libsodium.a)
endif()

find_library(SODIUM_LIBRARY
    NAMES
        sodium
        ${WIN32_LIBSODIUM_FILENAME}
    PATHS
        ${SODIUM_ROOT_DIR}/lib
)

if (SODIUM_LIBRARY)
    set(SODIUM_LIBRARIES
        ${SODIUM_LIBRARIES}
        ${SODIUM_LIBRARY}
    )
endif (SODIUM_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SODIUM DEFAULT_MSG SODIUM_LIBRARIES SODIUM_INCLUDE_DIR)

# show the SODIUM_INCLUDE_DIR and SODIUM_LIBRARIES variables only in the advanced view
mark_as_advanced(SODIUM_INCLUDE_DIR SODIUM_LIBRARIES)

