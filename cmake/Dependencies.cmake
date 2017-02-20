###############################################################################
#
# :: For UNIX-like systems that have pkg-config.
#
###############################################################################

include(ModulePackage)

find_package(Threads REQUIRED)

find_library(NCURSES_LIBRARIES      ncurses      )
find_library(UTIL_LIBRARIES         util         )
find_library(RT_LIBRARIES           rt           )

# For toxcore.
pkg_use_module(LIBSODIUM            libsodium    )

# For toxav.
pkg_use_module(OPUS                 opus         )
pkg_use_module(VPX                  vpx          )

# For tox-bootstrapd.
pkg_use_module(LIBCONFIG            libconfig    )

# For auto tests.
pkg_use_module(CHECK                check        )

# For tox-spectest.
pkg_use_module(MSGPACK              msgpack      )

# For av_test.
pkg_use_module(OPENCV               opencv       )
pkg_use_module(PORTAUDIO            portaudio-2.0)
pkg_use_module(SNDFILE              sndfile      )

###############################################################################
#
# :: For Windows and other systems lacking pkg-config.
#
###############################################################################

if(NOT LIBSODIUM_FOUND)
  include_directories(libsodium/include)
  find_library(LIBSODIUM_LIBRARIES
    NAMES
      sodium
      libsodium
    PATHS
      libsodium/Win32/Release/v140/static
      libsodium/x64/Release/v140/static
  )
  if(LIBSODIUM_LIBRARIES)
    set(LIBSODIUM_FOUND TRUE)
  endif()
  add_definitions(-DSODIUM_STATIC)
  message("libsodium: ${LIBSODIUM_LIBRARIES}")
endif()

if(("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC") AND CMAKE_USE_WIN32_THREADS_INIT)
  include_directories(pthreads-win32/Pre-built.2/include)
  find_library(CMAKE_THREAD_LIBS_INIT
    NAMES
      pthreadVC2
    PATHS
      pthreads-win32/Pre-built.2/lib/x86
      pthreads-win32/Pre-built.2/lib/x64
  )
  add_definitions(-DHAVE_STRUCT_TIMESPEC)
  message("libpthreads: ${CMAKE_THREAD_LIBS_INIT}")
endif()
