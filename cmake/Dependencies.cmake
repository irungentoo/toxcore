###############################################################################
#
# :: For UNIX-like systems that have pkg-config.
#
###############################################################################

include(ModulePackage)

find_package(Threads REQUIRED)

find_library(NSL_LIBRARIES          nsl          )
find_library(RT_LIBRARIES           rt           )
find_library(SOCKET_LIBRARIES       socket       )

# For toxcore.
pkg_use_module(LIBSODIUM            libsodium    )

# For toxav.
pkg_use_module(OPUS                 opus         )
pkg_use_module(VPX                  vpx          )

# For tox-bootstrapd.
pkg_use_module(LIBCONFIG            libconfig    )

# For tox-spectest.
pkg_use_module(MSGPACK              msgpack      )

###############################################################################
#
# :: For MSVC Windows builds.
#
# These require specific installation paths of dependencies:
# - libsodium in third-party/libsodium/Win32/Release/v140/dynamic
# - pthreads in third-party/pthreads-win32/Pre-built.2
#
###############################################################################

if(MSVC)
  # libsodium
  # ---------
  find_library(LIBSODIUM_LIBRARIES
    NAMES sodium libsodium
    PATHS
      "third_party/libsodium/Win32/Release/v140/dynamic"
      "third_party/libsodium/x64/Release/v140/dynamic"
  )
  if(LIBSODIUM_LIBRARIES)
    include_directories("third_party/libsodium/include")
    set(LIBSODIUM_FOUND TRUE)
    message("libsodium: ${LIBSODIUM_LIBRARIES}")
  else()
    message(FATAL_ERROR "libsodium libraries not found")
  endif()

  # pthreads
  # --------
  if(CMAKE_USE_WIN32_THREADS_INIT)
    find_library(CMAKE_THREAD_LIBS_INIT
      NAMES pthreadVC2
      PATHS
        "third_party/pthreads-win32/Pre-built.2/lib/x86"
        "third_party/pthreads-win32/Pre-built.2/lib/x64"
    )
    if(CMAKE_THREAD_LIBS_INIT)
      include_directories("third_party/pthreads-win32/Pre-built.2/include")
      add_definitions(-DHAVE_STRUCT_TIMESPEC)
      message("libpthreads: ${CMAKE_THREAD_LIBS_INIT}")
    else()
      message(FATAL_ERROR "libpthreads libraries not found")
    endif()
  endif()
endif()
