###############################################################################
#
# :: For systems that have pkg-config.
#
###############################################################################

find_package(PkgConfig REQUIRED)

find_library(NSL_LIBRARIES    nsl   )
find_library(RT_LIBRARIES     rt    )
find_library(SOCKET_LIBRARIES socket)

find_package(pthreads QUIET)
if(NOT TARGET PThreads4W::PThreads4W)
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
endif()

# For toxcore.
pkg_search_module(LIBSODIUM   libsodium IMPORTED_TARGET REQUIRED)
if(MSVC)
  find_package(unofficial-sodium REQUIRED)
endif()

# For toxav.
pkg_search_module(OPUS        opus      IMPORTED_TARGET)
if(NOT OPUS_FOUND)
  pkg_search_module(OPUS      Opus      IMPORTED_TARGET)
endif()
pkg_search_module(VPX         vpx       IMPORTED_TARGET)
if(NOT VPX_FOUND)
  pkg_search_module(VPX       libvpx    IMPORTED_TARGET)
endif()

# For tox-bootstrapd.
pkg_search_module(LIBCONFIG   libconfig IMPORTED_TARGET)
