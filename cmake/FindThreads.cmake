# Updated FindThreads.cmake that supports pthread-win32
# Downloaded from http://www.vtk.org/Bug/bug_view_advanced_page.php?bug_id=6399

# - This module determines the thread library of the system.
#
# The following variables are set
#  CMAKE_THREAD_LIBS_INIT     - the thread library
#  CMAKE_USE_SPROC_INIT       - are we using sproc?
#  CMAKE_USE_WIN32_THREADS_INIT - using WIN32 threads?
#  CMAKE_USE_PTHREADS_INIT    - are we using pthreads
#  CMAKE_HP_PTHREADS_INIT     - are we using hp pthreads
#
# If use of pthreads-win32 is desired, the following variables
# can be set.
#
#  THREADS_USE_PTHREADS_WIN32 -
#    Setting this to true searches for the pthreads-win32
#    port (since CMake 2.8.0)
#
#  THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME
#      C  = no exceptions (default)
#         (NOTE: This is the default scheme on most POSIX thread
#          implementations and what you should probably be using)
#      CE = C++ Exception Handling
#      SE = Structure Exception Handling (MSVC only)
#      (NOTE: Changing this option from the default may affect
#       the portability of your application.  See pthreads-win32
#       documentation for more details.)
#
#======================================================
# Example usage where threading library
# is provided by the system:
#
#   find_package(Threads REQUIRED)
#   add_executable(foo foo.cc)
#   target_link_libraries(foo ${CMAKE_THREAD_LIBS_INIT})
#
# Example usage if pthreads-win32 is desired on Windows
# or a system provided thread library:
#
#   set(THREADS_USE_PTHREADS_WIN32 true)
#   find_package(Threads REQUIRED)
#   include_directories(${THREADS_PTHREADS_INCLUDE_DIR})
#
#   add_executable(foo foo.cc)
#   target_link_libraries(foo ${CMAKE_THREAD_LIBS_INIT})
#

INCLUDE (CheckIncludeFiles)
INCLUDE (CheckLibraryExists)
SET(Threads_FOUND FALSE)

IF(WIN32 AND NOT CYGWIN AND THREADS_USE_PTHREADS_WIN32)
  SET(_Threads_ptwin32 true)
ENDIF()

# Do we have sproc?
IF(CMAKE_SYSTEM MATCHES IRIX)
  CHECK_INCLUDE_FILES("sys/types.h;sys/prctl.h"  CMAKE_HAVE_SPROC_H)
ENDIF()

IF(CMAKE_HAVE_SPROC_H)
  # We have sproc
  SET(CMAKE_USE_SPROC_INIT 1)

ELSEIF(_Threads_ptwin32)

  IF(NOT DEFINED THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME)
    # Assign the default scheme
    SET(THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME "C")
  ELSE()
    # Validate the scheme specified by the user
    IF(NOT THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME STREQUAL "C" AND
       NOT THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME STREQUAL "CE" AND
       NOT THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME STREQUAL "SE")
         MESSAGE(FATAL_ERROR "See documentation for FindPthreads.cmake, only C, CE, and SE modes are allowed")
    ENDIF()
    IF(NOT MSVC AND THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME STREQUAL "SE")
      MESSAGE(FATAL_ERROR "Structured Exception Handling is only allowed for MSVC")
    ENDIF(NOT MSVC AND THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME STREQUAL "SE")
  ENDIF()

  FIND_PATH(THREADS_PTHREADS_INCLUDE_DIR pthread.h)
  
  # Determine the library filename
  IF(MSVC)
    SET(_Threads_pthreads_libname
        pthreadV${THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME}2)
  ELSEIF(MINGW)
    SET(_Threads_pthreads_libname
        pthreadG${THREADS_PTHREADS_WIN32_EXCEPTION_SCHEME}2)
  ELSE()
    MESSAGE(FATAL_ERROR "This should never happen")
  ENDIF()

  # Use the include path to help find the library if possible
  SET(_Threads_lib_paths "")
  IF(THREADS_PTHREADS_INCLUDE_DIR)
     GET_FILENAME_COMPONENT(_Threads_root_dir
                            ${THREADS_PTHREADS_INCLUDE_DIR} PATH)
     SET(_Threads_lib_paths ${_Threads_root_dir}/lib)
  ENDIF()
  FIND_LIBRARY(THREADS_PTHREADS_WIN32_LIBRARY
               NAMES ${_Threads_pthreads_libname}
               PATHS ${_Threads_lib_paths}
               DOC "The Portable Threads Library for Win32"
               NO_SYSTEM_PATH
               )

  IF(THREADS_PTHREADS_INCLUDE_DIR AND THREADS_PTHREADS_WIN32_LIBRARY)
    MARK_AS_ADVANCED(THREADS_PTHREADS_INCLUDE_DIR)
    SET(CMAKE_THREAD_LIBS_INIT ${THREADS_PTHREADS_WIN32_LIBRARY})
    SET(CMAKE_HAVE_THREADS_LIBRARY 1)
    SET(Threads_FOUND TRUE)
  ENDIF()

  MARK_AS_ADVANCED(THREADS_PTHREADS_WIN32_LIBRARY)

ELSE()
  # Do we have pthreads?
  CHECK_INCLUDE_FILES("pthread.h" CMAKE_HAVE_PTHREAD_H)
  IF(CMAKE_HAVE_PTHREAD_H)

    #
    # We have pthread.h
    # Let's check for the library now.
    #
    SET(CMAKE_HAVE_THREADS_LIBRARY)
    IF(NOT THREADS_HAVE_PTHREAD_ARG)

      # Do we have -lpthreads
      CHECK_LIBRARY_EXISTS(pthreads pthread_create "" CMAKE_HAVE_PTHREADS_CREATE)
      IF(CMAKE_HAVE_PTHREADS_CREATE)
        SET(CMAKE_THREAD_LIBS_INIT "-lpthreads")
        SET(CMAKE_HAVE_THREADS_LIBRARY 1)
        SET(Threads_FOUND TRUE)
      ENDIF()

      # Ok, how about -lpthread
      CHECK_LIBRARY_EXISTS(pthread pthread_create "" CMAKE_HAVE_PTHREAD_CREATE)
      IF(CMAKE_HAVE_PTHREAD_CREATE)
        SET(CMAKE_THREAD_LIBS_INIT "-lpthread")
        SET(Threads_FOUND TRUE)
        SET(CMAKE_HAVE_THREADS_LIBRARY 1)
      ENDIF()

      IF(CMAKE_SYSTEM MATCHES "SunOS.*")
        # On sun also check for -lthread
        CHECK_LIBRARY_EXISTS(thread thr_create "" CMAKE_HAVE_THR_CREATE)
        IF(CMAKE_HAVE_THR_CREATE)
          SET(CMAKE_THREAD_LIBS_INIT "-lthread")
          SET(CMAKE_HAVE_THREADS_LIBRARY 1)
          SET(Threads_FOUND TRUE)
        ENDIF()
      ENDIF(CMAKE_SYSTEM MATCHES "SunOS.*")

    ENDIF(NOT THREADS_HAVE_PTHREAD_ARG)

    IF(NOT CMAKE_HAVE_THREADS_LIBRARY)
      # If we did not found -lpthread, -lpthread, or -lthread, look for -pthread
      IF("THREADS_HAVE_PTHREAD_ARG" MATCHES "^THREADS_HAVE_PTHREAD_ARG")
        MESSAGE(STATUS "Check if compiler accepts -pthread")
        TRY_RUN(THREADS_PTHREAD_ARG THREADS_HAVE_PTHREAD_ARG
          ${CMAKE_BINARY_DIR}
          ${CMAKE_ROOT}/Modules/CheckForPthreads.c
          CMAKE_FLAGS -DLINK_LIBRARIES:STRING=-pthread
          COMPILE_OUTPUT_VARIABLE OUTPUT)

        IF(THREADS_HAVE_PTHREAD_ARG)
          IF(THREADS_PTHREAD_ARG MATCHES "^2$")
            SET(Threads_FOUND TRUE)
            MESSAGE(STATUS "Check if compiler accepts -pthread - yes")
          ELSE()
            MESSAGE(STATUS "Check if compiler accepts -pthread - no")
            FILE(APPEND 
              ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log 
              "Determining if compiler accepts -pthread returned ${THREADS_PTHREAD_ARG} instead of 2. The compiler had the following output:\n${OUTPUT}\n\n")
          ENDIF()
        ELSE()
          MESSAGE(STATUS "Check if compiler accepts -pthread - no")
          FILE(APPEND 
            ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log 
            "Determining if compiler accepts -pthread failed with the following output:\n${OUTPUT}\n\n")
        ENDIF()

      ENDIF("THREADS_HAVE_PTHREAD_ARG" MATCHES "^THREADS_HAVE_PTHREAD_ARG")

      IF(THREADS_HAVE_PTHREAD_ARG)
        SET(Threads_FOUND TRUE)
        SET(CMAKE_THREAD_LIBS_INIT "-pthread")
      ENDIF()

    ENDIF(NOT CMAKE_HAVE_THREADS_LIBRARY)
  ENDIF(CMAKE_HAVE_PTHREAD_H)
ENDIF()

IF(CMAKE_THREAD_LIBS_INIT)
  SET(CMAKE_USE_PTHREADS_INIT 1)
  SET(Threads_FOUND TRUE)
ENDIF()

IF(CMAKE_SYSTEM MATCHES "Windows"
   AND NOT THREADS_USE_PTHREADS_WIN32)
  SET(CMAKE_USE_WIN32_THREADS_INIT 1)
  SET(Threads_FOUND TRUE)
ENDIF()

IF(CMAKE_USE_PTHREADS_INIT)
  IF(CMAKE_SYSTEM MATCHES "HP-UX-*")
    # Use libcma if it exists and can be used.  It provides more
    # symbols than the plain pthread library.  CMA threads
    # have actually been deprecated:
    #   http://docs.hp.com/en/B3920-90091/ch12s03.html#d0e11395
    #   http://docs.hp.com/en/947/d8.html
    # but we need to maintain compatibility here.
    # The CMAKE_HP_PTHREADS setting actually indicates whether CMA threads
    # are available.
    CHECK_LIBRARY_EXISTS(cma pthread_attr_create "" CMAKE_HAVE_HP_CMA)
    IF(CMAKE_HAVE_HP_CMA)
      SET(CMAKE_THREAD_LIBS_INIT "-lcma")
      SET(CMAKE_HP_PTHREADS_INIT 1)
      SET(Threads_FOUND TRUE)
    ENDIF(CMAKE_HAVE_HP_CMA)
    SET(CMAKE_USE_PTHREADS_INIT 1)
  ENDIF()

  IF(CMAKE_SYSTEM MATCHES "OSF1-V*")
    SET(CMAKE_USE_PTHREADS_INIT 0)
    SET(CMAKE_THREAD_LIBS_INIT )
  ENDIF()

  IF(CMAKE_SYSTEM MATCHES "CYGWIN_NT*")
    SET(CMAKE_USE_PTHREADS_INIT 1)
    SET(Threads_FOUND TRUE)
    SET(CMAKE_THREAD_LIBS_INIT )
    SET(CMAKE_USE_WIN32_THREADS_INIT 0)
  ENDIF()
ENDIF(CMAKE_USE_PTHREADS_INIT)

INCLUDE(FindPackageHandleStandardArgs)
IF(_Threads_ptwin32)
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(Threads DEFAULT_MSG
    THREADS_PTHREADS_WIN32_LIBRARY THREADS_PTHREADS_INCLUDE_DIR)
ELSE()
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(Threads DEFAULT_MSG Threads_FOUND)
ENDIF()

if(THREADS_FOUND AND NOT TARGET Threads::Threads)
  add_library(Threads::Threads INTERFACE IMPORTED)

  if(CMAKE_THREAD_LIBS_INIT)
    set_property(TARGET Threads::Threads PROPERTY INTERFACE_LINK_LIBRARIES "${CMAKE_THREAD_LIBS_INIT}")
    set_property(TARGET Threads::Threads PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${THREADS_PTHREADS_INCLUDE_DIR}")
  endif()
endif()