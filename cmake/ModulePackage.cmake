option(ENABLE_SHARED "Build shared (dynamic) libraries for all modules" ON)
option(ENABLE_STATIC "Build static libraries for all modules" ON)
option(COMPILE_AS_CXX "Compile all C code as C++ code" OFF)

include(FindPackageHandleStandardArgs)

if(NOT ENABLE_SHARED AND NOT ENABLE_STATIC)
  message(WARNING
    "Both static and shared libraries are disabled; "
    "enabling only shared libraries. Use -DENABLE_SHARED or -DENABLE_STATIC to "
    "select one manually.")
  set(ENABLE_SHARED ON)
endif()

find_package(PkgConfig)

if(COMPILE_AS_CXX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_FORMAT_MACROS=1")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_LIMIT_MACROS=1")
endif()

macro(set_source_language)
  if(COMPILE_AS_CXX)
    foreach(srcfile ${ARGN})
      get_filename_component(srcext ${srcfile} EXT)
      if(${srcext} STREQUAL ".c")
        set_source_files_properties(${srcfile} PROPERTIES LANGUAGE CXX)
      endif()
    endforeach()
  endif()
endmacro()

function(add_c_executable exec)
  set_source_language(${ARGN})

  add_executable(${exec} ${ARGN})
endfunction()

function(pkg_use_module mod pkg)
  if(PKG_CONFIG_FOUND)
    pkg_search_module(${mod} ${pkg})
  endif()
  if(${mod}_FOUND)
    link_directories(${${mod}_LIBRARY_DIRS})
    include_directories(${${mod}_INCLUDE_DIRS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)

    foreach(dir ${${mod}_INCLUDE_DIRS})
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isystem ${dir}" PARENT_SCOPE)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem ${dir}" PARENT_SCOPE)
    endforeach()
  else()
    set(${mod}_DEFINITIONS ${${mod}_CFLAGS_OTHER})
    find_path(${mod}_INCLUDE_DIR NAMES ${ARGV1}.h
      HINTS ${${mod}_INCLUDEDIR} ${${mod}_INCLUDE_DIRS}
      PATH_SUFFIXES ${ARGV1})
    find_library(${mod}_LIBRARY NAMES ${ARGV1} lib${ARGV1}
      HINTS ${${mod}_LIBDIR} ${${mod}_LIBRARY_DIRS})
    find_package_handle_standard_args(${mod} DEFAULT_MSG
      ${mod}_LIBRARY ${mod}_INCLUDE_DIR)

    if(${mod}_FOUND)
      mark_as_advanced(${mod}_INCLUDE_DIR ${mod}_LIBRARY)
      set(${mod}_LIBRARIES ${${mod}_LIBRARY} PARENT_SCOPE)
      set(${mod}_INCLUDE_DIRS ${${mod}_INCLUDE_DIR} PARENT_SCOPE)
      set(${mod}_FOUND TRUE PARENT_SCOPE)
      link_directories(${${mod}_LIBRARY_DIRS})
      include_directories(${${mod}_INCLUDE_DIRS})
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)

      foreach(dir ${${mod}_INCLUDE_DIRS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isystem ${dir}" PARENT_SCOPE)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem ${dir}" PARENT_SCOPE)
      endforeach()
    endif()
  endif()
endfunction()

function(add_module lib)
  set_source_language(${ARGN})

  if(ENABLE_SHARED)
    add_library(${lib}_shared SHARED ${ARGN})
    set_target_properties(${lib}_shared PROPERTIES
      OUTPUT_NAME ${lib}
      VERSION ${SOVERSION}
      SOVERSION ${SOVERSION_MAJOR}
    )
    install(TARGETS ${lib}_shared DESTINATION "lib")
  endif()
  if(ENABLE_STATIC)
    add_library(${lib}_static STATIC ${ARGN})
    set_target_properties(${lib}_static PROPERTIES OUTPUT_NAME ${lib})
    install(TARGETS ${lib}_static DESTINATION "lib")
  endif()
endfunction()

function(target_link_modules target)
  if(TARGET ${target}_shared)
    set(_targets ${_targets} ${target}_shared)
  endif()
  if(TARGET ${target}_static)
    set(_targets ${_targets} ${target}_static)
  endif()
  if(NOT _targets)
    set(_targets ${_targets} ${target})
  endif()

  foreach(target ${_targets})
    foreach(dep ${ARGN})
      if(TARGET ${dep}_shared)
        target_link_libraries(${target} ${dep}_shared)
      elseif(TARGET ${dep}_static)
        target_link_libraries(${target} ${dep}_static)
      else()
        target_link_libraries(${target} ${dep})
      endif()
    endforeach()
  endforeach()
endfunction()
