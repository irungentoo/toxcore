option(ENABLE_SHARED "Build shared (dynamic) libraries for all modules" ON)
option(ENABLE_STATIC "Build static libraries for all modules" ON)

if(NOT ENABLE_SHARED AND NOT ENABLE_STATIC)
  message(WARNING
    "Both static and shared libraries are disabled; "
    "enabling only shared libraries. Use -DENABLE_SHARED or -DENABLE_STATIC to "
    "select one manually.")
  set(ENABLE_SHARED ON)
endif()

option(FULLY_STATIC "Build fully static executables" OFF)
if(FULLY_STATIC)
  set(CMAKE_EXE_LINKER_FLAGS "-static -no-pie")
  # remove -Wl,-Bdynamic
  set(CMAKE_EXE_LINK_DYNAMIC_C_FLAGS)
  set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS)
  set(ENABLE_SHARED OFF)
  set(ENABLE_STATIC ON)
endif()

find_package(PkgConfig)

function(pkg_use_module mod pkgs)
  foreach(pkg IN ITEMS ${pkgs})
    if(PKG_CONFIG_FOUND)
      pkg_search_module(${mod} ${pkg})
    endif()
    if(NOT ${mod}_FOUND)
      find_package(${pkg} QUIET)
      # This is very very ugly, but the variables are sometimes used in this scope
      # and sometimes in the parent scope, so we have to set them to both places.
      set(${mod}_FOUND ${${pkg}_FOUND})
      set(${mod}_FOUND ${${pkg}_FOUND} PARENT_SCOPE)
      set(${mod}_LIBRARIES ${${pkg}_LIBS})
      set(${mod}_LIBRARIES ${${pkg}_LIBS} PARENT_SCOPE)
      set(${mod}_LIBRARY_DIRS ${${pkg}_LIBRARY_DIRS})
      set(${mod}_LIBRARY_DIRS ${${pkg}_LIBRARY_DIRS} PARENT_SCOPE)
      set(${mod}_INCLUDE_DIRS ${${pkg}_INCLUDE_DIRS})
      set(${mod}_INCLUDE_DIRS ${${pkg}_INCLUDE_DIRS} PARENT_SCOPE)
    endif()
    if(${mod}_FOUND)
      link_directories(${${mod}_LIBRARY_DIRS})
      include_directories(${${mod}_INCLUDE_DIRS})
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${${mod}_CFLAGS_OTHER}" PARENT_SCOPE)

      if(NOT MSVC)
        foreach(dir ${${mod}_INCLUDE_DIRS})
          set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isystem ${dir}" PARENT_SCOPE)
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem ${dir}" PARENT_SCOPE)
        endforeach()
      endif()
      break()
    endif()
  endforeach()
endfunction()

function(add_module lib)
  set(${lib}_SOURCES ${ARGN} PARENT_SCOPE)

  if(ENABLE_SHARED)
    add_library(${lib}_shared SHARED ${ARGN})
    set_target_properties(${lib}_shared PROPERTIES OUTPUT_NAME ${lib})
  endif()
  if(ENABLE_STATIC)
    add_library(${lib}_static STATIC ${ARGN})
    set_target_properties(${lib}_static PROPERTIES OUTPUT_NAME ${lib})
  endif()
endfunction()

function(install_module lib)
  if(ENABLE_SHARED)
    set_target_properties(${lib}_shared PROPERTIES
      VERSION ${SOVERSION}
      SOVERSION ${SOVERSION_MAJOR}
    )
    install(TARGETS ${lib}_shared
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
  if(ENABLE_STATIC)
    install(TARGETS ${lib}_static
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  string(REPLACE ";" " " ${lib}_PKGCONFIG_LIBS "${${lib}_PKGCONFIG_LIBS}")
  string(REPLACE ";" " " ${lib}_PKGCONFIG_REQUIRES "${${lib}_PKGCONFIG_REQUIRES}")

  configure_file(
    "${${lib}_SOURCE_DIR}/other/pkgconfig/${lib}.pc.in"
    "${CMAKE_BINARY_DIR}/${lib}.pc"
    @ONLY
  )

  configure_file(
    "${toxcore_SOURCE_DIR}/other/rpm/${lib}.spec.in"
    "${CMAKE_BINARY_DIR}/${lib}.spec"
    @ONLY
  )

  install(FILES
    ${CMAKE_BINARY_DIR}/${lib}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  foreach(sublib ${${lib}_API_HEADERS})
    string(REPLACE "^" ";" sublib ${sublib})
    list(GET sublib 0 header)

    install(FILES ${header} ${ARGN})
  endforeach()
endfunction()

function(target_link_modules target)
  # If the target we're adding dependencies to is a shared library, add it to
  # the set of targets.
  if(TARGET ${target}_shared)
    set(_targets ${_targets} ${target}_shared)
    # Shared libraries should first try to link against other shared libraries.
    set(${target}_shared_primary shared)
    # If that fails (because the shared target doesn't exist), try linking
    # against the static library. This requires the static library's objects to
    # be PIC.
    set(${target}_shared_secondary static)
  endif()
  # It can also be a static library at the same time.
  if(TARGET ${target}_static)
    set(_targets ${_targets} ${target}_static)
    # Static libraries aren't actually linked, but their dependencies are
    # recorded by "linking" them. If we link an executable to a static library,
    # we want to also link statically against its transitive dependencies.
    set(${target}_static_primary static)
    # If a dependency doesn't exist as static library, we link against the
    # shared one.
    set(${target}_static_secondary shared)
  endif()
  # If it's neither, then it's an executable.
  if(NOT _targets)
    set(_targets ${_targets} ${target})
    # Executables preferably link against static libraries, so they are
    # standalone and can be shipped without any external dependencies. As a
    # frame of reference: tests become roughly 600-800K binaries instead of
    # 50-100K on x86_64 Linux.
    set(${target}_primary static)
    set(${target}_secondary shared)
  endif()

  foreach(dep ${ARGN})
    foreach(_target ${_targets})
      if(TARGET ${dep}_${${_target}_primary})
        target_link_libraries(${_target} ${dep}_${${_target}_primary})
      elseif(TARGET ${dep}_${${_target}_secondary})
        target_link_libraries(${_target} ${dep}_${${_target}_secondary})
      else()
        # We record the modules linked to this target, so that we can collect
        # them later when linking a composed module.
        list(FIND LINK_MODULES ${dep} _index)
        if(_index EQUAL -1)
          set(LINK_MODULES ${LINK_MODULES} ${dep})
        endif()

        target_link_libraries(${_target} ${dep})
      endif()
    endforeach()
  endforeach()

  set(${target}_LINK_MODULES ${${target}_LINK_MODULES} ${LINK_MODULES} PARENT_SCOPE)
endfunction()
