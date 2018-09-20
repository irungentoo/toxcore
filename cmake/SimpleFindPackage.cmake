macro(simple_find_package pkg)
  set(oneValueArgs PKGCFG_NAME)
  set(multiValueArgs PATH_SUFFIXES INCLUDE_NAMES LIB_NAMES)
  cmake_parse_arguments(arg "" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_${pkg} QUIET ${arg_PKGCFG_NAME})

  find_path(${pkg}_INCLUDE_DIR
    NAMES ${arg_INCLUDE_NAMES}
    HINTS ${PC_${pkg}_INCLUDE_DIRS}
    PATH_SUFFIXES ${arg_PATH_SUFFIXES})

  find_library(${pkg}_LIBRARY
    NAMES ${arg_LIB_NAMES}
    HINTS ${PC_${pkg}_LIBRARY_DIRS})

  mark_as_advanced(${pkg}_LIBRARY ${pkg}_INCLUDE_DIR)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(${pkg} 
    FOUND_VAR ${pkg}_FOUND
    REQUIRED_VARS
      ${pkg}_LIBRARY
      ${pkg}_INCLUDE_DIR)

  if (${pkg}_FOUND)
    set(${pkg}_INCLUDE_DIRS ${${pkg}_INCLUDE_DIR})
    set(${pkg}_LIBRARIES ${${pkg}_LIBRARY})
  endif()

  if (${pkg}_FOUND AND NOT TARGET ${pkg}::${pkg})
    add_library(${pkg}::${pkg} UNKNOWN IMPORTED)
    set_target_properties(${pkg}::${pkg} PROPERTIES
      IMPORTED_LOCATION "${${pkg}_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${${pkg}_INCLUDE_DIR}")
  endif()
endmacro()
