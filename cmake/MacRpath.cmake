# Taken from https://cmake.org/Wiki/CMake_RPATH_handling#Always_full_RPATH.
#
# In many cases you will want to make sure that the required libraries are
# always found independent from LD_LIBRARY_PATH and the install location. Then
# you can use these settings:

# Use, i.e. don't skip the full RPATH for the build tree.
set(CMAKE_SKIP_BUILD_RPATH FALSE)

# When building, don't use the install RPATH already
# (but later on when installing).
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# Add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH.
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# The RPATH to be used when installing, but only if it's not a system directory.
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif()
