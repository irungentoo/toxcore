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

function(install_module lib)
  if(TARGET ${lib}_shared)
    set_target_properties(${lib}_shared PROPERTIES
      VERSION ${SOVERSION}
      SOVERSION ${SOVERSION_MAJOR}
    )
    install(TARGETS ${lib}_shared
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()
  if(TARGET ${lib}_static)
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
