################################################################################
#
# :: Strict ABI
#
# Enabling the STRICT_ABI flag will generate and use an LD version script.
# It ensures that the dynamic libraries (libtoxcore.so, libtoxav.so) only
# export the symbols that are defined in their public API (tox.h and toxav.h,
# respectively).
#
################################################################################

find_program(SHELL NAMES sh dash bash zsh fish)

macro(make_version_script)
  if(STRICT_ABI AND SHELL AND ENABLE_SHARED)
    _make_version_script(${ARGN})
  endif()
endmacro()

function(_make_version_script target)
  set(${target}_VERSION_SCRIPT "${CMAKE_BINARY_DIR}/${target}.ld")

  if(NOT APPLE)
    file(WRITE ${${target}_VERSION_SCRIPT}
      "{ global:\n")
  endif()

  foreach(sublib ${ARGN})
    string(REPLACE "^" ";" sublib ${sublib})
    list(GET sublib 0 header)
    list(GET sublib 1 ns)

    execute_process(
      COMMAND ${SHELL} -c "egrep '^\\w' ${header} | grep '${ns}_[a-z0-9_]*(' | grep -v '^typedef' | grep -o '${ns}_[a-z0-9_]*(' | egrep -o '[a-z0-9_]+' | sort -u"
      OUTPUT_VARIABLE sublib_SYMS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    if("${sublib_SYMS}" STREQUAL "")
      continue()
    endif()
    string(REPLACE "\n" ";" sublib_SYMS ${sublib_SYMS})

    foreach(sym ${sublib_SYMS})
      if(APPLE)
        file(APPEND ${${target}_VERSION_SCRIPT} "_")
      endif()
      file(APPEND ${${target}_VERSION_SCRIPT} "${sym}")
      if(NOT APPLE)
        file(APPEND ${${target}_VERSION_SCRIPT} ";")
      endif()
      file(APPEND ${${target}_VERSION_SCRIPT} "\n")
    endforeach(sym)
  endforeach(sublib)

  if(NOT APPLE)
    file(APPEND ${${target}_VERSION_SCRIPT}
      "local: *; };\n")
  endif()

  if(APPLE)
    set_target_properties(${target}_shared PROPERTIES
      LINK_FLAGS -Wl,-exported_symbols_list,${${target}_VERSION_SCRIPT})
  else()
    set_target_properties(${target}_shared PROPERTIES
      LINK_FLAGS -Wl,--version-script,${${target}_VERSION_SCRIPT})
  endif()
endfunction()

option(STRICT_ABI "Enforce strict ABI export in dynamic libraries" OFF)
if(WIN32 AND NOT MINGW)
  # Windows doesn't have this linker functionality.
  set(STRICT_ABI OFF)
endif()

if(STRICT_ABI AND NOT ENABLE_STATIC)
  if(AUTOTEST)
    message("AUTOTEST option is incompatible with STRICT_ABI. Disabling AUTOTEST.")
  endif()
  set(AUTOTEST OFF)

  if(BUILD_MISC_TESTS)
    message("BUILD_MISC_TESTS option is incompatible with STRICT_ABI. Disabling BUILD_MISC_TESTS.")
  endif()
  set(BUILD_MISC_TESTS OFF)

  if(BOOTSTRAP_DAEMON)
    message("BOOTSTRAP_DAEMON option is incompatible with STRICT_ABI. Disabling BOOTSTRAP_DAEMON.")
  endif()
  set(BOOTSTRAP_DAEMON OFF)

  if(DHT_BOOTSTRAP)
    message("DHT_BOOTSTRAP option is incompatible with STRICT_ABI. Disabling DHT_BOOTSTRAP.")
  endif()
  set(DHT_BOOTSTRAP OFF)
endif()
