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

function(make_version_script header ns lib)
  execute_process(
    COMMAND ${SHELL} -c "egrep '^\\w' ${header} | grep '${ns}_[a-z0-9_]*(' | grep -v '^typedef' | grep -o '${ns}_[a-z0-9_]*(' | egrep -o '\\w+' | sort -u"
    OUTPUT_VARIABLE ${lib}_SYMS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(REPLACE "\n" ";" ${lib}_SYMS ${${lib}_SYMS})

  set(${lib}_VERSION_SCRIPT "${CMAKE_BINARY_DIR}/${lib}.ld")

  file(WRITE ${${lib}_VERSION_SCRIPT}
    "{ global:\n")
  foreach(sym ${${lib}_SYMS})
    file(APPEND ${${lib}_VERSION_SCRIPT}
      "${sym};\n")
  endforeach(sym)
  file(APPEND ${${lib}_VERSION_SCRIPT}
    "local: *; };\n")

  set_target_properties(${lib}_shared PROPERTIES
    LINK_FLAGS -Wl,--version-script,${${lib}_VERSION_SCRIPT})
endfunction()

option(STRICT_ABI "Enforce strict ABI export in dynamic libraries" OFF)
if(WIN32 OR APPLE)
  # Windows and OSX don't have this linker functionality.
  set(STRICT_ABI OFF)
endif()
