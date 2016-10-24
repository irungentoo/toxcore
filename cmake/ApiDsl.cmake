################################################################################
#
# :: APIDSL regeneration
#
################################################################################

find_program(APIDSL NAMES
  apidsl
  apidsl.native
  apidsl.byte
  ${CMAKE_SOURCE_DIR}/../apidsl/apigen.native)
find_program(ASTYLE NAMES
  astyle
  $ENV{ASTYLE})

function(apidsl)
  if(APIDSL AND ASTYLE)
    foreach(in_file ${ARGN})
      # Get the directory component of the input file name.
      if(CMAKE_VERSION VERSION_LESS 3.0)
        execute_process(
          COMMAND dirname ${in_file}
          OUTPUT_VARIABLE dirname
          OUTPUT_STRIP_TRAILING_WHITESPACE)
      else()
        get_filename_component(dirname ${in_file} DIRECTORY)
      endif()

      # Get the name without extension (i.e. without ".api.h").
      get_filename_component(filename ${in_file} NAME_WE)

      # Put them together, with the new extension that is ".h".
      set(out_file ${CMAKE_SOURCE_DIR}/${dirname}/${filename}.h)

      # Run apidsl.
      add_custom_command(
        OUTPUT ${out_file}
        COMMAND "${APIDSL}" "${CMAKE_SOURCE_DIR}/${in_file}"
          | "${ASTYLE}" --options="${CMAKE_SOURCE_DIR}/other/astyle/astylerc"
          > "${out_file}"
        DEPENDS ${in_file})
    endforeach()
  endif()
endfunction()
