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
  astyle)

function(apidsl)
  if(APIDSL AND ASTYLE)
    foreach(in_file ${ARGN})
      get_filename_component(dirname ${in_file} DIRECTORY)
      get_filename_component(filename ${in_file} NAME_WE)
      set(out_file ${CMAKE_SOURCE_DIR}/${dirname}/${filename}.h)
      add_custom_command(
        OUTPUT ${out_file}
        COMMAND "${APIDSL}" "${CMAKE_SOURCE_DIR}/${in_file}"
          | "${ASTYLE}" --options="${CMAKE_SOURCE_DIR}/other/astyle/astylerc"
          > "${out_file}"
        DEPENDS ${in_file})
    endforeach()
  endif()
endfunction()
