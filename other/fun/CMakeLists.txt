add_executable(save-generator save-generator.c)
target_link_modules(save-generator toxcore misc_tools)

add_executable(strkey strkey.c)
target_link_modules(strkey toxcore ${LIBSODIUM_LIBRARIES})

add_executable(create_bootstrap_keys create_bootstrap_keys.c)
target_link_modules(create_bootstrap_keys ${LIBSODIUM_LIBRARIES})

add_executable(create_minimal_savedata create_minimal_savedata.c)
target_link_modules(create_minimal_savedata ${LIBSODIUM_LIBRARIES})

add_executable(create_savedata create_savedata.c)
target_link_modules(create_savedata toxcore ${LIBSODIUM_LIBRARIES})

add_executable(sign sign.c)
target_link_modules(sign ${LIBSODIUM_LIBRARIES} misc_tools)

add_executable(cracker_simple cracker_simple.c)
target_link_modules(cracker_simple ${LIBSODIUM_LIBRARIES} misc_tools)

# MSVC doesn't support OpenMP
if(NOT MSVC)
  find_package(OpenMP)
  if(OpenMP_C_FOUND)
    add_executable(cracker cracker.c)
    target_link_modules(cracker ${LIBSODIUM_LIBRARIES})
    target_link_libraries(cracker OpenMP::OpenMP_C)
  endif()
endif()
