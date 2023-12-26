# Unity build broken because of _XOPEN_SOURCE macro
set_source_files_properties(
  src/tox-bootstrapd.c
  PROPERTIES SKIP_UNITY_BUILD_INCLUSION TRUE)

add_executable(tox-bootstrapd
  src/command_line_arguments.c
  src/command_line_arguments.h
  src/config.c
  src/config.h
  src/config_defaults.h
  src/global.h
  src/log.c
  src/log.h
  src/log_backend_stdout.c
  src/log_backend_stdout.h
  src/log_backend_syslog.c
  src/log_backend_syslog.h
  src/tox-bootstrapd.c
  ../bootstrap_node_packets.c
  ../bootstrap_node_packets.h)
target_link_libraries(tox-bootstrapd PRIVATE ${LIBCONFIG_LIBRARIES})
target_link_directories(tox-bootstrapd PRIVATE ${LIBCONFIG_LIBRARY_DIRS})
target_include_directories(tox-bootstrapd SYSTEM PRIVATE ${LIBCONFIG_INCLUDE_DIRS})
target_compile_options(tox-bootstrapd PRIVATE ${LIBCONFIG_CFLAGS_OTHER})
if(TARGET toxcore_static)
  target_link_libraries(tox-bootstrapd PRIVATE toxcore_static)
else()
  target_link_libraries(tox-bootstrapd PRIVATE toxcore_shared)
endif()
install(TARGETS tox-bootstrapd RUNTIME DESTINATION bin)
install(FILES bash-completion/completions/tox-bootstrapd DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/bash-completion/completions")
