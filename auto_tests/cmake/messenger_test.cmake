cmake_minimum_required(VERSION 2.6.0)
project(messenger_test C)
set(exe_name messenger_test)

add_executable(${exe_name}
    messenger_test.c)

set(EXTRA_LIBS m rt pthread)

linkCoreLibraries(${exe_name})
add_dependencies(${exe_name} Check)
target_link_libraries(${exe_name} check ${EXTRA_LIBS})
