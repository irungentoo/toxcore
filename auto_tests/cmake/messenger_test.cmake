cmake_minimum_required(VERSION 2.6.0)
project(messenger_test C)
set(exe_name messenger_test)

add_executable(${exe_name}
    messenger_test.c)

linkCoreLibraries(${exe_name})
add_dependencies(${exe_name} Check)
target_link_libraries(${exe_name} check)
