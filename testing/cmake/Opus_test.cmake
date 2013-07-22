cmake_minimum_required(VERSION 2.6.0)
project(OPUS_test C)

set(exe_name OPUS_test)

add_executable(${exe_name}
        OPUS_test.c)

target_link_libraries(${exe_name} portaudio opus)

linkCoreLibraries(${exe_name})
