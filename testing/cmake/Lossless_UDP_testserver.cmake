cmake_minimum_required(VERSION 2.6.0)
project(Lossless_UDP_testserver C)

set(exe_name Lossless_UDP_testserver)

add_executable(${exe_name}
        Lossless_UDP_testserver.c)

linkCoreLibraries(${exe_name})
