cmake_minimum_required(VERSION 2.6.0)
project(Lossless_UDP_testclient C)

set(exe_name Lossless_UDP_testclient)

add_executable(${exe_name}
        Lossless_UDP_testclient.c)

linkCoreLibraries(${exe_name})
