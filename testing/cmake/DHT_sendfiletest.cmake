cmake_minimum_required(VERSION 2.6.0)
project(DHT_sendfiletest C)

set(exe_name DHT_sendfiletest)

add_executable(${exe_name}
        DHT_sendfiletest.c)

linkCoreLibraries(${exe_name})
