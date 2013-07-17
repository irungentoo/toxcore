cmake_minimum_required(VERSION 2.6.0)
project(DHT_test C)

set(exe_name DHT_test)

add_executable(${exe_name}
        DHT_test.c)

linkCoreLibraries(${exe_name})
