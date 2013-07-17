cmake_minimum_required(VERSION 2.6.0)
project(DHT_bootstrap C)

set(exe_name DHT_bootstrap)

add_executable(${exe_name}
        DHT_bootstrap.c)

linkCoreLibraries(${exe_name})
