cmake_minimum_required(VERSION 2.6.0)
project(DHT_cryptosendfiletest C)

set(exe_name DHT_cryptosendfiletest)

add_executable(${exe_name}
        DHT_cryptosendfiletest.c)

linkCoreLibraries(${exe_name})