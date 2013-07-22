cmake_minimum_required(VERSION 2.6.0)
project(DHT_bootstrap_daemon C)

set(exe_name DHT_bootstrap_daemon)

add_executable(${exe_name}
        DHT_bootstrap_daemon.c)

linkCoreLibraries(${exe_name})
