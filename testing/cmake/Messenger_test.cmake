cmake_minimum_required(VERSION 2.6.0)
project(Messenger_test C)

set(exe_name Messenger_test)

add_executable(${exe_name}
        Messenger_test.c)

linkCoreLibraries(${exe_name})
