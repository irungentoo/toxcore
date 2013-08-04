cmake_minimum_required(VERSION 2.6.0)
project(messenger_test C)

set(exe_name messenger_test)

add_executable(${exe_name}
	messenger_test.c misc_tools.c)

linkCoreLibraries(${exe_name})
