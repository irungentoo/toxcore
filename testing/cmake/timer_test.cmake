cmake_minimum_required(VERSION 2.6.0)
project(timer_test C)

set(exe_name timer_test)

add_executable(${exe_name}
	timer_test.c)

linkCoreLibraries(${exe_name})
