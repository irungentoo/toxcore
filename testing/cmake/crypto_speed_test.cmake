cmake_minimum_required(VERSION 2.6.0)
project(crypto_speed_test C)

set(exe_name crypto_speed_test)

add_executable(${exe_name}
	crypto_speed_test.c)

linkCoreLibraries(${exe_name})
