cmake_minimum_required(VERSION 2.6.0)
project(toxic C)

set(exe_name toxic)

add_executable(${exe_name}
        toxic/main.c toxic/prompt.c)
	
target_link_libraries(${exe_name} curses)

linkCoreLibraries(${exe_name})
