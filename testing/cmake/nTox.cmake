cmake_minimum_required(VERSION 2.6.0)
project(nTox C)

set(exe_name nTox)

add_executable(${exe_name}
        nTox.c)
	
target_link_libraries(${exe_name} ncurses)

linkCoreLibraries(${exe_name})
