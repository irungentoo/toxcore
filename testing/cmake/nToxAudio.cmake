cmake_minimum_required(VERSION 2.6.0)
project(nToxAudio C)

set(exe_name nToxAudio)

add_executable(${exe_name}
	nToxAudio.c misc_tools.c)

target_link_libraries(${exe_name}
	ncurses)

linkCoreLibraries(${exe_name})
