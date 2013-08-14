cmake_minimum_required(VERSION 2.6.0)
project(toxic C)

execute_process(COMMAND git rev-list HEAD --count OUTPUT_VARIABLE COMMIT)
SET(GCC_COVERAGE_COMPILE_FLAGS '-DTOXICVER="0.1.1_r${COMMIT}"')
add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})
set(exe_name toxic)

add_executable(${exe_name}
	main.c
	windows.c
	prompt.c
	friendlist.c
	chat.c
	configdir.c)

target_link_libraries(${exe_name}
	curses)

linkCoreLibraries(${exe_name})
