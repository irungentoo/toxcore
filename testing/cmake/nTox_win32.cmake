cmake_minimum_required(VERSION 2.6.0)
project(nTox_win32 C)

set(exe_name nTox_win32)

add_executable(${exe_name}
        nTox_win32.c misc_tools.c)
        
linkCoreLibraries(${exe_name})
