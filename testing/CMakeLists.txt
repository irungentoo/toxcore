# Helpful code for tests and other utilities
set(misc_tools_SOURCES
  misc_tools.c
  misc_tools.h)
add_library(misc_tools STATIC ${misc_tools_SOURCES})
if(TARGET toxcore_static)
  target_link_libraries(misc_tools PRIVATE toxcore_static)
else()
  target_link_libraries(misc_tools PRIVATE toxcore_shared)
endif()
if(TARGET pthreads4w::pthreads4w)
  target_link_libraries(misc_tools PUBLIC pthreads4w::pthreads4w)
elseif(TARGET PThreads4W::PThreads4W)
  target_link_libraries(misc_tools PUBLIC PThreads4W::PThreads4W)
elseif(TARGET Threads::Threads)
  target_link_libraries(misc_tools PUBLIC Threads::Threads)
endif()

################################################################################
#
# :: Test programs
#
################################################################################

if(BUILD_MISC_TESTS)
  add_executable(Messenger_test Messenger_test.c)
  target_link_libraries(Messenger_test PRIVATE misc_tools)
  if(TARGET toxcore_static)
    target_link_libraries(Messenger_test PRIVATE toxcore_static)
  else()
    target_link_libraries(Messenger_test PRIVATE toxcore_shared)
  endif()
endif()

if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bench")
  add_subdirectory(bench)
endif()

if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/support")
  add_subdirectory(support)
endif()
