# Helpful code for tests and other utilities
set(misc_tools_SOURCES
  misc_tools.c
  misc_tools.h)
add_library(misc_tools ${misc_tools_SOURCES})
target_link_modules(misc_tools toxcore)

################################################################################
#
# :: Test programs
#
################################################################################

if (BUILD_MISC_TESTS)
  add_executable(Messenger_test Messenger_test.c)
  target_link_modules(Messenger_test toxcore misc_tools)
endif()
