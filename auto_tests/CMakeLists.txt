cmake_minimum_required(VERSION 2.6.0)
cmake_policy(SET CMP0011 NEW)

include_directories(${CHECK_INCLUDE_DIRS})

find_package(Check REQUIRED)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/messenger_test.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/crypto_test.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/friends_test.cmake)

include( CTest )
enable_testing()

add_test(messenger messenger_test)
add_test(crypto crypto_test)
# TODO enable once test is fixed
#add_test(friends friends_test)

add_custom_target(
    test COMMAND ${CMAKE_CTEST_COMMAND} -V 
    DEPENDS messenger_test crypto_test
)
