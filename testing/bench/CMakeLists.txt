if(NOT UNITTEST)
  return()
endif()

find_package(benchmark QUIET)

if(benchmark_FOUND)
  add_executable(tox_messenger_bench tox_messenger_bench.cc)
  target_link_libraries(tox_messenger_bench PRIVATE
    toxcore_static
    support
    benchmark::benchmark
  )

  add_executable(tox_friends_scaling_bench tox_friends_scaling_bench.cc)
  target_link_libraries(tox_friends_scaling_bench PRIVATE
    toxcore_static
    support
    benchmark::benchmark
  )
endif()
