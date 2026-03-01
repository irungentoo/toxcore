if(NOT UNITTEST)
  return()
endif()

set(support_SOURCES
  doubles/fake_network_stack.cc
  doubles/fake_sockets.cc
  doubles/network_universe.cc
  src/clock.cc
  src/environment.cc
  src/fake_clock.cc
  src/fake_memory.cc
  src/fake_random.cc
  src/fuzz_helpers.cc
  src/memory.cc
  src/network.cc
  src/random.cc
  src/simulated_environment.cc
  src/simulation.cc
  src/tox_network.cc
  src/tox_runner.cc
  doubles/fake_clock.hh
  doubles/fake_memory.hh
  doubles/fake_network_stack.hh
  doubles/fake_random.hh
  doubles/fake_sockets.hh
  doubles/network_universe.hh
  public/clock.hh
  public/environment.hh
  public/fuzz_data.hh
  public/fuzz_helpers.hh
  public/memory.hh
  public/mpsc_queue.hh
  public/network.hh
  public/random.hh
  public/simulated_environment.hh
  public/simulation.hh
  public/tox_network.hh
  public/tox_runner.hh
)

add_library(support STATIC ${support_SOURCES})

if(TARGET toxcore_static)
  target_link_libraries(support PRIVATE toxcore_static)
else()
  target_link_libraries(support PRIVATE toxcore_shared)
endif()

if(TARGET pthreads4w::pthreads4w)
  target_link_libraries(support PUBLIC pthreads4w::pthreads4w)
elseif(TARGET PThreads4W::PThreads4W)
  target_link_libraries(support PUBLIC PThreads4W::PThreads4W)
elseif(TARGET Threads::Threads)
  target_link_libraries(support PUBLIC Threads::Threads)
endif()

if(TARGET GTest::gtest_main)
  function(support_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE support GTest::gtest_main)
    if(TARGET toxcore_static)
      target_link_libraries(${target} PRIVATE toxcore_static)
    else()
      target_link_libraries(${target} PRIVATE toxcore_shared)
    endif()
    add_test(NAME ${target} COMMAND ${target})
  endfunction()

  support_test(fake_sockets_test doubles/fake_sockets_test.cc)
  support_test(fake_network_stack_test doubles/fake_network_stack_test.cc)
  support_test(fake_network_udp_test doubles/fake_network_udp_test.cc)
  support_test(fake_network_tcp_test doubles/fake_network_tcp_test.cc)
  support_test(network_universe_test doubles/network_universe_test.cc)
  support_test(bootstrap_scaling_test bootstrap_scaling_test.cc)
  # TODO(iphydf): Re-enable once we migrate TCP server to ev.
  #support_test(tox_network_test tox_network_test.cc)
endif()
