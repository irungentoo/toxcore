#ifndef C_TOXCORE_TOXCORE_MONO_TIME_TEST_UTIL_HH
#define C_TOXCORE_TOXCORE_MONO_TIME_TEST_UTIL_HH

#include "../testing/support/doubles/fake_clock.hh"
#include "attributes.h"
#include "mono_time.h"

void setup_fake_clock(Mono_Time *_Nonnull mono_time, tox::test::FakeClock &clock);

#endif  // C_TOXCORE_TOXCORE_MONO_TIME_TEST_UTIL_HH
