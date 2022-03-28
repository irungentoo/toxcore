/* Tests that we can make a friend connection.
 *
 * This is the simplest test that brings up two toxes that can talk to each
 * other. It's useful as a copy/pasteable starting point for testing other
 * features.
 */

#include <stdint.h>

#include "auto_test_support.h"

static void friend_connection_test(AutoTox *toxes)
{
    // Nothing to do here. When copying this test, add test-specific code here.
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    run_auto_test(nullptr, 2, friend_connection_test, 0, &options);

    return 0;
}
