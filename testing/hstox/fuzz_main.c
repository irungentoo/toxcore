#include "driver.h"

#include <unistd.h>

// The number of afl iterations before terminating the process and starting a
// new one.
// See https://github.com/mcarpenter/afl/blob/master/llvm_mode/README.llvm.
#define ITERATIONS 1000

#ifdef __GLASGOW_HASKELL__
#define main fuzz_main
#endif
int main(int argc, char **argv)
{
    struct settings cfg = {false, false};
#ifdef __AFL_LOOP

    while (__AFL_LOOP(ITERATIONS))
#endif
        communicate(cfg, STDIN_FILENO, STDOUT_FILENO);

    return 0;
}
