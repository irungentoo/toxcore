#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/group_announce.h"
#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

void do_announce(ANNOUNCE *announce)
{
    networking_poll(announce->net);
    do_DHT(announce->dht);
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *onion = onion_suite();
    SRunner *test_runner = srunner_create(onion);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
