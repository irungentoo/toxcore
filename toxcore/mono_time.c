#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef __APPLE__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#ifndef OS_WIN32
#include <sys/time.h>
#endif

#include "mono_time.h"

#include <stdlib.h>
#include <time.h>

#include "ccompat.h"

/* don't call into system billions of times for no reason */
struct Mono_Time {
    uint64_t time;
    uint64_t base_time;
};

Mono_Time *mono_time_new(void)
{
    Mono_Time *monotime = (Mono_Time *)malloc(sizeof(Mono_Time));

    if (monotime == nullptr) {
        return nullptr;
    }

    monotime->time = 0;
    monotime->base_time = 0;

    return monotime;
}

void mono_time_free(Mono_Time *monotime)
{
    free(monotime);
}

void mono_time_update(Mono_Time *monotime)
{
    if (monotime->base_time == 0) {
        monotime->base_time = ((uint64_t)time(nullptr) - (current_time_monotonic() / 1000ULL));
    }

    monotime->time = (current_time_monotonic() / 1000ULL) + monotime->base_time;
}

uint64_t mono_time_get(const Mono_Time *monotime)
{
    return monotime->time;
}

bool mono_time_is_timeout(const Mono_Time *monotime, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= mono_time_get(monotime);
}


//!TOKSTYLE-
// No global mutable state in Tokstyle.
static Mono_Time global_time;
//!TOKSTYLE+

/* XXX: note that this is not thread-safe; if multiple threads call unix_time_update() concurrently, the return value of
 * unix_time() may fail to increase monotonically with increasing time */
void unix_time_update(void)
{
    mono_time_update(&global_time);
}
uint64_t unix_time(void)
{
    return mono_time_get(&global_time);
}
int is_timeout(uint64_t timestamp, uint64_t timeout)
{
    return mono_time_is_timeout(&global_time, timestamp, timeout);
}


//!TOKSTYLE-
// No global mutable state in Tokstyle.
#ifdef OS_WIN32
static uint64_t last_monotime;
static uint64_t add_monotime;
#endif
//!TOKSTYLE+

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void)
{
    uint64_t time;
#ifdef OS_WIN32
    uint64_t old_add_monotime = add_monotime;
    time = (uint64_t)GetTickCount() + add_monotime;

    /* Check if time has decreased because of 32 bit wrap from GetTickCount(), while avoiding false positives from race
     * conditions when multiple threads call this function at once */
    if (time + 0x10000 < last_monotime) {
        uint32_t add = ~0;
        /* use old_add_monotime rather than simply incrementing add_monotime, to handle the case that many threads
         * simultaneously detect an overflow */
        add_monotime = old_add_monotime + add;
        time += add;
    }

    last_monotime = time;
#else
    struct timespec monotime;
#if defined(__linux__) && defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
#elif defined(__APPLE__)
    clock_serv_t muhclock;
    mach_timespec_t machtime;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &muhclock);
    clock_get_time(muhclock, &machtime);
    mach_port_deallocate(mach_task_self(), muhclock);

    monotime.tv_sec = machtime.tv_sec;
    monotime.tv_nsec = machtime.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, &monotime);
#endif
    time = 1000ULL * monotime.tv_sec + (monotime.tv_nsec / 1000000ULL);
#endif
    return time;
}
