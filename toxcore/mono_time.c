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

    mono_time_current_time_cb *current_time_callback;
    void *user_data;
};

static mono_time_current_time_cb current_time_monotonic_default;

Mono_Time *mono_time_new(void)
{
    Mono_Time *mono_time = (Mono_Time *)malloc(sizeof(Mono_Time));

    if (mono_time == nullptr) {
        return nullptr;
    }

    mono_time->current_time_callback = current_time_monotonic_default;
    mono_time->user_data = nullptr;

    mono_time->time = 0;
    mono_time->base_time = (uint64_t)time(nullptr) - (current_time_monotonic(mono_time) / 1000ULL);

    mono_time_update(mono_time);

    return mono_time;
}

void mono_time_free(Mono_Time *mono_time)
{
    free(mono_time);
}

void mono_time_update(Mono_Time *mono_time)
{
    mono_time->time = (current_time_monotonic(mono_time) / 1000ULL) + mono_time->base_time;
}

uint64_t mono_time_get(const Mono_Time *mono_time)
{
    return mono_time->time;
}

bool mono_time_is_timeout(const Mono_Time *mono_time, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= mono_time_get(mono_time);
}

void mono_time_set_current_time_callback(Mono_Time *mono_time,
        mono_time_current_time_cb *current_time_callback, void *user_data)
{
    if (current_time_callback == nullptr) {
        mono_time->current_time_callback = current_time_monotonic_default;
        mono_time->user_data = nullptr;
    } else {
        mono_time->current_time_callback = current_time_callback;
        mono_time->user_data = user_data;
    }
}

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(const Mono_Time *mono_time)
{
    return mono_time->current_time_callback(mono_time->user_data);
}

//!TOKSTYLE-
// No global mutable state in Tokstyle.
#ifdef OS_WIN32
static uint64_t last_clock_mono;
static uint64_t add_clock_mono;
#endif
//!TOKSTYLE+

static uint64_t current_time_monotonic_default(void *user_data)
{
    uint64_t time;
#ifdef OS_WIN32
    uint64_t old_add_clock_mono = add_clock_mono;
    time = (uint64_t)GetTickCount() + add_clock_mono;

    /* Check if time has decreased because of 32 bit wrap from GetTickCount(), while avoiding false positives from race
     * conditions when multiple threads call this function at once */
    if (time + 0x10000 < last_clock_mono) {
        uint32_t add = ~0;
        /* use old_add_clock_mono rather than simply incrementing add_clock_mono, to handle the case that many threads
         * simultaneously detect an overflow */
        add_clock_mono = old_add_clock_mono + add;
        time += add;
    }

    last_clock_mono = time;
#else
    struct timespec clock_mono;
#if defined(__linux__) && defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &clock_mono);
#elif defined(__APPLE__)
    clock_serv_t muhclock;
    mach_timespec_t machtime;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &muhclock);
    clock_get_time(muhclock, &machtime);
    mach_port_deallocate(mach_task_self(), muhclock);

    clock_mono.tv_sec = machtime.tv_sec;
    clock_mono.tv_nsec = machtime.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, &clock_mono);
#endif
    time = 1000ULL * clock_mono.tv_sec + (clock_mono.tv_nsec / 1000000ULL);
#endif
    return time;
}
