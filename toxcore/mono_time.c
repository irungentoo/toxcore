/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2023 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif

#include "mono_time.h"

#ifdef OS_WIN32
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

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <assert.h>
#endif
#include <pthread.h>
#include <time.h>

#include "ccompat.h"
#include "mem.h"
#include "util.h"

/** don't call into system billions of times for no reason */
struct Mono_Time {
    uint64_t cur_time;
    uint64_t base_time;

#ifndef ESP_PLATFORM
    /* protect `time` from concurrent access */
    pthread_rwlock_t *time_update_lock;
#endif

    mono_time_current_time_cb *current_time_callback;
    void *user_data;
};

static uint64_t timespec_to_u64(struct timespec clock_mono)
{
    return UINT64_C(1000) * clock_mono.tv_sec + (clock_mono.tv_nsec / UINT64_C(1000000));
}

#ifdef OS_WIN32
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
{
    LARGE_INTEGER freq;
    LARGE_INTEGER count;
    if (!QueryPerformanceFrequency(&freq)) {
        return 0;
    }
    if (!QueryPerformanceCounter(&count)) {
        return 0;
    }
    struct timespec sp = {0};
    sp.tv_sec = count.QuadPart / freq.QuadPart;
    if (freq.QuadPart < 1000000000) {
        sp.tv_nsec = (count.QuadPart % freq.QuadPart) * 1000000000 / freq.QuadPart;
    } else {
        sp.tv_nsec = (long)((count.QuadPart % freq.QuadPart) * (1000000000.0 / freq.QuadPart));
    }
    return timespec_to_u64(sp);
}
#else
#ifdef __APPLE__
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
{
    struct timespec clock_mono;
    clock_serv_t muhclock;
    mach_timespec_t machtime;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &muhclock);
    clock_get_time(muhclock, &machtime);
    mach_port_deallocate(mach_task_self(), muhclock);

    clock_mono.tv_sec = machtime.tv_sec;
    clock_mono.tv_nsec = machtime.tv_nsec;
    return timespec_to_u64(clock_mono);
}
#else // !__APPLE__
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // This assert should always fail. If it does, the fuzzing harness didn't
    // override the mono time callback.
    assert(user_data == nullptr);
#endif
    struct timespec clock_mono;
    clock_gettime(CLOCK_MONOTONIC, &clock_mono);
    return timespec_to_u64(clock_mono);
}
#endif // !__APPLE__
#endif // !OS_WIN32


Mono_Time *mono_time_new(const Memory *mem, mono_time_current_time_cb *current_time_callback, void *user_data)
{
    Mono_Time *mono_time = (Mono_Time *)mem_alloc(mem, sizeof(Mono_Time));

    if (mono_time == nullptr) {
        return nullptr;
    }

#ifndef ESP_PLATFORM
    mono_time->time_update_lock = (pthread_rwlock_t *)mem_alloc(mem, sizeof(pthread_rwlock_t));

    if (mono_time->time_update_lock == nullptr) {
        mem_delete(mem, mono_time);
        return nullptr;
    }

    if (pthread_rwlock_init(mono_time->time_update_lock, nullptr) != 0) {
        mem_delete(mem, mono_time->time_update_lock);
        mem_delete(mem, mono_time);
        return nullptr;
    }
#endif

    mono_time_set_current_time_callback(mono_time, current_time_callback, user_data);

    mono_time->cur_time = 0;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Maximum reproducibility. Never return time = 0.
    mono_time->base_time = 1;
#else
    // Never return time = 0 in case time() returns 0 (e.g. on microcontrollers
    // without battery-powered RTC or ones where NTP didn't initialise it yet).
    mono_time->base_time = max_u64(1, (uint64_t)time(nullptr)) * UINT64_C(1000) - current_time_monotonic(mono_time);
#endif

    mono_time_update(mono_time);

    return mono_time;
}

void mono_time_free(const Memory *mem, Mono_Time *mono_time)
{
    if (mono_time == nullptr) {
        return;
    }
#ifndef ESP_PLATFORM
    pthread_rwlock_destroy(mono_time->time_update_lock);
    mem_delete(mem, mono_time->time_update_lock);
#endif
    mem_delete(mem, mono_time);
}

void mono_time_update(Mono_Time *mono_time)
{
    const uint64_t cur_time =
        mono_time->base_time + mono_time->current_time_callback(mono_time->user_data);

#ifndef ESP_PLATFORM
    pthread_rwlock_wrlock(mono_time->time_update_lock);
#endif
    mono_time->cur_time = cur_time;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif
}

uint64_t mono_time_get_ms(const Mono_Time *mono_time)
{
#if !defined(ESP_PLATFORM) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Fuzzing is only single thread for now, no locking needed */
    pthread_rwlock_rdlock(mono_time->time_update_lock);
#endif
    const uint64_t cur_time = mono_time->cur_time;
#if !defined(ESP_PLATFORM) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif
    return cur_time;
}

uint64_t mono_time_get(const Mono_Time *mono_time)
{
    return mono_time_get_ms(mono_time) / UINT64_C(1000);
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
        mono_time->user_data = mono_time;
    } else {
        mono_time->current_time_callback = current_time_callback;
        mono_time->user_data = user_data;
    }
}

/** @brief Return current monotonic time in milliseconds (ms).
 *
 * The starting point is unspecified and in particular is likely not comparable
 * to the return value of `mono_time_get_ms()`.
 */
uint64_t current_time_monotonic(Mono_Time *mono_time)
{
    return mono_time->current_time_callback(mono_time->user_data);
}
