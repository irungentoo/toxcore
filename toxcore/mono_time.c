/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
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

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "ccompat.h"

/** don't call into system billions of times for no reason */
struct Mono_Time {
    uint64_t cur_time;
    uint64_t base_time;
#ifdef OS_WIN32
    /* protect `last_clock_update` and `last_clock_mono` from concurrent access */
    pthread_mutex_t last_clock_lock;
    uint32_t last_clock_mono;
    bool last_clock_update;
#endif

#ifndef ESP_PLATFORM
    /* protect `time` from concurrent access */
    pthread_rwlock_t *time_update_lock;
#endif

    mono_time_current_time_cb *current_time_callback;
    void *user_data;
};

#ifdef OS_WIN32
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
{
    Mono_Time *const mono_time = (Mono_Time *)user_data;

    /* Must hold mono_time->last_clock_lock here */

    /* GetTickCount provides only a 32 bit counter, but we can't use
     * GetTickCount64 for backwards compatibility, so we handle wraparound
     * ourselves.
     */
    const uint32_t ticks = GetTickCount();

    /* the higher 32 bits count the number of wrap arounds */
    uint64_t old_ovf = mono_time->cur_time & ~((uint64_t)UINT32_MAX);

    /* Check if time has decreased because of 32 bit wrap from GetTickCount() */
    if (ticks < mono_time->last_clock_mono) {
        /* account for overflow */
        old_ovf += UINT32_MAX + UINT64_C(1);
    }

    if (mono_time->last_clock_update) {
        mono_time->last_clock_mono = ticks;
        mono_time->last_clock_update = false;
    }

    /* splice the low and high bits back together */
    return old_ovf + ticks;
}
#else // !OS_WIN32
static uint64_t timespec_to_u64(struct timespec clock_mono)
{
    return 1000ULL * clock_mono.tv_sec + (clock_mono.tv_nsec / 1000000ULL);
}
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


Mono_Time *mono_time_new(mono_time_current_time_cb *current_time_callback, void *user_data)
{
    Mono_Time *mono_time = (Mono_Time *)calloc(1, sizeof(Mono_Time));

    if (mono_time == nullptr) {
        return nullptr;
    }

#ifndef ESP_PLATFORM
    mono_time->time_update_lock = (pthread_rwlock_t *)calloc(1, sizeof(pthread_rwlock_t));

    if (mono_time->time_update_lock == nullptr) {
        free(mono_time);
        return nullptr;
    }

    if (pthread_rwlock_init(mono_time->time_update_lock, nullptr) < 0) {
        free(mono_time->time_update_lock);
        free(mono_time);
        return nullptr;
    }
#endif

    mono_time_set_current_time_callback(mono_time, current_time_callback, user_data);

#ifdef OS_WIN32

    mono_time->last_clock_mono = 0;
    mono_time->last_clock_update = false;

    if (pthread_mutex_init(&mono_time->last_clock_lock, nullptr) < 0) {
        free(mono_time->time_update_lock);
        free(mono_time);
        return nullptr;
    }

#endif

    mono_time->cur_time = 0;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Maximum reproducibility. Never return time = 0.
    mono_time->base_time = 1;
#else
    mono_time->base_time = (uint64_t)time(nullptr) - (current_time_monotonic(mono_time) / 1000ULL);
#endif

    mono_time_update(mono_time);

    return mono_time;
}

void mono_time_free(Mono_Time *mono_time)
{
    if (mono_time == nullptr) {
        return;
    }
#ifdef OS_WIN32
    pthread_mutex_destroy(&mono_time->last_clock_lock);
#endif
#ifndef ESP_PLATFORM
    pthread_rwlock_destroy(mono_time->time_update_lock);
    free(mono_time->time_update_lock);
#endif
    free(mono_time);
}

void mono_time_update(Mono_Time *mono_time)
{
    uint64_t cur_time = 0;
#ifdef OS_WIN32
    /* we actually want to update the overflow state of mono_time here */
    pthread_mutex_lock(&mono_time->last_clock_lock);
    mono_time->last_clock_update = true;
#endif
    cur_time = mono_time->current_time_callback(mono_time->user_data) / 1000ULL;
    cur_time += mono_time->base_time;
#ifdef OS_WIN32
    pthread_mutex_unlock(&mono_time->last_clock_lock);
#endif

#ifndef ESP_PLATFORM
    pthread_rwlock_wrlock(mono_time->time_update_lock);
#endif
    mono_time->cur_time = cur_time;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif
}

uint64_t mono_time_get(const Mono_Time *mono_time)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Fuzzing is only single thread for now, no locking needed */
    return mono_time->cur_time;
#else
#ifndef ESP_PLATFORM
    pthread_rwlock_rdlock(mono_time->time_update_lock);
#endif
    const uint64_t cur_time = mono_time->cur_time;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif
    return cur_time;
#endif
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

/**
 * Return current monotonic time in milliseconds (ms). The starting point is
 * unspecified.
 */
uint64_t current_time_monotonic(Mono_Time *mono_time)
{
    /* For WIN32 we don't want to change overflow state of mono_time here */
#ifdef OS_WIN32
    /* We don't want to update the overflow state of mono_time here,
     * but must protect against other threads */
    pthread_mutex_lock(&mono_time->last_clock_lock);
#endif
    const uint64_t cur_time = mono_time->current_time_callback(mono_time->user_data);
#ifdef OS_WIN32
    pthread_mutex_unlock(&mono_time->last_clock_lock);
#endif
    return cur_time;
}
