/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2014 Tox project.
 */
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

#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "ccompat.h"

/* don't call into system billions of times for no reason */
struct Mono_Time {
    uint64_t time;
    uint64_t base_time;
#ifdef OS_WIN32
    /* protect `last_clock_update` and `last_clock_mono` from concurrent access */
    pthread_mutex_t last_clock_lock;
    uint32_t last_clock_mono;
    bool last_clock_update;
#endif

    /* protect `time` from concurrent access */
    pthread_rwlock_t *time_update_lock;

    mono_time_current_time_cb *current_time_callback;
    void *user_data;
};

static uint64_t current_time_monotonic_default(Mono_Time *mono_time, void *user_data)
{
    uint64_t time = 0;
#ifdef OS_WIN32
    /* Must hold mono_time->last_clock_lock here */

    /* GetTickCount provides only a 32 bit counter, but we can't use
     * GetTickCount64 for backwards compatibility, so we handle wraparound
     * ourselves.
     */
    uint32_t ticks = GetTickCount();

    /* the higher 32 bits count the number of wrap arounds */
    uint64_t old_ovf = mono_time->time & ~((uint64_t)UINT32_MAX);

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
    time = old_ovf + ticks;
#else
    struct timespec clock_mono;
#if defined(__APPLE__)
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

Mono_Time *mono_time_new(void)
{
    Mono_Time *mono_time = (Mono_Time *)malloc(sizeof(Mono_Time));

    if (mono_time == nullptr) {
        return nullptr;
    }

    mono_time->time_update_lock = (pthread_rwlock_t *)malloc(sizeof(pthread_rwlock_t));

    if (mono_time->time_update_lock == nullptr) {
        free(mono_time);
        return nullptr;
    }

    if (pthread_rwlock_init(mono_time->time_update_lock, nullptr) < 0) {
        free(mono_time->time_update_lock);
        free(mono_time);
        return nullptr;
    }

    mono_time->current_time_callback = current_time_monotonic_default;
    mono_time->user_data = nullptr;

#ifdef OS_WIN32

    mono_time->last_clock_mono = 0;
    mono_time->last_clock_update = false;

    if (pthread_mutex_init(&mono_time->last_clock_lock, nullptr) < 0) {
        free(mono_time->time_update_lock);
        free(mono_time);
        return nullptr;
    }

#endif

    mono_time->time = 0;
    mono_time->base_time = (uint64_t)time(nullptr) - (current_time_monotonic(mono_time) / 1000ULL);

    mono_time_update(mono_time);

    return mono_time;
}

void mono_time_free(Mono_Time *mono_time)
{
#ifdef OS_WIN32
    pthread_mutex_destroy(&mono_time->last_clock_lock);
#endif
    pthread_rwlock_destroy(mono_time->time_update_lock);
    free(mono_time->time_update_lock);
    free(mono_time);
}

void mono_time_update(Mono_Time *mono_time)
{
    uint64_t time = 0;
#ifdef OS_WIN32
    /* we actually want to update the overflow state of mono_time here */
    pthread_mutex_lock(&mono_time->last_clock_lock);
    mono_time->last_clock_update = true;
#endif
    time = mono_time->current_time_callback(mono_time, mono_time->user_data) / 1000ULL;
    time += mono_time->base_time;
#ifdef OS_WIN32
    pthread_mutex_unlock(&mono_time->last_clock_lock);
#endif

    pthread_rwlock_wrlock(mono_time->time_update_lock);
    mono_time->time = time;
    pthread_rwlock_unlock(mono_time->time_update_lock);
}

uint64_t mono_time_get(const Mono_Time *mono_time)
{
    uint64_t time = 0;
    pthread_rwlock_rdlock(mono_time->time_update_lock);
    time = mono_time->time;
    pthread_rwlock_unlock(mono_time->time_update_lock);
    return time;
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
uint64_t current_time_monotonic(Mono_Time *mono_time)
{
    /* For WIN32 we don't want to change overflow state of mono_time here */
#ifdef OS_WIN32
    /* We don't want to update the overflow state of mono_time here,
     * but must protect against other threads */
    pthread_mutex_lock(&mono_time->last_clock_lock);
#endif
    uint64_t time = mono_time->current_time_callback(mono_time, mono_time->user_data);
#ifdef OS_WIN32
    pthread_mutex_unlock(&mono_time->last_clock_lock);
#endif
    return time;
}
