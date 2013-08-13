/*  timer.h
 *
 *  Timing subsystem. Provides deadline timers.
 *  All times are aliased to a second for efficiency.
 *
 *  Timer Guarantees:
 *  - The callback will not be called before the timer expires.
 *  - The callback will be called sometime after the timer expires,
 *    on a best effort basis.
 *  - If timer_poll is called at least once a second, the callback
 *    will be called at most one second after it expires.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef TIMER_H
#define TIMER_H

#include <stdint.h>
#include <stdbool.h>

#define US_PER_SECOND 1000000 /* 1 s = 10^6 us */

struct timer;
typedef struct timer timer;

/* If time_callback returns a non-zero value, timer t is deleted.
 * You may call any of the timer functions within the callback:
 * For example, you may call timer_start to restart the timer from
 * within a callback. */
typedef int (*timer_callback)(timer* t, void* userarg);

/* Initisalise timer subsystem */
void timer_init(void);

/* Poll. (I will eventually replace all polling in Tox with an async system.) */
void timer_poll(void);

/* Creates a new timer. Does not enqueue/start it. */
timer* new_timer(void);

/* Destroys a timer instance. */
void delete_timer(timer* t);

/* Sets up the timer callback. */
void timer_setup(timer* t, timer_callback cb, void* userarg);

/* Accessor Function. */
void* timer_get_userdata(timer* t);

/* Starts the timer so that it's called in sec seconds in the future from now. 
 * A non-positive value of sec results in the callback being called immediately.
 * This function may be called again after a timer has been started to adjust 
 * the expiry time. */
void timer_start(timer* t, int sec);

/* Stops the timer. Returns -1 if the timer was not active. */
int timer_stop(timer* t);

/* Adds additionalsec seconds to the timer. 
 * Returns -1 and does nothing if the timer was not active. */
int timer_delay(timer* t, int additonalsec);

/* Returns the time remaining on a timer in seconds.
 * Returns -1 if the timer is not active.
 * Returns 0 if the timer has expired and the callback hasn't been called yet. */
int timer_time_remaining(timer* t);

/* Determines if timer is active. Returns TRUE if it is active */
bool timer_is_active(timer* t);

/* Single-use timer.
 * Creates a new timer, preforms setup and starts it. 
 * Callback must return a non-zero value to prevent memory leak. */
void timer_single(timer_callback cb, void* userarg, int sec);

/* Single-use microsecond timer.
 * Creates a new timer, preforms setup and starts it. 
 * Please do not use this when accuracy is not absolutely required.
 * Use when one needs to time a period < 1 s.
 * Use the more coarse timers above for periods > 5 s. 
 * WARNING: the callback will be called with NULL as the first argument */
void timer_us(timer_callback cb, void* userarg, int us);

/* Internal Testing */
void timer_internal_tests(bool(*)(bool, char*));

#endif
