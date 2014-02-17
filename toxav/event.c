/**  event.c
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *   Report bugs/suggestions at #tox-dev @ freenode.net:6667
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include "event.h"

#include "../toxcore/util.h"
#include "../toxcore/network.h"

#define _GNU_SOURCE

#include <assert.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>

#define RUN_IN_THREAD(func, args) { pthread_t _tid; \
pthread_create(&_tid, NULL, func, args); assert( pthread_detach(_tid) == 0 ); }

#define LOCK(event_handler) pthread_mutex_lock (&event_handler->mutex)
#define UNLOCK(event_handler) pthread_mutex_unlock(&event_handler->mutex)

#define FREQUENCY 10000

#define inline__ inline __attribute__((always_inline))


typedef struct _EventContainer {
    void *(*func)(void *);
    void *func_args;
    unsigned timeout;
    long long id;

} EventContainer;

typedef struct _EventHandler {
    EventContainer *timed_events;
    size_t timed_events_count;

    int running;

    pthread_mutex_t mutex;

} EventHandler;

int throw_event( void * (func)(void *), void *arg );
int reset_timer_event ( int id, uint32_t timeout );
int throw_timer_event ( void * (func)(void *), void *arg, unsigned timeout);
int cancel_timer_event ( int id );
int execute_timer_event ( int id );

struct _Event event = {
    throw_event,
    /* reset_timer_event */ NULL,
    throw_timer_event,
    cancel_timer_event,
    /*execute_timer_event*/ NULL
};

/*
 * Random functions used by this file
 */
void clear_events (EventContainer **event_container, size_t *counter)
{
    free(*event_container );

    *event_container = NULL;
    *counter = 0;
}

int pop_id ( EventContainer **event_container, size_t *counter, int id )
{
    if ( !*event_container || !*counter || !id )
        return -1;

    EventContainer *_it = *event_container;
    int i;

    for ( i = *counter; i; -- i ) {
        if ( _it->id == id ) { /* Hit! */
            break;
        }

        ++_it;
    }

    if ( i ) {
        for ( ; i; -- i ) {
            *_it = *(_it + 1);
            ++_it;
        }

        -- (*counter );

        if ( !(*counter)) { /* Free and set to NULL */
            free(*event_container);
            *event_container = NULL;
        } else {
            void *_result = realloc(*event_container, sizeof(EventContainer) * (*counter )); /* resize */


            if ( _result != NULL ) {
                *event_container = _result;
                return 0;
            } else {
                /* Not sure what would happen next so abort execution.
                 */
                fprintf(stderr, "CRITICAL! Failed to reallocate memory in %s():%d, aborting...", __func__, __LINE__);
                abort();
                return -1;
            }
        }
    }

    /* not found here */

    return -1;
}

void push_event ( EventContainer **container, size_t *counter, void * (func)(void *), void *arg )
{
    EventContainer *_new = realloc((*container ), sizeof(EventContainer) * ((*counter ) + 1));

    if ( _new == NULL ) {
        /* Not sure what would happen next so abort execution.
         * TODO: This could notice the calling function
         *       about realloc failing.
         */
        fprintf(stderr, "CRITICAL! Failed to reallocate memory in %s():%d, aborting...", __func__, __LINE__);
        abort();
    }

    _new[*counter].func = func;
    _new[*counter].func_args = arg;
    _new[*counter].timeout = 0;
    _new[*counter].id = 0;

    (*container) = _new;

    (*counter )++;
}

void reorder_events ( size_t counter, EventContainer *container, unsigned timeout )
{
    if ( counter > 1 ) {

        int i = counter - 1;

        /* start from behind excluding last added member */
        EventContainer *_it = &container[i - 1];

        EventContainer _last_added = container[i];

        for ( ; i; --i ) {
            if ( _it->timeout > timeout ) {
                *(_it + 1) = *_it;
                *_it = _last_added;
                -- _it;
            }
        }

    }
}

/* ============================================= */

/* main poll for event execution */
void *event_poll( void *arg )
{
    EventHandler *_event_handler = arg;

    while ( _event_handler->running ) {

        LOCK( _event_handler );

        if ( _event_handler->timed_events ) {

            uint32_t _time = ((uint32_t)(current_time() / 1000));

            if ( _event_handler->timed_events[0].timeout < _time ) {

                RUN_IN_THREAD ( _event_handler->timed_events[0].func,
                                _event_handler->timed_events[0].func_args );

                pop_id(&_event_handler->timed_events,
                       &_event_handler->timed_events_count,
                       _event_handler->timed_events[0].id);

            }

        }

        UNLOCK( _event_handler );

        usleep(FREQUENCY);
    }

    LOCK( _event_handler );

    clear_events(&_event_handler->timed_events, &_event_handler->timed_events_count);

    UNLOCK( _event_handler );

    _event_handler->running = -1;
    pthread_exit(NULL);
}

int throw_event( void * (func)(void *), void *arg )
{
    pthread_t _tid;
    int _rc =
        pthread_create(&_tid, NULL, func, arg );

    return (0 != _rc ) ? _rc : pthread_detach(_tid);
}

EventHandler event_handler;

/* Place and order array of timers */
int throw_timer_event ( void * (func)(void *), void *arg, unsigned timeout)
{
    static int _unique_id = 1;

    push_event(&event_handler.timed_events, &(event_handler.timed_events_count), func, arg );

    size_t _counter = event_handler.timed_events_count;

    event_handler.timed_events[_counter - 1].timeout = timeout + ((uint32_t)(current_time() / 1000));
    event_handler.timed_events[_counter - 1].id = _unique_id;
    ++_unique_id;


    /* reorder */

    reorder_events(_counter, event_handler.timed_events, timeout );

    return _unique_id - 1;
}

int execute_timer_event ( int id )
{
    int _status;

    LOCK((&event_handler));
    EventContainer *_it = event_handler.timed_events;

    int _i = event_handler.timed_events_count;

    /* Find it and execute */
    for ( ; _i; _i-- ) {
        if ( _it->id == id ) {
            RUN_IN_THREAD ( _it->func, _it->func_args );
            break;
        }

        ++_it;
    }

    /* Now remove it from the queue */

    if ( _i ) {
        for ( ; _i; -- _i ) {
            *_it = *(_it + 1);
            ++_it;
        }

        -- event_handler.timed_events_count;

        if ( !event_handler.timed_events_count ) { /* Free and set to null */
            free(event_handler.timed_events);
            event_handler.timed_events = NULL;
        } else {
            void *_result = realloc(event_handler.timed_events,
                                    sizeof(EventContainer) * event_handler.timed_events_count); /* resize */

            if ( _result != NULL ) {
                event_handler.timed_events = _result;
            } else {
                /* Not sure what would happen next so abort execution.
                */
                fprintf(stderr, "CRITICAL! Failed to reallocate memory in %s():%d, aborting...", __func__, __LINE__);
                abort();
                return -1;
            }
        }

        _status = 0;

    } else _status = -1;

    UNLOCK((&event_handler));

    return _status;
}

int reset_timer_event ( int id, uint32_t timeout )
{
    int _status;

    LOCK((&event_handler));

    EventContainer *_it = event_handler.timed_events;

    int _i = event_handler.timed_events_count;

    /* Find it and change */
    for ( ; _i; _i-- ) {
        if ( _it->id == id ) {
            _it->timeout = timeout + ((uint32_t)(current_time() / 1000));
            break;
        }

        ++_it;
    }

    _status = _i ? -1 : 0;

    UNLOCK((&event_handler));

    return _status;
}

/* Remove timer from array */
inline__ int cancel_timer_event ( int id )
{
    return pop_id (&event_handler.timed_events, &event_handler.timed_events_count, id );
}


/* Initialization and termination of event polls
 * This will be run at the beginning and the end of the program execution.
 * I think that's the best way to do it.
 */

void __attribute__((constructor)) init_event_poll ()
{
    event_handler.timed_events = NULL;
    event_handler.timed_events_count = 0;

    event_handler.running = 1;

    pthread_mutex_init(&event_handler.mutex, NULL);

    RUN_IN_THREAD(event_poll, &event_handler);
}

/* NOTE: Do we need this? */
void __attribute__((destructor)) terminate_event_poll()
{
    /* Exit thread */
    event_handler.running = 0;

    /* Give it enought time to exit */
    usleep(FREQUENCY * 2);

    pthread_mutex_destroy( &event_handler.mutex );
}