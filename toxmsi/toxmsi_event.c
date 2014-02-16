/* toxmsi_event.c
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

/*----------------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

#include "toxmsi_event.h"

#include "../toxrtp/toxrtp_helper.h"
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

static int _unique_id = 1;

/* clear events */
void clear_events (event_container_t** _event_container, size_t* _counter)
{
    assert( *_event_container );

    free(*_event_container);
    *_event_container = NULL;

    *_counter = 0;
}

int pop_id ( event_container_t** _event_container, size_t* _counter, int _id )
{
    if ( !*_event_container || !*_counter || !_id )
        return FAILURE;

    event_container_t* _it = *_event_container;
    int i;

    for ( i = *_counter; i > 0 ; -- i ){
        if ( _it->_id == _id ) { /* Hit! */
            break;
        }
        ++_it;
    }

    if ( i ) {
        for ( ; i > 0; -- i ){ *_it = *(_it + 1); ++_it; }
        -- (*_counter);
        *_event_container = realloc(*_event_container, sizeof(event_container_t) * (*_counter)); /* resize */

        if ( *_counter )
            assert(*_event_container);

        return SUCCESS;

    } else {
        assert(i);
        return FAILURE;
    }
}

/* main poll for event execution */
void* event_poll( void* _event_handler_p )
{
    event_handler_t* _event_handler = _event_handler_p;
    uint32_t* _frequms = &_event_handler->_frequms;


    while ( _event_handler->_running )
    {

        if ( _event_handler->_events_count ){
            pthread_mutex_lock(&_event_handler->_mutex);

            int i;
            for ( i = 0; i < _event_handler->_events_count; i ++ ){
                _event_handler->_events[i]._event(_event_handler->_events[i]._event_args);

            }
            clear_events(&_event_handler->_events, &_event_handler->_events_count);

            pthread_mutex_unlock(&_event_handler->_mutex);
        }

        if ( _event_handler->_timed_events_count ){
            pthread_mutex_lock(&_event_handler->_mutex);

            uint32_t _time = t_time();

            if ( _event_handler->_timed_events[0]._timeout < _time ) {
                _event_handler->_timed_events[0]._event(_event_handler->_timed_events[0]._event_args);

                pop_id(&_event_handler->_timed_events,
                       &_event_handler->_timed_events_count,
                       _event_handler->_timed_events[0]._id);
            }
            pthread_mutex_unlock(&_event_handler->_mutex);
        }


        usleep(*_frequms);
    }

    _event_handler->_running = -1;
    pthread_exit(NULL);
}

void push_event ( event_container_t** _container, size_t* _counter, event_t _func, event_arg_t _arg )
{
    (*_counter)++;
    (*_container) = realloc((*_container), sizeof(event_container_t) * (*_counter));
    assert((*_container) != NULL);

    (*_container[*_counter - 1])._event = _func;
    (*_container[*_counter - 1])._event_args = _arg;
    (*_container[*_counter - 1])._timeout = 0;
    (*_container[*_counter - 1])._id = 0;
}

void throw_event( void* _event_handler_p, event_t _func, event_arg_t _arg )
{
    if ( !_func )
        return;

    event_handler_t* _event_handler = _event_handler_p;

    pthread_mutex_lock(&_event_handler->_mutex);

    push_event(&_event_handler->_events, &_event_handler->_events_count, _func, _arg);

    pthread_mutex_unlock(&_event_handler->_mutex);
}

int throw_timer_event ( void* _event_handler_p, event_t _func, event_arg_t _arg, uint32_t _timeout)
{
    if ( !_func )
        return FAILURE;

    event_handler_t* _event_handler = _event_handler_p;

    pthread_mutex_lock(&_event_handler->_mutex);

    push_event(&_event_handler->_timed_events, &_event_handler->_timed_events_count, _func, _arg);
    size_t _counter = _event_handler->_timed_events_count;
    _event_handler->_timed_events[_counter - 1]._timeout = _timeout + t_time();
    _event_handler->_timed_events[_counter - 1]._id = _unique_id; ++_unique_id;


    /* reorder */
    if ( _counter > 1 ) {

        int i = _counter - 1;
        /* start from behind excluding last added member */
        event_container_t* _it = &_event_handler->_timed_events[i - 1];

        event_container_t _last_added = _event_handler->_timed_events[i];

        for ( ; i > 0; --i ) {
            if ( _it->_timeout > _timeout ){
                *(_it + 1) = *_it;
                *_it = _last_added; -- _it;
            }
        }

    }

    pthread_mutex_unlock(&_event_handler->_mutex);

    return _event_handler->_timed_events[_counter - 1]._id;
}
int cancel_timer_event ( void* _event_handler_p, int _id )
{
    event_handler_t* _event_handler = _event_handler_p;
    return pop_id(&_event_handler->_timed_events, &_event_handler->_timed_events_count, _id);
}

event_handler_t* init_event_poll (uint32_t _frequms)
{
    event_handler_t* _retu = calloc(sizeof(event_handler_t), 1);
    assert(_retu);
    /* Initialize basic events */
    _retu->_events = NULL ;

    /* Initialize timed events */
    _retu->_timed_events = NULL;

    _retu->_frequms = _frequms;
    _retu->_running = 1;
    pthread_mutex_init(&_retu->_mutex, NULL);

    pthread_create(&_retu->_thread_id, NULL, event_poll, _retu);
    int _rc = pthread_detach(_retu->_thread_id);
    assert(_rc == 0);

    return _retu;
}

int terminate_event_poll(event_handler_t* _handler)
{
    if ( !_handler )
        return FAILURE;

    _handler->_running = 0;
    while (_handler->_running != -1); /* Wait for execution */

    if (_handler->_events)
        clear_events(&_handler->_events, &_handler->_events_count);
    if (_handler->_events)
        clear_events(&_handler->_timed_events, &_handler->_timed_events_count);

    pthread_mutex_destroy( &_handler->_mutex );

    free(_handler);

    return SUCCESS;
}

