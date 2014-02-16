/* toxmsi_event.h
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

#ifndef _MSI__EVENT_H_
#define _MSI__EVENT_H_

#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>

typedef void* event_arg_t;

typedef void ( *event_t ) ( event_arg_t );
typedef void ( *timed_event_t ) ( event_arg_t );

typedef struct event_container_s {
    event_t            _event;
    event_arg_t        _event_args;
    uint32_t           _timeout;
    long long          _id;

} event_container_t;

typedef struct event_handler_s {
    event_container_t* _events;
    size_t             _events_count;

    event_container_t* _timed_events;
    size_t             _timed_events_count;

    uint32_t           _frequms;
    int                _running;

    pthread_mutex_t    _mutex;
    pthread_t          _thread_id;

} event_handler_t;

event_handler_t*    init_event_poll         ( uint32_t _frequms );
int                 terminate_event_poll    ( event_handler_t* _event_handler );

void                throw_event             ( void* _event_handler_p, event_t _func, event_arg_t _arg );

/* Not yet ready for use */
int                 throw_timer_event       ( void* _event_handler_p, event_t _func, event_arg_t _arg, uint32_t _timeout);
int                 cancel_timer_event      ( void* _event_handler_p, int _id );


#endif /* _MSI__EVENT_H_ */
