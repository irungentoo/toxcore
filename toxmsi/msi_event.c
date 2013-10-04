#include "msi_event.h"

#include "../toxrtp/rtp_helper.h"
#include <assert.h>

void* event_poll( void* _event_handler_p )
{
    event_handler_t* _event_handler = _event_handler_p;
    uint32_t* _frequms = &_event_handler->_frequms;

    while ( _event_handler->_running )
    {
        if ( _event_handler->_events ){
            int i;
            pthread_mutex_lock(&_event_handler->_mutex);

            assert(_event_handler->_events_count);
            for ( i = 0; i < _event_handler->_events_count; i ++ ){
                _event_handler->_events[i](_event_handler->_events_args[i]);

            }
            pthread_mutex_unlock(&_event_handler->_mutex);

            clear_events(_event_handler);
        }
        usleep(*_frequms);
    }

    _event_handler->_running = -1;
    pthread_exit(NULL);
}

void throw_event( void* _event_handler_p, event_t _func, event_arg_t _arg )
{
    event_handler_t* _event_handler = _event_handler_p;

    pthread_mutex_lock(&_event_handler->_mutex);

    if ( _event_handler->_events ){
        _event_handler->_events_count++;
        _event_handler->_events = realloc(_event_handler->_events, sizeof(event_t) * _event_handler->_events_count);
        assert(_event_handler->_events != NULL);
        _event_handler->_events_args = realloc(_event_handler->_events_args, sizeof(event_arg_t) *_event_handler->_events_count);
        assert(_event_handler->_events_args != NULL);

        _event_handler->_events[_event_handler->_events_count - 1] = _func;
        _event_handler->_events_args[_event_handler->_events_count - 1] = _arg;
    } else {
        _event_handler->_events = malloc(sizeof(event_t));
        assert(_event_handler->_events != NULL);
        _event_handler->_events_args = malloc(sizeof(event_arg_t));
        assert(_event_handler->_events_args != NULL );

        _event_handler->_events[0] = _func;
        _event_handler->_events_args[0] = _arg;
        _event_handler->_events_count ++;
    }

    pthread_mutex_unlock(&_event_handler->_mutex);
}
void clear_events (event_handler_t* _event_handler)
{
    pthread_mutex_lock(&_event_handler->_mutex);

    if ( _event_handler->_events ) {
        free(_event_handler->_events);
        _event_handler->_events = NULL;
    }
    if ( _event_handler->_events_args ){
        free(_event_handler->_events_args);
        _event_handler->_events_args = NULL;
    }

    _event_handler->_events_count = 0;

    pthread_mutex_unlock(&_event_handler->_mutex);
}

event_handler_t* init_event_poll (uint32_t _frequms)
{
    event_handler_t* _retu = malloc(sizeof(event_handler_t));
    _retu->_events = NULL;
    _retu->_events_args = NULL;
    _retu->_events_count = 0;
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

    clear_events(_handler);
    pthread_mutex_destroy( &_handler->_mutex );

    free(_handler);

    return SUCCESS;
}

