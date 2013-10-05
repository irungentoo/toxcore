#ifndef _MSI__EVENT_H_
#define _MSI__EVENT_H_

#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>

typedef void* event_arg_t;
typedef void (*event_t) (event_arg_t);

typedef struct event_handler_s
{
    event_t*            _events;
    event_arg_t*        _events_args;
    size_t              _events_count;
    uint32_t            _frequms;
    int                 _running;

    pthread_mutex_t     _mutex;
    pthread_t           _thread_id;

} event_handler_t;

event_handler_t*    init_event_poll     (uint32_t _frequms);
int                 terminate_event_poll(event_handler_t* _event_handler);

void                clear_events (event_handler_t* _event_handler);
void                throw_event  ( void* _event_handler, event_t _func, event_arg_t _arg );


#endif /* _MSI__EVENT_H_ */
