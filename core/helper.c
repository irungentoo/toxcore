#include "helper.h"
#include "network.h"

static int _seed = -1; /* Not initiated */

int set_ip_port ( const char* _ip, short _port, void* _dest )
    {
    if ( !_dest ) {
            return FAILURE;
            }

    IP_Port* _dest_c = ( IP_Port* ) _dest;

    _dest_c->ip.i = inet_addr ( _ip );
    _dest_c->port = htons ( _port );

    return SUCCESS;
    }

uint32_t get_random_number ( uint32_t _max )
    {
    if ( _seed < 0 ) {
            srand ( unix_time() );
            _seed++;
            }

    if ( _max <= 0 ) {
            return rand();
            }
    else {
            return rand() % _max;
            }
    }

void        memadd ( uint8_t* _dest, uint16_t _from, const uint8_t* _source, uint16_t _size )
    {
    for ( uint16_t it = 0; _from < _size; _from ++ ) {
            _dest[_from] = _source[it];
            it ++;
            }
    }
