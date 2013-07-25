#ifndef _HELPER_H_
#define _HELPER_H_

#include <time.h>
#include <inttypes.h>
/* PLACE ALL YOUR HELPER FUNCTIONS/MACROS HERE */

/* Current time, unix format */
#define unix_time() ((uint32_t)time(NULL)) /* Replaced this from DHT.h to here since i will be using it too !Red!*/

#define SUCCESS 0
#define FAILURE -1

int         set_ip_port(const char* _ip, short _port, void* _cont);
uint32_t    get_random_number( uint32_t _max);

void        memadd(uint8_t* _dest, uint16_t _from, const uint8_t* _source, uint16_t _size);

#endif /* _HELPER_H_ */
