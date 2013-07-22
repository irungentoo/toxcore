/* friend_requests.h
 * 
 * Handle friend requests.
 * 
 */


#ifndef FRIEND_REQUESTS_H 
#define FRIEND_REQUESTS_H  


#include "DHT.h"
#include "net_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Try to send a friendrequest to peer with public_key
   data is the data in the request and length is the length. */
int send_friendrequest(uint8_t * public_key, uint8_t * data, uint32_t length);


/* set the function that will be executed when a friend request for us is received.
   function format is function(uint8_t * public_key, uint8_t * data, uint16_t length) */
void callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t));

/* if we receive a packet we call this function so it can be handled.
   return 0 if packet is handled correctly.
   return 1 if it didn't handle the packet or if the packet was shit. */
int friendreq_handlepacket(uint8_t * packet, uint32_t length, IP_Port source);



#ifdef __cplusplus
}
#endif

#endif