/* LAN_discovery.h
 * 
 * LAN discovery implementation.
 * 
 */


#ifndef LAN_DISCOVERY_H 
#define LAN_DISCOVERY_H 


#include "DHT.h"


/*Send a LAN discovery pcaket to the broadcast address with port port*/
int send_LANdiscovery(uint16_t port);


/* if we receive a packet we call this function so it can be handled.
   return 0 if packet is handled correctly.
   return 1 if it didn't handle the packet or if the packet was shit. */
int LANdiscovery_handlepacket(uint8_t * packet, uint32_t length, IP_Port source);





#endif
