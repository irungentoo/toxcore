/* LAN_discovery.c
 * 
 * LAN discovery implementation.
 * 
 */

#include "LAN_discovery.h"


/*Return the broadcast ip
  TODO: make it return the real one, not the 255.255.255.255 one.*/
IP broadcast_ip()
{
    IP ip;
    ip.i = ~0;
    return ip;
}

/*return 0 if ip is a LAN ip
  return -1 if it is not */
int LAN_ip(IP ip)
{
    if(ip.c[0] == 127)/* Loopback */
        return 0;
    if(ip.c[0] == 10)/* 10.0.0.0 to 10.255.255.255 range */
        return 0;
    if(ip.c[0] == 172 && ip.c[1] >= 16 && ip.c[1] <= 31)/* 172.16.0.0 to 172.31.255.255 range */
        return 0;
    if(ip.c[0] == 192 && ip.c[1] == 168) /* 192.168.0.0 to 192.168.255.255 range */
        return 0;
    if(ip.c[0] == 169 && ip.c[1] == 254 && ip.c[2] != 0 && ip.c[2] != 255)/* 169.254.1.0 to 169.254.254.255 range */
        return 0;
    return -1;
}

int handle_LANdiscovery(uint8_t * packet, uint32_t length, IP_Port source)
{
    if(LAN_ip(source.ip) == -1)
        return 1;
    if(length != crypto_box_PUBLICKEYBYTES + 1)
        return 1;
    DHT_bootstrap(source, packet + 1);
    return 0;
}


int send_LANdiscovery(uint16_t port)
{
    uint8_t data[crypto_box_PUBLICKEYBYTES + 1];
    data[0] = 32;
    memcpy(data + 1, self_public_key, crypto_box_PUBLICKEYBYTES);
    IP_Port ip_port = {broadcast_ip(), port};
    return sendpacket(ip_port, data, 1 + crypto_box_PUBLICKEYBYTES);
}


int LANdiscovery_handlepacket(uint8_t * packet, uint32_t length, IP_Port source)
{
    if(packet[0] == 32)
        return handle_LANdiscovery(packet, length, source);
    return 1;
}
