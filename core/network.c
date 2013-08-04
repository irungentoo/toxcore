/* network.h
 *
 * Functions for the core networking.
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

#include "network.h"

/* returns current UNIX time in microseconds (us). */
uint64_t current_time()
{
    uint64_t time;
#ifdef WIN32
    /* This probably works fine */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    time = ft.dwHighDateTime;
    time <<=32;
    time |= ft.dwLowDateTime;
    time -= 116444736000000000UL;
    return time/10;
#else
    struct timeval a;
    gettimeofday(&a, NULL);
    time = 1000000UL*a.tv_sec + a.tv_usec;
    return time;
#endif
}

/* return a random number
   NOTE: this function should probably not be used where cryptographic randomness is absolutely necessary */
uint32_t random_int()
{
#ifndef VANILLA_NACL
    //NOTE: this function comes from libsodium
    return randombytes_random();
#else
    return random();
#endif
}

/* our UDP socket, a global variable. */
static int sock;

/* Basic network functions:
   Function to send packet(data) of length length to ip_port */
int sendpacket(IP_Port ip_port, uint8_t * data, uint32_t length)
{

    ADDR addr = {AF_INET, ip_port.port, ip_port.ip};
    /* IPv6
	ADDR addr = {AF_INET6, ip_port.port, ip_port.ip}; */
	
    return sendto(sock,(char *) data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

/* Function to receive data, ip and port of sender is put into ip_port
   the packet data into data
   the packet length into length.
   dump all empty packets. */
int receivepacket(IP_Port * ip_port, uint8_t * data, uint32_t * length)
{
    ADDR addr;
#ifdef WIN32
    int addrlen = sizeof(addr);
#else
    uint32_t addrlen = sizeof(addr);
#endif
    (*(int32_t*)length) = recvfrom(sock,(char*) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
    if (*(int32_t*)length <= 0)
        return -1; /* nothing received or empty packet */

    ip_port->ip = addr.ip;
    ip_port->port = addr.port;
    return 0;
}

/* initialize networking
   bind to ip and port
   ip must be in network order EX: 127.0.0.1 = (7F000001)
   port is in host byte order (this means don't worry about it)
   returns 0 if no problems
   returns -1 if there are problems */
int init_networking(IP ip, uint16_t port)
{
uint16_t ipv4flag = 0;
#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
        return -1;
#else
    srandom((uint32_t)current_time());
#endif
    srand((uint32_t)current_time());
    
    /* as long as the 32-bit IP problem in union IP is not fixed just use
    IPv4 by default. When it is fixed, just add a 6 to AF_INET.
    The rest of the code will still work for now */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ipv4flag = 1; // force IPv4, delete this for IPv6-try then
	
	 /* initialize our socket, prefer IPv6
     sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); */
	
    /* Check for socket error */
#ifdef WIN32
    if (sock == INVALID_SOCKET) { /* MSDN recommends this */
    	// no IPv6, try IPv4 then
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
        	return -1;
        }
        ipv4flag = 1;
    }
#else
    if (sock < 0) {
    	// no IPv6, try IPv4 then
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
        	return -1;
        }
        ipv4flag = 1;
    }
#endif

    /* Functions to increase the size of the send and receive UDP buffers
       NOTE: uncomment if necessary */
    /*
    int n = 1024 * 1024 * 2;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&n, sizeof(n)) == -1)
    {
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&n, sizeof(n)) == -1)
        return -1;
    */

	if (!ipv4flag) {
	// TODO IPv6 Multicast
	/* IPv6: Obviously, there is no broadcast in IPv6, so multicast to all nodes it is
	--> ff01::1 or ff02::1 -> all nodes addresses
	
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF ,
                           &outif, sizeof(outif)); */
                           
    } else {
		/* Enable broadcast on IPv4-socket */
		int broadcast = 1;
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
    }              
    /* Set socket nonblocking */
#ifdef WIN32
    /* I think this works for windows */
    u_long mode = 1;
    /* ioctl(sock, FIONBIO, &mode); */
    ioctlsocket(sock, FIONBIO, &mode);
#else
    fcntl(sock, F_SETFL, O_NONBLOCK, 1);
#endif

	/* assume IPv6 */
	ADDR addr = {AF_INET6, htons(port), ip};
	
	if (ipv4flag)
		addr.family = AF_INET;
       
   	/* Bind our socket to port PORT and address 0.0.0.0 */
   	bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    return 0;

}

/* function to cleanup networking stuff */
void shutdown_networking()
{
#ifdef WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    return;
}

/*
  resolve_addr():
    address should represent IPv4 or a hostname with A record

    returns a data in network byte order that can be used to set IP.i or IP_Port.ip.i
    returns 0 on failure
*/
uint32_t resolve_addr(const char *address)
{
    struct addrinfo *server = NULL;
    struct addrinfo *server4 = NULL;
    struct addrinfo  hints;
    int              rc;
    uint32_t         addr = 0;
	uint16_t ipv6flag = 0; // tells us if IPv6 found

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;    // both IPv4 and IPv6 and sort later
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

	/* port 7 - echo protocol sends back everything it gets */
    rc = getaddrinfo(address, "echo", &hints, &server);

    // Lookup failed.
    if(rc != 0) {
        return 0;
    }
	
	// a bit hacky, could be prettier...
	// save server in server4 in case we do need IPv4
	memcpy(server,server4,sizeof(struct addrinfo));
	
	while(server) {
		// IPv6
		if(server->ai_family == AF_INET6) {
			ipv6flag = 1;
			addr = ((struct sockaddr_in*)server->ai_addr)->sin_addr.s_addr;
   		break;
   		} 
		server = server->ai_next;
	}
	
	// IPv4
	if (!ipv6flag){
		if(server4->ai_family == AF_INET) {
			addr = ((struct sockaddr_in*)server4->ai_addr)->sin_addr.s_addr;
		} else {
			return 0;
		}
	}
    
    freeaddrinfo(server);
    freeaddrinfo(server4);
    return addr;
}
