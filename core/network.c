/* network.h
* 
* Functions for the core networking.
* 
 
    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
    
*/

#include "network.h"


//returns current time in milleseconds since the epoch.
uint64_t current_time()
{
    uint64_t time;
    #ifdef WIN32
    //TODO: windows version
    #else
    struct timeval a;
    gettimeofday(&a, NULL);
    time = 1000000UL*a.tv_sec + a.tv_usec;
    #endif
    return time;
    
}

int random_int()
{
    #ifdef WIN32
    //TODO replace rand with a more random windows function
    return rand();
    #else
    return random();
    #endif
}

//our UDP socket, a global variable.
static int sock;

//Basic network functions:
//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {AF_INET, ip_port.port, ip_port.ip}; 
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
    
}

//Function to recieve data, ip and port of sender is put into ip_port
//the packet data into data
//the packet length into length.
//dump all empty packets.
int recievepacket(IP_Port * ip_port, char * data, uint32_t * length)
{
    ADDR addr;
    uint32_t addrlen = sizeof(addr);
    (*(int *)length) = recvfrom(sock, data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    if(*(int *)length <= 0)
    {
        //nothing recieved
        //or empty packet
        return -1;
    }
    ip_port->ip = addr.ip;
    ip_port->port = addr.port;
    return 0;
    
}

//initialize networking
//bind to ip and port
//ip must be in network order EX: 127.0.0.1 = (7F000001)
//port is in host byte order (this means don't worry about it)
//returns 0 if no problems
//TODO: add something to check if there are errors
int init_networking(IP ip ,uint16_t port)
{
    #ifdef WIN32
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
    {
        return -1;
    }
    
    #else
    srandom((uint32_t)current_time());
    #endif
    srand((uint32_t)current_time());
    
    //initialize our socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    
    //Functions to increase the size of the send and recieve UDP buffers
    //NOTE: uncomment if necessary
    /*
    int n = 1024 * 1024 * 2;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&n, sizeof(n)) == -1)
    {
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&n, sizeof(n)) == -1)
    {
        return -1;
    }*/
    
    //Set socket nonblocking
    #ifdef WIN32
    //I think this works for windows
    u_long mode = 1;
    //ioctl(sock, FIONBIO, &mode);
    ioctlsocket(sock, FIONBIO, &mode); 
    #else
    fcntl(sock, F_SETFL, O_NONBLOCK, 1);
    #endif
    
    //Bind our socket to port PORT and address 0.0.0.0
    ADDR addr = {AF_INET, htons(port), ip}; 
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));   
    return 0;

}

//function to cleanup networking stuff
void shutdown_networking()
{
    #ifdef WIN32
    WSACleanup();
    #endif
    return;
}