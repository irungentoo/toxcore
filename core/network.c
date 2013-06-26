

#include "network.h"

//our UDP socket, a global variable.
static int sock;

//Basic network functions:
//TODO: put them somewhere else than here

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
    #endif
    
    //initialize our socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    
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