#include "DHT.h"

//send a getnodes request
int getnodes()
{
    
    
    
    
}

//send a ping request
//Currently incomplete: missing the ping_id part
int ping(IP_Port ip_port)
{
    char data[37];
    data[0] = 00;
    memcpy(data + 5, self_client_id, 32);
//ADDR addr = {.family = AF_INET, .ip = ip_port.ip, .port = ip_port.port};
    
//return sendto(sock, data, sizeof(data) - 1, 0, (struct sockaddr *)&addr, addrlen);
    //sendto(int socket_descriptor, char *buffer, int buffer_length, int flags, struct sockaddr *destination_address, int address_length);
}



void addfriend(char * client_id)
{
    
    
    
    
}





char delfriend(char * client_id)
{
    
    
    
    
}





IP_Port getfriendip(char * client_id)
{
    
    
    
}




void DHT_recvpacket(char * packet, uint32_t length)
{

}




void doDHT()
{
    
    
    
}




void bootstrap(IP_Port ip_port)
{
    
    
    
    
}

