#include "DHT.h"


//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {.family = AF_INET, .ip = ip_port.ip, .port = ip_port.port};
    
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}



//send a getnodes request
//Currently incomplete: missing the ping_id part
int getnodes(IP_Port ip_port, char * client_id)
{
   char data[69];
   data[0] = 2;
   
   memcpy(data + 5, self_client_id, 32);
   memcpy(data + 37, client_id, 32);
   
   sendpacket(ip_port, data, sizeof(data));
}

//send a ping request
//Currently incomplete: missing the ping_id part
int ping(IP_Port ip_port)
{
    char data[37];
    data[0] = 0;
    
    memcpy(data + 5, self_client_id, 32);
    
    sendpacket(ip_port, data, sizeof(data));
    
}


//Packet handling functions
//One to handle each types of packets

int handle_pingreq(char * packet, uint32_t length, IP_Port source)
{
    
    
}

int handle_pingres(char * packet, uint32_t length, IP_Port source)
{
    
    
}

int handle_getnodes(char * packet, uint32_t length, IP_Port source)
{
    
    
}

int handle_sendnodes(char * packet, uint32_t length, IP_Port source)
{
    
    
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




void DHT_recvpacket(char * packet, uint32_t length, IP_Port source)
{
    switch (packet[0]) {
    case 0:
        handle_pingreq(packet, length, source);
        break;        
    case 1:
        handle_pingres(packet, length, source);
        break;        
    case 2:
        handle_getnodes(packet, length, source);
        break;        
    case 3:
        handle_sendnodes(packet, length, source);
        break;
    default: 
        break;
        
    }
    

}




void doDHT()
{
    
    
    
}




void bootstrap(IP_Port ip_port)
{
    
    
    
    
}

