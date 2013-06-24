#include "DHT.h"


//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {.family = AF_INET, .ip = ip_port.ip, .port = ip_port.port};
    
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

//Attempt to add client with ip_port and client_id to the friends client list and close_clientlist
int addto_lists(IP_Port ip_port, char * client_id)
{
    
    
    
}


//send a ping request
//Currently incomplete: missing the ping_id part
int pingreq(IP_Port ip_port)
{
    char data[37];
    data[0] = 0;
    
    memcpy(data + 5, self_client_id, 32);
    
    sendpacket(ip_port, data, sizeof(data));
    
}

//send a ping response
//Currently incomplete: missing the ping_id part
int pingres(IP_Port ip_port, uint32_t ping_id)
{
    char data[37];
    data[0] = 1;
    
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, 32);
    
    sendpacket(ip_port, data, sizeof(data));
    
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

//send a getnodes request
//Currently incomplete: missing the ping_id part
int sendnodes(IP_Port ip_port, char * client_id)
{
   char data[325];
   data[0] = 3;
   
   memcpy(data + 5, self_client_id, 32);
   memcpy(data + 37, client_id, 32);
   
   sendpacket(ip_port, data, sizeof(data));
}




//Packet handling functions
//One to handle each types of packets

int handle_pingreq(char * packet, uint32_t length, IP_Port source)
{
    uint32_t ping_id;
    
    memcpy(&ping_id, packet + 1, 4);
    
    pingres(source, ping_id);
    
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
        //TODO: try to add requesting node to client_list if packet is valid
        break;        
    case 1:
        handle_pingres(packet, length, source);
        break;        
    case 2:
        handle_getnodes(packet, length, source);
        //TODO: try to add requesting node to client_list if packet is valid
        break;        
    case 3:
        handle_sendnodes(packet, length, source);
        break;
    default: 
        return;
        
    }
    

}




void doDHT()
{
    
    
    
}




void bootstrap(IP_Port ip_port)
{

    getnodes(ip_port, self_client_id);
    
}

