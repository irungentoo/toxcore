 

#include "../core/Messenger.h"

#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

//horrible function from one of my first C programs.
//only here because I was too lazy to write a proper one.
unsigned char * hex_string_to_bin(char hex_string[])
{
    unsigned char * val = malloc(strlen(hex_string));
    char * pos = hex_string;
    int i=0;
    while(i < strlen(hex_string))
    {
        sscanf(pos,"%2hhx",&val[i]);
        pos+=2;
        i++;
    }
    return val;
}

void print_request(uint8_t * public_key, uint8_t * data, uint16_t length)
{
    printf("Friend request recieved from: \n");
    printf("ClientID: ");
    uint32_t j;
    for(j = 0; j < 32; j++)
    {
        if(public_key[j] < 16)
            printf("0");
        printf("%hhX", public_key[j]);
    }
    printf("\nOf length: %u with data: %s \n", length, data);
    
    if(length != sizeof("Install Gentoo"))
    {
        return;
    }
    if(memcmp(data ,"Install Gentoo", sizeof("Install Gentoo")) == 0 )
    //if the request contained the message of peace the person is obviously a friend so we add him.
    {
        printf("Friend request accepted.\n");
        m_addfriend_norequest(public_key);
    }
}

void print_message(int friendnumber, uint8_t * string, uint16_t length)
{
    printf("Message with length %u recieved from %u: %s \n", length, friendnumber, string);
    m_sendmessage(friendnumber, "Test1", 6);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("usage %s ip port (of the DHT bootstrap node)\n", argv[0]);
        exit(0);
    }
    initMessenger();
    m_callback_friendrequest(print_request);
    m_callback_friendmessage(print_message);
    
    m_setinfo("Install Gentoo", sizeof("Install Gentoo"));//The message we send is a message of peace
    
    printf("OUR ID: ");
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16)
            printf("0");
        printf("%hhX",self_public_key[i]);
    }
    
    char temp_id[128];
    printf("\nEnter the client_id of the friend you wish to add (32 bytes HEX format):\n");
    scanf("%s", temp_id);
    int num = m_addfriend(hex_string_to_bin(temp_id));
    
    perror("Initialization");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    bootstrap_ip_port.ip.i = inet_addr(argv[1]);
    DHT_bootstrap(bootstrap_ip_port);
    
    while(1)
    {
        m_sendmessage(num, "Test", 5);
        doMessenger();
        c_sleep(30);
    }
    
}
