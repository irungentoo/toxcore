/* Lossless_UDP testclient
 * A program that connects and sends a file using our lossless UDP algorithm.
 * NOTE: this program simulates a 33% packet loss.
 *
 * Best used in combination with Lossless_UDP_testserver
 *
 * Compile with: gcc -O2 -Wall -lsodium -o testclient ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testclient.c
 *
 * Command line arguments are the ip and port to connect and send the file to.
 * EX: ./testclient 127.0.0.1 33445 filename.txt
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/network.h"
#include "../toxcore/Lossless_UDP.h"
#include "misc_tools.c"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

#define PORT 33446

void printpacket(uint8_t *data, uint32_t length, IP_Port ip_port)
{
    uint32_t i;
    printf("UNHANDLED PACKET RECEIVED\nLENGTH:%u\nCONTENTS:\n", length);
    printf("--------------------BEGIN-----------------------------\n");

    for (i = 0; i < length; i++) {
        if (data[i] < 16)
            printf("0");

        printf("%hhX", data[i]);
    }

    printf("\n--------------------END-----------------------------\n\n\n");
}

void printip(IP_Port ip_port)
{
    printf("\nIP: %s Port: %u", ip_ntoa(&ip_port.ip), ntohs(ip_port.port));
}
/*
void printpackets(Data test)
{
    int i;
    if(test.size == 0)
        return;
    printf("SIZE: %u\n", test.size);
    for(i =0; i < test.size; i++)
    {
        printf("%hhX", test.data[i]);
    }
    printf("\n");
}

void printconnection(int connection_id)
{
    printf("--------------------BEGIN---------------------\n");
    IP_Port ip_port = connections[connection_id].ip_port;
    printf("IP: %u.%u.%u.%u Port: %u\n",ip_port.ip.c[0],ip_port.ip.c[1],ip_port.ip.c[2],ip_port.ip.c[3],ntohs(ip_port.port));
    printf("status: %u, inbound: %u, SYNC_rate: %u\n", connections[connection_id].status,
    connections[connection_id].inbound, connections[connection_id].SYNC_rate);
    printf("data rate: %u, last sync: %llu, last sent: %llu, last recv: %llu \n", connections[connection_id].data_rate,
    connections[connection_id].last_SYNC, connections[connection_id].last_sent, connections[connection_id].last_recv);
    int i;
    for(i =0; i < MAX_QUEUE_NUM; i++)
    {
        printf(" %u ",i);
        printpackets(connections[connection_id].sendbuffer[i]);
    }
    for(i =0; i < MAX_QUEUE_NUM; i++)
    {
        printf(" %u ",i);
        printpackets(connections[connection_id].recvbuffer[i]);
    }
    Data sendbuffer[MAX_QUEUE_NUM];
    Data recvbuffer[MAX_QUEUE_NUM];
    printf("recv_num: %u, orecv_num: %u, sent_packetnum %u, osent_packetnum: %u, successful_sent: %u, successful_read: %u\n",
    connections[connection_id].recv_packetnum,
    connections[connection_id].orecv_packetnum, connections[connection_id].sent_packetnum, connections[connection_id].osent_packetnum,
    connections[connection_id].successful_sent,
    connections[connection_id].successful_read);

    printf("req packets: \n");
    for(i = 0; i < BUFFER_PACKET_NUM; i++)
    {
            printf(" %u ", connections[connection_id].req_packets[i]);
    }
    printf("\nNumber: %u recv_counter: %u, send_counter: %u\n", connections[connection_id].num_req_paquets,
    connections[connection_id].recv_counter, connections[connection_id].send_counter);

    printf("--------------------END---------------------\n");

}
*/

/*( receive packets and send them to the packethandler */
/*run doLossless_UDP(); */
//void Lossless_UDP()
//{
/*    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while (receivepacket(&ip_port, data, &length) != -1) {
    printf("packet with length: %u\n", length); */
/* if(rand() % 3 != 1)//add packet loss
 { */
/*
            if (LosslessUDP_handlepacket(data, length, ip_port))
                printpacket(data, length, ip_port);
            else
            printf("Received handled packet with length: %u\n", length); //printconnection(0); */

/* } */
/* }*/

//networking_poll();

//doLossless_UDP();

//}

int main(int argc, char *argv[])
{
    /* let user override default by cmdline */
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    if (argc < argvoffset + 4) {
        printf("Usage: %s [--ipv4|--ipv6] ip port filename\n", argv[0]);
        exit(0);
    }

    uint8_t buffer[MAX_DATA_SIZE];
    int read;

    FILE *file = fopen(argv[argvoffset + 3], "rb");

    if (file == NULL) {
        printf("Failed to open file \"%s\".\n", argv[argvoffset + 3]);
        return 1;
    }


    /* initialize networking */
    /* bind to ip 0.0.0.0:PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    Lossless_UDP *ludp = new_lossless_udp(new_networking(ip, PORT));
    perror("Initialization");

    IP_Port serverip;
    ip_init(&serverip.ip, ipv6enabled);

    if (!addr_resolve(argv[argvoffset + 1], &serverip.ip, NULL)) {
        printf("Failed to convert \"%s\" into an IP address.\n", argv[argvoffset + 1]);
        return 1;
    }

    serverip.port = htons(atoi(argv[argvoffset + 2]));
    printip(serverip);

    int connection = new_connection(ludp, serverip);
    uint64_t timer = current_time();

    while (1) {
        /* printconnection(connection); */
        networking_poll(ludp->net);
        do_lossless_udp(ludp);

        if (is_connected(ludp, connection) == LUDP_ESTABLISHED) {
            printf("Connecting took: %llu us\n", (unsigned long long)(current_time() - timer));
            break;
        }

        if (is_connected(ludp, connection) == LUDP_NO_CONNECTION) {
            printf("Connection timeout after: %llu us\n", (unsigned long long)(current_time() - timer));
            return 1;
        }

        c_sleep(1);
    }

    timer = current_time();
    unsigned long long bytes_sent = 0;

    /*read first part of file */
    read = fread(buffer, 1, MAX_DATA_SIZE, file);

    while (1) {
        /* printconnection(connection); */
        networking_poll(ludp->net);
        do_lossless_udp(ludp);

        if (is_connected(ludp, connection) == LUDP_ESTABLISHED) {

            while (write_packet(ludp, connection, buffer, read)) {
                bytes_sent += read;
                /* printf("Wrote data.\n"); */
                read = fread(buffer, 1, MAX_DATA_SIZE, file);

            }

            /* printf("%u\n", sendqueue(connection)); */
            if (sendqueue(ludp, connection) == 0) {
                if (read == 0) {
                    unsigned long long us = (unsigned long long)(current_time() - timer);
                    printf("Sent file successfully in: %llu us = %llu seconds. Average speed: %llu KB/s\n", us, us / 1000000UL,
                           bytes_sent / (us / 1024UL));
                    //printf("Total bytes sent: %llu B, Total data sent: %llu B, overhead: %llu B\n", total_bytes_sent, bytes_sent, total_bytes_sent-bytes_sent);
                    break;
                }
            }
        } else {
            printf("%u Client Connecting Lost after: %llu us\n", is_connected(ludp, connection),
                   (unsigned long long)(current_time() - timer));
            return 0;
        }

    }

    c_sleep(25);

    return 0;
}
