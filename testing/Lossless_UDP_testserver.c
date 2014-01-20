/* Lossless_UDP testserver
 * A program that waits for a lossless UDP connection and then saves all the data received to a file.
 * NOTE: this program simulates a 33% packet loss.
 *
 * Best used in combination with Lossless_UDP_testclient
 *
 * Compile with: gcc -O2 -Wall -lsodium -o testserver ../core/network.c ../core/Lossless_UDP.c Lossless_UDP_testserver.c
 *
 * Command line argument is the name of the file to save what we receive to.
 * EX: ./testserver filename1.txt
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

//Sleep function (x = milliseconds)
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

#define PORT 33445

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

/* receive packets and send them to the packethandler
 * run doLossless_UDP(); */
//void Lossless_UDP()
//{
//    IP_Port ip_port;
//    uint8_t data[MAX_UDP_PACKET_SIZE];
//    uint32_t length;
//    while (receivepacket(&ip_port, data, &length) != -1) {
//if(rand() % 3 != 1)//add packet loss
//{
//            if (LosslessUDP_handlepacket(data, length, ip_port)) {
//                    printpacket(data, length, ip_port);
//            } else {
//printconnection(0);
//                 printf("Received handled packet with length: %u\n", length);
//            }
//}
//    }

// networking_poll();

//doLossless_UDP();
//}


int main(int argc, char *argv[])
{
    /* let user override default by cmdline */
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    if (argc < argvoffset + 2) {
        printf("Usage: %s [--ipv4|--ipv6] filename\n", argv[0]);
        exit(0);
    }

    uint8_t buffer[MAX_DATA_SIZE];
    int read;

    FILE *file = fopen(argv[argvoffset + 1], "wb");

    if (file == NULL) {
        printf("Failed to open file \"%s\".\n", argv[argvoffset + 1]);
        return 1;
    }


    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip_init(&ip, ipv6enabled);

    Lossless_UDP *ludp = new_lossless_udp(new_networking(ip, PORT));
    perror("Initialization");

    int connection;
    uint64_t timer = current_time();

    while (1) {
        networking_poll(ludp->net);
        do_lossless_udp(ludp);
        connection = incoming_connection(ludp, 0);

        if (connection != -1) {
            if (is_connected(ludp, connection) == LUDP_NOT_CONFIRMED) {
                printf("Received the connection.\n");

            }

            break;
        }

        c_sleep(1);
    }

    timer = current_time();

    while (1) {
        //printconnection(0);
        networking_poll(ludp->net);

        if (is_connected(ludp, connection) >= LUDP_NOT_CONFIRMED) {
            confirm_connection(ludp, connection);

            while (1) {
                read = read_packet(ludp, connection, buffer);

                if (read != 0) {
                    // printf("Received data.\n");
                    if (!fwrite(buffer, read, 1, file))
                        printf("file write error\n");
                } else {
                    break;
                }
            }
        }

        do_lossless_udp(ludp);

        if (is_connected(ludp, connection) == LUDP_TIMED_OUT) {
            printf("Server Connecting Lost after: %llu us\n", (unsigned long long)(current_time() - timer));
            fclose(file);
            return 1;
        }

        c_sleep(25);
    }

    return 0;
}
