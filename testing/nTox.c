/* nTox.c
 *
 * Textual frontend for Tox.
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

#ifdef __WIN32__
#define _WIN32_WINNT 0x501
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#endif


#include "nTox.h"
#include "misc_tools.c"

#include <stdio.h>
#include <time.h>

#ifdef __WIN32__
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

char lines[HISTORY][STRING_LENGTH];
char line[STRING_LENGTH];

char *help = "[i] commands:\n/f ID (to add friend)\n/m friendnumber message  "
             "(to send message)\n/s status (to change status)\n[i] /l list (l"
             "ist friends)\n/h for help\n/i for info\n/n nick (to change nick"
             "name)\n/q (to quit)";
int x, y;

typedef struct {
    uint8_t id[TOX_CLIENT_ID_SIZE];
    uint8_t accepted;
} Friend_request;

Friend_request pending_requests[256];
uint8_t num_requests = 0;

/*
  resolve_addr():
    address should represent IPv4 or a hostname with A record

    returns a data in network byte order that can be used to set IP.i or IP_Port.ip.i
    returns 0 on failure

    TODO: Fix ipv6 support
*/

uint32_t resolve_addr(const char *address)
{
    struct addrinfo *server = NULL;
    struct addrinfo  hints;
    int              rc;
    uint32_t         addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;    // IPv4 only right now.
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

#ifdef __WIN32__
    int res;
    WSADATA wsa_data;

    res = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (res != 0) {
        return 0;
    }

#endif

    rc = getaddrinfo(address, "echo", &hints, &server);

    // Lookup failed.
    if (rc != 0) {
#ifdef __WIN32__
        WSACleanup();
#endif
        return 0;
    }

    // IPv4 records only..
    if (server->ai_family != AF_INET) {
        freeaddrinfo(server);
#ifdef __WIN32__
        WSACleanup();
#endif
        return 0;
    }


    addr = ((struct sockaddr_in *)server->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(server);
#ifdef __WIN32__
    WSACleanup();
#endif
    return addr;
}

void get_id(Tox *m, char *data)
{
    sprintf(data, "[i] ID: ");
    int offset = strlen(data);
    int i = 0;
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_getaddress(m, address);

    for (; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        sprintf(data + 2 * i + offset, "%02X ", address[i]);
    }
}

void new_lines(char *line)
{
    int i = 0;

    for (i = HISTORY - 1; i > 0; i--)
        strncpy(lines[i], lines[i - 1], STRING_LENGTH - 1);

    strncpy(lines[0], line, STRING_LENGTH - 1);
    do_refresh();
}


void print_friendlist(Tox *m)
{
    char name[TOX_MAX_NAME_LENGTH];
    int i = 0;
    new_lines("[i] Friend List:");

    while (tox_getname(m, i, (uint8_t *)name) != -1) {
        /* account for the longest name and the longest "base" string */
        char fstring[TOX_MAX_NAME_LENGTH + strlen("[i] Friend: NULL\n\tid: ")];

        if (strlen(name) <= 0) {
            sprintf(fstring, "[i] Friend: No Friend!\n\tid: %i", i);
        } else {
            sprintf(fstring, "[i] Friend: %s\n\tid: %i", (uint8_t *)name, i);
        }

        i++;
        new_lines(fstring);
    }

    if (i == 0)
        new_lines("\tno friends! D:");
}

char *format_message(Tox *m, char *message, int friendnum)
{
    char name[TOX_MAX_NAME_LENGTH];

    if (friendnum != -1) {
        tox_getname(m, friendnum, (uint8_t *)name);
    } else {
        tox_getselfname(m, (uint8_t *)name, sizeof(name));
    }

    char *msg = malloc(100 + strlen(message) + strlen(name) + 1);

    time_t rawtime;
    struct tm *timeinfo;
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char *time = asctime(timeinfo);
    size_t len = strlen(time);
    time[len - 1] = '\0';

    if (friendnum != -1) {
        sprintf(msg, "[%d] %s <%s> %s", friendnum, time, name, message);
    } else {
        // This message came from ourselves
        sprintf(msg, "%s <%s> %s", time, name, message);
    }

    return msg;
}

void line_eval(Tox *m, char *line)
{
    if (line[0] == '/') {
        char inpt_command = line[1];
        char prompt[STRING_LENGTH + 2] = "> ";
        int prompt_offset = 3;
        strcat(prompt, line);
        new_lines(prompt);

        if (inpt_command == 'f') { // add friend command: /f ID
            int i;
            char temp_id[128];

            for (i = 0; i < 128; i++)
                temp_id[i] = line[i + prompt_offset];

            unsigned char *bin_string = hex_string_to_bin(temp_id);
            int num = tox_addfriend(m, bin_string, (uint8_t *)"Install Gentoo", sizeof("Install Gentoo"));
            free(bin_string);
            char numstring[100];

            switch (num) {
                case TOX_FAERR_TOOLONG:
                    sprintf(numstring, "[i] Message is too long.");
                    break;

                case TOX_FAERR_NOMESSAGE:
                    sprintf(numstring, "[i] Please add a message to your request.");
                    break;

                case TOX_FAERR_OWNKEY:
                    sprintf(numstring, "[i] That appears to be your own ID.");
                    break;

                case TOX_FAERR_ALREADYSENT:
                    sprintf(numstring, "[i] Friend request already sent.");
                    break;

                case TOX_FAERR_UNKNOWN:
                    sprintf(numstring, "[i] Undefined error when adding friend.");
                    break;

                default:
                    sprintf(numstring, "[i] Added friend as %d.", num);
                    break;
            }

            new_lines(numstring);
            do_refresh();
        } else if (inpt_command == 'd') {
            tox_do(m);
        } else if (inpt_command == 'm') { //message command: /m friendnumber messsage
            size_t len = strlen(line);

            if (len < 3)
                return;

            char numstring[len - 3];
            char message[len - 3];
            int i;

            for (i = 0; i < len; i++) {
                if (line[i + 3] != ' ') {
                    numstring[i] = line[i + 3];
                } else {
                    int j;

                    for (j = (i + 1); j < (len + 1); j++)
                        message[j - i - 1] = line[j + 3];

                    break;
                }
            }

            int num = atoi(numstring);

            if (tox_sendmessage(m, num, (uint8_t *) message, strlen(message) + 1) != 1) {
                new_lines("[i] could not send message");
            } else {
                new_lines(format_message(m, message, -1));
            }
        } else if (inpt_command == 'n') {
            uint8_t name[TOX_MAX_NAME_LENGTH];
            int i = 0;
            size_t len = strlen(line);

            for (i = 3; i < len; i++) {
                if (line[i] == 0 || line[i] == '\n') break;

                name[i - 3] = line[i];
            }

            name[i - 3] = 0;
            tox_setname(m, name, i - 2);
            char numstring[100];
            sprintf(numstring, "[i] changed nick to %s", (char *)name);
            new_lines(numstring);
        } else if (inpt_command == 'l') {
            print_friendlist(m);
        } else if (inpt_command == 's') {
            uint8_t status[TOX_MAX_STATUSMESSAGE_LENGTH];
            int i = 0;
            size_t len = strlen(line);

            for (i = 3; i < len; i++) {
                if (line[i] == 0 || line[i] == '\n') break;

                status[i - 3] = line[i];
            }

            status[i - 3] = 0;
            tox_set_statusmessage(m, status, strlen((char *)status) + 1);
            char numstring[100];
            sprintf(numstring, "[i] changed status to %s", (char *)status);
            new_lines(numstring);
        } else if (inpt_command == 'a') {
            uint8_t numf = atoi(line + 3);
            char numchar[100];

            if (numf >= num_requests || pending_requests[numf].accepted) {
                sprintf(numchar, "[i] you either didn't receive that request or you already accepted it");
                new_lines(numchar);
            } else {
                int num = tox_addfriend_norequest(m, pending_requests[numf].id);

                if (num != -1) {
                    pending_requests[numf].accepted = 1;
                    sprintf(numchar, "[i] friend request %u accepted", numf);
                    new_lines(numchar);
                    sprintf(numchar, "[i] added friendnumber %d", num);
                    new_lines(numchar);
                } else {
                    sprintf(numchar, "[i] failed to add friend");
                    new_lines(numchar);
                }
            }

            do_refresh();
        } else if (inpt_command == 'h') { //help
            new_lines(help);
        } else if (inpt_command == 'i') { //info
            char idstring[200];
            get_id(m, idstring);
            new_lines(idstring);
        }

        else if (inpt_command == 'q') { //exit
            endwin();
            exit(EXIT_SUCCESS);
        } else {
            new_lines("[i] invalid command");
        }
    } else {
        new_lines("[i] invalid command");
        //new_lines(line);
    }
}

void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width)
{
    strcpy(output, input);
    size_t len = strlen(output);
    int i = 0;

    for (i = line_width; i < len; i = i + line_width) {
        while (output[i] != ' ' && i != 0) {
            i--;
        }

        if (i > 0) {
            output[i] = '\n';
        }
    }
}

int count_lines(char *string)
{
    size_t len = strlen(string);
    int count = 1;
    int i;

    for (i = 0; i < len; i++) {
        if (string[i] == '\n')
            count++;
    }

    return count;
}

char *appender(char *str, const char c)
{
    size_t len = strlen(str);

    if (len < STRING_LENGTH) {
        str[len + 1] = str[len];
        str[len] = c;
    }

    return str;
}

void do_refresh()
{
    int count = 0;
    char wrap_output[STRING_LENGTH];
    int L;
    int i;

    for (i = 0; i < HISTORY; i++) {
        wrap(wrap_output, lines[i], x);
        L = count_lines(wrap_output);
        count = count + L;

        if (count < y) {
            move(y - 1 - count, 0);
            printw(wrap_output);
            clrtoeol();
        }
    }

    move(y - 1, 0);
    clrtoeol();
    printw(">> ");
    printw(line);
    clrtoeol();
    refresh();
}

void print_request(uint8_t *public_key, uint8_t *data, uint16_t length, void *userdata)
{
    new_lines("[i] received friend request with message:");
    new_lines((char *)data);
    char numchar[100];
    sprintf(numchar, "[i] accept request with /a %u", num_requests);
    new_lines(numchar);
    memcpy(pending_requests[num_requests].id, public_key, TOX_CLIENT_ID_SIZE);
    pending_requests[num_requests].accepted = 0;
    ++num_requests;
    do_refresh();
}

void print_message(Tox *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    new_lines(format_message(m, (char *)string, friendnumber));
}

void print_nickchange(Tox *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    char name[TOX_MAX_NAME_LENGTH];

    if (tox_getname(m, friendnumber, (uint8_t *)name) != -1) {
        char msg[100 + length];
        sprintf(msg, "[i] [%d] %s is now known as %s.", friendnumber, name, string);
        new_lines(msg);
    }
}

void print_statuschange(Tox *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    char name[TOX_MAX_NAME_LENGTH];

    if (tox_getname(m, friendnumber, (uint8_t *)name) != -1) {
        char msg[100 + length + strlen(name) + 1];
        sprintf(msg, "[i] [%d] %s's status changed to %s.", friendnumber, name, string);
        new_lines(msg);
    }
}

void load_key(Tox *m, char *path)
{
    FILE *data_file = fopen(path, "r");
    int size = 0;

    if (data_file) {
        //load keys
        fseek(data_file, 0, SEEK_END);
        size = ftell(data_file);
        rewind(data_file);

        uint8_t data[size];

        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            fputs("[!] could not read data file! exiting...\n", stderr);
            goto FILE_ERROR;
        }

        tox_load(m, data, size);

    } else {
        //else save new keys
        int size = tox_size(m);
        uint8_t data[size];
        tox_save(m, data);
        data_file = fopen(path, "w");

        if (!data_file) {
            perror("[!] load_key");
            exit(1);
        }

        if (fwrite(data, sizeof(uint8_t), size, data_file) != size) {
            fputs("[!] could not write data file! exiting...", stderr);
            goto FILE_ERROR;
        }
    }

    if (fclose(data_file) < 0)
        perror("[!] fclose failed");

    return;

FILE_ERROR:

    if (fclose(data_file) < 0)
        perror("[!] fclose failed");

    exit(1);
}

void print_help(void)
{
    printf("nTox %.1f - Command-line tox-core client\n", 0.1);
    puts("Options:");
    puts("\t-h\t-\tPrint this help and exit.");
    puts("\t-f\t-\tSpecify a keyfile to read (or write to) from.");
}

int main(int argc, char *argv[])
{
    int on = 0;
    int c = 0;
    int i = 0;
    char *filename = "data";
    char idstring[200] = {0};
    Tox *m;

    if (argc < 4) {
        printf("[!] Usage: %s [IP] [port] [public_key] <keyfile>\n", argv[0]);
        exit(0);
    }

    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            break;
        } else if (argv[i][0] == '-') {
            if (argv[i][1] == 'h') {
                print_help();
                exit(0);
            } else if (argv[i][1] == 'f') {
                if (argv[i + 1] != NULL)
                    filename = argv[i + 1];
                else {
                    fputs("[!] you passed '-f' without giving an argument!\n", stderr);
                }
            }
        }
    }

    m = tox_new();

    if ( !m ) {
        fputs("Failed to allocate Messenger datastructure", stderr);
        exit(0);
    }

    load_key(m, filename);

    tox_callback_friendrequest(m, print_request, NULL);
    tox_callback_friendmessage(m, print_message, NULL);
    tox_callback_namechange(m, print_nickchange, NULL);
    tox_callback_statusmessage(m, print_statuschange, NULL);

    initscr();
    noecho();
    raw();
    getmaxyx(stdscr, y, x);

    new_lines("/h for list of commands");
    get_id(m, idstring);
    new_lines(idstring);
    strcpy(line, "");

    tox_IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    int resolved_address = resolve_addr(argv[1]);

    if (resolved_address != 0)
        bootstrap_ip_port.ip.i = resolved_address;
    else
        exit(1);

    unsigned char *binary_string = hex_string_to_bin(argv[3]);
    tox_bootstrap(m, bootstrap_ip_port, binary_string);
    free(binary_string);
    nodelay(stdscr, TRUE);

    while (1) {
        if (on == 0 && tox_isconnected(m)) {
            new_lines("[i] connected to DHT\n[i] define username with /n");
            on = 1;
        }

        tox_do(m);
        c_sleep(1);
        do_refresh();

        c = getch();

        if (c == ERR || c == 27)
            continue;

        getmaxyx(stdscr, y, x);

        if ((c == 0x0d) || (c == 0x0a)) {
            line_eval(m, line);
            strcpy(line, "");
        } else if (c == 8 || c == 127) {
            line[strlen(line) - 1] = '\0';
        } else if (isalnum(c) || ispunct(c) || c == ' ') {
            strcpy(line, appender(line, (char) c));
        }
    }

    tox_kill(m);
    endwin();
    return 0;
}
