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
uint8_t flag[HISTORY];
char input_line[STRING_LENGTH];

/* wrap: continuation mark */
const size_t wrap_cont_len = 3;
const char wrap_cont_str[] = "\n+ ";

/* documented: fdmnlsahxgiztq */
/* undocumented: d (tox_do()) */

/* 221 characters */
char *help_main =
    "[i] Available main commands:\n+ "
    "/x (to print one's own id)|"
    "/s status (to change status, e.g. AFK)|"
    "/n nick (to change your nickname)|"
    "/q (to quit)|"
    "/h friend (for friend related commands)|"
    "/h group (for group related commands)";

/* 229 characters */
char *help_friend =
    "[i] Available friend commands:\n+ "
    "/l list (to list friends)|"
    "/f ID (to send a friend request)|"
    "/a request no. (to accept a friend request)|"
    "/m friend no. message (to send a message)|"
    "/t friend no. filename (to send a file to a friend)";
/* too long:
    "|/r [@HH:MM] message (to set up a rendezvous)"; */

/* 166 characters */
char *help_group =
    "[i] Available group commands:\n+ "
    "/g (to create a new group)|"
    "/i friend no. group no. (to invite a friend to a group)|"
    "/z group no. message (to send a message to a group)";

int x, y;

typedef struct {
    uint8_t id[TOX_CLIENT_ID_SIZE];
    uint8_t accepted;
} Friend_request;

Friend_request pending_requests[256];
uint8_t num_requests = 0;

#define NUM_FILE_SENDERS 256
typedef struct {
    FILE *file;
    uint16_t friendnum;
    uint8_t filenumber;
    uint8_t nextpiece[1024];
    uint16_t piecelength;
} File_Sender;
File_Sender file_senders[NUM_FILE_SENDERS];
uint8_t numfilesenders;

void send_filesenders(Tox *m)
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        if (file_senders[i].file == 0)
            continue;

        while (1) {
            if (!tox_file_senddata(m, file_senders[i].friendnum, file_senders[i].filenumber, file_senders[i].nextpiece,
                                   file_senders[i].piecelength))
                break;

            file_senders[i].piecelength = fread(file_senders[i].nextpiece, 1, tox_filedata_size(m, file_senders[i].friendnum),
                                                file_senders[i].file);

            if (file_senders[i].piecelength == 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
                tox_file_sendcontrol(m, file_senders[i].friendnum, 0, file_senders[i].filenumber, 3, 0, 0);
                char msg[512];
                sprintf(msg, "[t] %u file transfer: %u completed", file_senders[i].friendnum, file_senders[i].filenumber);
                new_lines(msg);
                break;
            }
        }
    }
}
int add_filesender(Tox *m, uint16_t friendnum, char *filename)
{
    FILE *tempfile = fopen(filename, "r");

    if (tempfile == 0)
        return -1;

    fseek(tempfile, 0, SEEK_END);
    uint64_t filesize = ftell(tempfile);
    fseek(tempfile, 0, SEEK_SET);
    int filenum = tox_new_filesender(m, friendnum, filesize, (uint8_t *)filename, strlen(filename) + 1);

    if (filenum == -1)
        return -1;

    file_senders[numfilesenders].file = tempfile;
    file_senders[numfilesenders].piecelength = fread(file_senders[numfilesenders].nextpiece, 1, tox_filedata_size(m,
            file_senders[numfilesenders].friendnum),
            file_senders[numfilesenders].file);
    file_senders[numfilesenders].friendnum = friendnum;
    file_senders[numfilesenders].filenumber = filenum;
    ++numfilesenders;
    return filenum;
}

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
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_getaddress(m, address);

    uint32_t i = 0;

    for (; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        sprintf(data + 2 * i + offset, "%02X ", address[i]);
    }
}

void new_lines_mark(char *line, uint8_t special)
{
    int i = 0;

    for (i = HISTORY - 1; i > 0; i--) {
        strncpy(lines[i], lines[i - 1], STRING_LENGTH - 1);
        flag[i] = flag[i - 1];
    }

    strncpy(lines[0], line, STRING_LENGTH - 1);
    flag[i] = special;

    do_refresh();
}

void new_lines(char *line)
{
    new_lines_mark(line, 0);
}


const char ptrn_friend[] = "[i] Friend: %s\n+ id: %i";
void print_friendlist(Tox *m)
{
    char name[TOX_MAX_NAME_LENGTH];
    int i = 0;
    new_lines("[i] Friend List:");

    while (tox_getname(m, i, (uint8_t *)name) != -1) {
        /* account for the longest name and the longest "base" string and number (int) */
        char fstring[TOX_MAX_NAME_LENGTH + strlen(ptrn_friend) + 21];

        if (strlen(name) <= 0) {
            sprintf(fstring, ptrn_friend, "No name?", i);
        } else {
            sprintf(fstring, ptrn_friend, (uint8_t *)name, i);
        }

        i++;
        new_lines(fstring);
    }

    if (i == 0)
        new_lines("+ no friends! D:");
}

void rendezvous_found(void *data, uint8_t *id)
{
    char id_str[TOX_FRIEND_ADDRESS_SIZE * 2 + 1];
    uint32_t i = 0;

    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++)
        sprintf(id_str + i * 2, "%02X ", id[i]);

    id_str[TOX_FRIEND_ADDRESS_SIZE * 2] = 0;

    char msg[TOX_FRIEND_ADDRESS_SIZE * 2 + 64];
    sprintf(msg, "[r] Friend's id is said to be: %s", id_str);
    new_lines(msg);
}

uint8_t rendezvous_timeout(void *data)
{
    new_lines("[r] Rendezvous timeframe exceeded, not looking further.");
    return 0;
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

/* forward declaration */
static int save_data(Tox *m);

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
                    if (num >= 0) {
                        sprintf(numstring, "[i] Added friend as %d.", num);
                        save_data(m);
                    } else
                        sprintf(numstring, "[i] Unknown error %i.", num);

                    break;
            }

            new_lines(numstring);
        } else if (inpt_command == 'd') {
            tox_do(m);
        } else if (inpt_command == 'm') { //message command: /m friendnumber messsage
            char *posi[1];
            int num = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                if (tox_sendmessage(m, num, (uint8_t *) *posi + 1, strlen(*posi + 1) + 1) < 1) {
                    char sss[256];
                    sprintf(sss, "[i] could not send message to friend num %u", num);
                    new_lines(sss);
                } else {
                    new_lines(format_message(m, *posi + 1, -1));
                }
            } else
                new_lines("Error, bad input.");
        } else if (inpt_command == 'n') {
            uint8_t name[TOX_MAX_NAME_LENGTH];
            size_t i, len = strlen(line);

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
            size_t i, len = strlen(line);

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
                    save_data(m);
                } else {
                    sprintf(numchar, "[i] failed to add friend");
                    new_lines(numchar);
                }
            }
        } else if (inpt_command == 'h') { //help
            if (line[2] == ' ') {
                if (line[3] == 'f') {
                    new_lines_mark(help_friend, 1);
                    return;
                } else if (line[3] == 'g') {
                    new_lines_mark(help_group, 1);
                    return;
                }
            }

            new_lines_mark(help_main, 1);
        } else if (inpt_command == 'x') { //info
            char idstring[200];
            get_id(m, idstring);
            new_lines(idstring);
        } else if (inpt_command == 'g') { //create new group chat
            char msg[256];
            sprintf(msg, "[g] Created new group chat with number: %u", tox_add_groupchat(m));
            new_lines(msg);
        } else if (inpt_command == 'i') { //invite friendnum to groupnum
            char *posi[1];
            int friendnumber = strtoul(line + prompt_offset, posi, 0);
            int groupnumber = strtoul(*posi + 1, NULL, 0);
            char msg[256];
            sprintf(msg, "[g] Invited friend number %u to group number %u, returned: %u (0 means success)", friendnumber,
                    groupnumber, tox_invite_friend(m, friendnumber, groupnumber));
            new_lines(msg);
        } else if (inpt_command == 'z') { //send message to groupnum
            char *posi[1];
            int groupnumber = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                char msg[256 + 1024];
                sprintf(msg, "[g] sent message: %s to group num: %u returned: %u (0 means success)", *posi + 1, groupnumber,
                        tox_group_message_send(m, groupnumber, (uint8_t *)*posi + 1, strlen(*posi + 1) + 1));
                new_lines(msg);
            }
        } else if (inpt_command == 't') {
            char msg[512];
            char *posi[1];
            int friendnum = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                sprintf(msg, "[t] Sending file %s to friendnum %u filenumber is %i (-1 means failure)", *posi + 1, friendnum,
                        add_filesender(m, friendnum, *posi + 1));
                new_lines(msg);
            }
        } else if (inpt_command == 'r') { // rendezvous: find someone by a point in time and common "secret"
            uint64_t timestamp = time(NULL);
            int offset = prompt_offset;

            if (strlen(line) - offset < 16) {
                new_lines("[r] To set up a rendezvous, use: /r @HH:MM The passphrase you agreed upon.\n"
                          "    e.g.: /r @03:45 The quick brown fox jumps over the lazy dog.\n"
                          "    Hours continue beyond midnight up to 35:59 (11:59am tomorrow).\n"
                          "    Minutes are rounded down to three minutes of exactness.");
                return;
            }

            if (line[offset] == '@') {
#ifndef WIN32
                /*
                 * time: @HH:MM (hour:minute, hour > 24 = beyond midnight)
                 * text: anything after time
                 */
                int hour = (line[offset + 1] - '0') * 10 + line[offset + 2] - '0';
                int colon = line[offset + 3] == ':';
                int minute = (line[offset + 4] - '0') * 10 + line[offset + 5] - '0';

                if ((hour >= 0) && (hour <= 35) && (minute >= 0) && (minute <= 59) && colon) {
                    /* need current hour:minute, then calc. diff and delta that on timestamp */
                    time_t now1 = time(NULL);
                    struct tm *now2 = localtime(&now1);
                    int delta = hour * 60 + minute - (now2->tm_hour * 60 + now2->tm_min);

                    if  (delta < 0) {
                        new_lines("[r] Date/time for rendezvous lies in the past: Not doing anything.");
                        return;
                    }

                    char msg[256];
                    sprintf(msg, "[r] [DBG] Now: %02i:%02i, target: %02i:%02i, delta: %i.", now2->tm_hour, now2->tm_min, hour, minute,
                            delta);
                    new_lines(msg);

                    timestamp += delta * 60;
                } else {
                    new_lines("[r] Date/time input wasn't in the expected format: Not doing anything.");
                    return;
                }

#else
                new_lines("[r] Date/time for rendezvous not yet supported: Using current time.");

                while (line[offset] && (line[offset] != ' '))
                    offset++;

                if (line[offset] == ' ')
                    offset++;

                if (offset != prompt_offset + 7)
                    line[offset] = 0;

#endif
            }

            if (!line[offset])
                new_lines("[r] Input invalid: Want @time, need text (at least 16 characters).");
            else if (tox_rendezvous(m, line + offset, timestamp, rendezvous_found, rendezvous_timeout, NULL))
                /* found: => print_friend_id */
                new_lines("[r] Trying to find someone with the given secret and time.");
            else
                new_lines("[r] Failed to initialize rendezvous.");
        } else if (inpt_command == 'q') { //exit
            save_data(m);
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

/* basic wrap, ignores embedded '\t', '\n' or '|' */
void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width)
{
    strcpy(output, input);
    size_t i, k, m, len = strlen(output);

    for (i = line_width; i < len; i = i + line_width) {
        /* look backward for a space to turn into a new line */
        k = i;
        m = i - line_width;

        while (output[k] != ' ' && k > m) {
            k--;
        }

        if (k > 0) {
            /* replace and set as new line start */
            output[k] = '\n';
            i = k + 1;
        } else {
            /* nothing found backwards: look forward */
            while ((i < len) && (output[i] != ' '))
                i++;

            if (i < len)
                output[i] = '\n';
        }
    }
}

/*
 * extended wrap, honors '\n', accepts '|' as "break here when necessary"
 * marks wrapped lines with "+ " in front, which does expand output
 * does NOT honor '\t': would require a lot more work (and tab width isn't always 8)
 */
void wrap_bars(char output[STRING_LENGTH], char input[STRING_LENGTH], size_t line_width)
{
    size_t len = strlen(input);
    size_t ipos, opos = 0;
    size_t bar_avail = 0, space_avail = 0, nl_got = 0;   /* in opos */

    for (ipos = 0; ipos < len; ipos++) {
        if (opos - nl_got < line_width) {
            /* not yet at the limit */
            char c = input[ipos];

            if (c == ' ')
                space_avail = opos;

            output[opos++] = input[ipos];

            if (opos >= STRING_LENGTH) {
                opos = STRING_LENGTH - 1;
                break;
            }

            if (c == '|') {
                output[opos - 1] = ' ';
                bar_avail = opos;

                if (opos + 2 >= STRING_LENGTH) {
                    opos = STRING_LENGTH - 1;
                    break;
                }

                output[opos++] = '|';
                output[opos++] = ' ';
            }

            if (c == '\n')
                nl_got = opos;

            continue;
        } else {
            /* at the limit */
            if (bar_avail > nl_got) {
                /* overwrite */
                memcpy(output + bar_avail - 1, wrap_cont_str, wrap_cont_len);
                nl_got = bar_avail;

                ipos--;
                continue;
            }

            if (space_avail > nl_got) {
                if (opos + wrap_cont_len - 1 >= STRING_LENGTH) {
                    opos = STRING_LENGTH - 1;
                    break;
                }

                /* move forward by 2 characters */
                memmove(output + space_avail + 3, output + space_avail + 1, opos - (space_avail + 1));
                memcpy(output + space_avail, wrap_cont_str, wrap_cont_len);
                nl_got = space_avail + 1;

                opos += 2;
                ipos--;
                continue;
            }

            char c = input[ipos];

            if ((c == '|') || (c == ' ') || (c == '\n')) {
                if (opos + wrap_cont_len >= STRING_LENGTH) {
                    opos = STRING_LENGTH - 1;
                    break;
                }

                memcpy(output + opos, wrap_cont_str, wrap_cont_len);

                nl_got = opos;
                opos += wrap_cont_len;
            }

            output[opos++] = input[ipos];

            if (opos >= STRING_LENGTH) {
                opos = STRING_LENGTH - 1;
                break;
            }

            continue;
        }
    }

    output[opos] = 0;
}

int count_lines(char *string)
{
    size_t i, len = strlen(string);
    int count = 1;

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
        if (flag[i])
            wrap_bars(wrap_output, lines[i], x);
        else
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
    printw(input_line);
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

static char *data_file_name = NULL;

static int load_data(Tox *m)
{
    FILE *data_file = fopen(data_file_name, "r");
    size_t size = 0;

    if (data_file) {
        fseek(data_file, 0, SEEK_END);
        size = ftell(data_file);
        rewind(data_file);

        uint8_t data[size];

        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            fputs("[!] could not read data file!\n", stderr);
            fclose(data_file);
            return 0;
        }

        tox_load(m, data, size);

        if (fclose(data_file) < 0) {
            perror("[!] fclose failed");
            /* we got it open and the expected data read... let it be ok */
            /* return 0; */
        }

        return 1;
    }

    return 0;
}

static int save_data(Tox *m)
{
    FILE *data_file = fopen(data_file_name, "w");

    if (!data_file) {
        perror("[!] load_key");
        return 0;
    }

    int res = 1;
    size_t size = tox_size(m);
    uint8_t data[size];
    tox_save(m, data);

    if (fwrite(data, sizeof(uint8_t), size, data_file) != size) {
        fputs("[!] could not write data file (1)!", stderr);
        res = 0;
    }

    if (fclose(data_file) < 0) {
        perror("[!] could not write data file (2)");
        res = 0;
    }

    return res;
}

static int load_data_or_init(Tox *m, char *path)
{
    data_file_name = path;

    if (load_data(m))
        return 1;

    if (save_data(m))
        return 1;

    return 0;
}

void print_help(char *prog_name)
{
    printf("nTox %.1f - Command-line tox-core client\n", 0.1);
    printf("Usage: %s [--ipv4|--ipv6] IP PORT KEY [-f keyfile]\n", prog_name);

    puts("Options: (order IS relevant)");
    puts("  --ipv4 / --ipv6 [Optional] Support IPv4 only or IPv4 & IPv6.");
    puts("  IP PORT KEY     [REQUIRED] A server to connect to (IP/Port) and its key.");
    puts("  -f keyfile      [Optional] Specify a keyfile to read from and write to.");
}

void print_invite(Tox *m, int friendnumber, uint8_t *group_public_key, void *userdata)
{
    char msg[256];
    sprintf(msg, "[i] received group chat invite from: %u, auto accepting and joining. group number: %u", friendnumber,
            tox_join_groupchat(m, friendnumber, group_public_key));
    new_lines(msg);
}

void print_groupmessage(Tox *m, int groupnumber, int peernumber, uint8_t *message, uint16_t length, void *userdata)
{
    char msg[256 + length];
    uint8_t name[TOX_MAX_NAME_LENGTH];
    tox_group_peername(m, groupnumber, peernumber, name);
    sprintf(msg, "[g] %u: <%s>: %s", groupnumber, name, message);
    new_lines(msg);
}

void file_request_accept(Tox *m, int friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename,
                         uint16_t filename_length, void *userdata)
{
    char msg[512];
    sprintf(msg, "[t] %u is sending us: %s of size %llu", friendnumber, filename, (long long unsigned int)filesize);
    new_lines(msg);

    if (tox_file_sendcontrol(m, friendnumber, 1, filenumber, 0, 0, 0)) {
        sprintf(msg, "Accepted file transfer. (saving file as: %u.%u.bin)", friendnumber, filenumber);
        new_lines(msg);
    } else
        new_lines("Could not accept file transfer.");
}

void file_print_control(Tox *m, int friendnumber, uint8_t send_recieve, uint8_t filenumber, uint8_t control_type,
                        uint8_t *data,
                        uint16_t length, void *userdata)
{
    char msg[512] = {0};

    if (control_type == 0)
        sprintf(msg, "[t] %u accepted file transfer: %u", friendnumber, filenumber);
    else if (control_type == 3)
        sprintf(msg, "[t] %u file transfer: %u completed", friendnumber, filenumber);
    else
        sprintf(msg, "[t] control %u received", control_type);

    new_lines(msg);
}

void write_file(Tox *m, int friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length, void *userdata)
{
    char filename[256];
    sprintf(filename, "%u.%u.bin", friendnumber, filenumber);
    FILE *pFile = fopen(filename, "a");

    if (tox_file_dataremaining(m, friendnumber, filenumber, 1) == 0) {
        //file_control(m, friendnumber, 1, filenumber, 3, 0, 0);
        char msg[512];
        sprintf(msg, "[t] %u file transfer: %u completed", friendnumber, filenumber);
        new_lines(msg);
    }

    if (fwrite(data, length, 1, pFile) != 1)
        new_lines("Error writing to file");

    fclose(pFile);
}


int main(int argc, char *argv[])
{
    if (argc < 4) {
        if ((argc == 2) && !strcmp(argv[1], "-h")) {
            print_help(argv[0]);
            exit(0);
        }

        printf("Usage: %s [--ipv4|--ipv6] IP PORT KEY [-f keyfile] (or %s -h for help)\n", argv[0], argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    int on = 0;
    int c = 0;
    char *filename = "data";
    char idstring[200] = {0};
    Tox *m;

    /* [-f keyfile] MUST be last two arguments, no point in walking over the list
     * especially not a good idea to accept it anywhere in the middle */
    if (argc > argvoffset + 3)
        if (!strcmp(argv[argc - 2], "-f"))
            filename = argv[argc - 1];

    m = tox_new(ipv6enabled);

    if ( !m ) {
        fputs("Failed to allocate Messenger datastructure", stderr);
        exit(0);
    }

    load_data_or_init(m, filename);

    tox_callback_friendrequest(m, print_request, NULL);
    tox_callback_friendmessage(m, print_message, NULL);
    tox_callback_namechange(m, print_nickchange, NULL);
    tox_callback_statusmessage(m, print_statuschange, NULL);
    tox_callback_group_invite(m, print_invite, NULL);
    tox_callback_group_message(m, print_groupmessage, NULL);
    tox_callback_file_data(m, write_file, NULL);
    tox_callback_file_control(m, file_print_control, NULL);
    tox_callback_file_sendrequest(m, file_request_accept, NULL);

    initscr();
    noecho();
    raw();
    getmaxyx(stdscr, y, x);

    new_lines("/h for list of commands");
    get_id(m, idstring);
    new_lines(idstring);
    strcpy(input_line, "");

    uint16_t port = htons(atoi(argv[argvoffset + 2]));
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = tox_bootstrap_from_address(m, argv[argvoffset + 1], ipv6enabled, port, binary_string);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        endwin();
        exit(1);
    }

    nodelay(stdscr, TRUE);

    new_lines("[i] change username with /n");
    uint8_t name[TOX_MAX_NAME_LENGTH];
    uint16_t namelen = tox_getselfname(m, name, sizeof(name));

    if (namelen > 0) {
        char whoami[128 + TOX_MAX_NAME_LENGTH];
        snprintf(whoami, sizeof(whoami), "[i] your current username is: %s", name);
        new_lines(whoami);
    }

    time_t timestamp0 = time(NULL);

    while (1) {
        if (on == 0) {
            if (tox_isconnected(m)) {
                new_lines("[i] connected to DHT");
                on = 1;
            } else {
                time_t timestamp1 = time(NULL);

                if (timestamp0 + 10 < timestamp1) {
                    timestamp0 = timestamp1;
                    tox_bootstrap_from_address(m, argv[argvoffset + 1], ipv6enabled, port, binary_string);
                }
            }
        }

        send_filesenders(m);
        tox_do(m);
        c_sleep(1);
        do_refresh();

        c = getch();

        if (c == ERR || c == 27)
            continue;

        getmaxyx(stdscr, y, x);

        if ((c == 0x0d) || (c == 0x0a)) {
            line_eval(m, input_line);
            strcpy(input_line, "");
        } else if (c == 8 || c == 127) {
            input_line[strlen(input_line) - 1] = '\0';
        } else if (isalnum(c) || ispunct(c) || c == ' ') {
            strcpy(input_line, appender(input_line, (char) c));
        }
    }

    tox_kill(m);
    endwin();
    return 0;
}
