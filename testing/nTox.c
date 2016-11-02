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

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define _WIN32_WINNT 0x501
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <sys/select.h>

#include "misc_tools.c"
#include "nTox.h"

#include <locale.h>
#include <stdio.h>
#include <time.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static void new_lines(char const *line);
static void do_refresh(void);

static char lines[HISTORY][STRING_LENGTH];
static uint8_t flag[HISTORY];
static char input_line[STRING_LENGTH];

/* wrap: continuation mark */
enum { wrap_cont_len = 3 };
static const char wrap_cont_str[] = "\n+ ";

#define STRING_LENGTH_WRAPPED (STRING_LENGTH + 16 * (wrap_cont_len + 1))

/* documented: fdmnlsahxgiztq(c[rfg]) */
/* undocumented: d (tox_do()) */

/* 251+1 characters */
static const char *help_main =
    "[i] Available main commands:\n+ "
    "/x (to print one's own id)|"
    "/s status (to change status, e.g. AFK)|"
    "/n nick (to change your nickname)|"
    "/q (to quit)|"
    "/cr (to reset conversation)|"
    "/h friend (for friend related commands)|"
    "/h group (for group related commands)";

/* 190+1 characters */
static const char *help_friend1 =
    "[i] Available friend commands (1/2):\n+ "
    "/l list (to list friends)|"
    "/r friend no. (to remove from the friend list)|"
    "/f ID (to send a friend request)|"
    "/a request no. (to accept a friend request)";

/* 187+1 characters */
static const char *help_friend2 =
    "[i] Available friend commands (2/2):\n+ "
    "/m friend no. message (to send a message)|"
    "/t friend no. filename (to send a file to a friend)|"
    "/cf friend no. (to talk to that friend per default)";

/* 253+1 characters */
static const char *help_group =
    "[i] Available group commands:\n+ "
    "/g (to create a group)|"
    "/i friend no. group no. (to invite a friend to a group)|"
    "/z group no. message (to send a message to a group)|"
    "/p group no. (to list a group's peers)|"
    "/cg group no. (to talk to that group per default)";

static int x, y;

static int conversation_default = 0;

typedef struct {
    uint8_t id[TOX_PUBLIC_KEY_SIZE];
    uint8_t accepted;
} Friend_request;

static Friend_request pending_requests[256];
static uint8_t num_requests = 0;

#define NUM_FILE_SENDERS 64
typedef struct {
    FILE *file;
    uint32_t friendnum;
    uint32_t filenumber;
} File_Sender;
static File_Sender file_senders[NUM_FILE_SENDERS];
static uint8_t numfilesenders;

static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                   size_t length,
                                   void *user_data)
{
    unsigned int i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        /* This is slow */
        if (file_senders[i].file && file_senders[i].friendnum == friend_number && file_senders[i].filenumber == file_number) {
            if (length == 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
                char msg[512];
                sprintf(msg, "[t] %u file transfer: %u completed", file_senders[i].friendnum, file_senders[i].filenumber);
                new_lines(msg);
                break;
            }

            fseek(file_senders[i].file, position, SEEK_SET);
            uint8_t data[length];
            int len = fread(data, 1, length, file_senders[i].file);
            tox_file_send_chunk(tox, friend_number, file_number, position, data, len, 0);
            break;
        }
    }
}


static uint32_t add_filesender(Tox *m, uint16_t friendnum, char *filename)
{
    FILE *tempfile = fopen(filename, "rb");

    if (tempfile == 0) {
        return -1;
    }

    fseek(tempfile, 0, SEEK_END);
    uint64_t filesize = ftell(tempfile);
    fseek(tempfile, 0, SEEK_SET);
    uint32_t filenum = tox_file_send(m, friendnum, TOX_FILE_KIND_DATA, filesize, 0, (uint8_t *)filename,
                                     strlen(filename), 0);

    if (filenum == -1) {
        return -1;
    }

    file_senders[numfilesenders].file = tempfile;
    file_senders[numfilesenders].friendnum = friendnum;
    file_senders[numfilesenders].filenumber = filenum;
    ++numfilesenders;
    return filenum;
}



#define FRADDR_TOSTR_CHUNK_LEN 8
#define FRADDR_TOSTR_BUFSIZE (TOX_ADDRESS_SIZE * 2 + TOX_ADDRESS_SIZE / FRADDR_TOSTR_CHUNK_LEN + 1)

static void fraddr_to_str(uint8_t *id_bin, char *id_str)
{
    uint32_t i, delta = 0, pos_extra = 0, sum_extra = 0;

    for (i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE) {
            pos_extra = 2 * (i + 1) + delta;
        }

        if (i >= TOX_PUBLIC_KEY_SIZE) {
            sum_extra |= id_bin[i];
        }

        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra) {
        id_str[pos_extra] = 0;
    }
}

static void get_id(Tox *m, char *data)
{
    sprintf(data, "[i] ID: ");
    int offset = strlen(data);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(m, address);
    fraddr_to_str(address, data + offset);
}

static int getfriendname_terminated(Tox *m, int friendnum, char *namebuf)
{
    tox_friend_get_name(m, friendnum, (uint8_t *)namebuf, NULL);
    int res = tox_friend_get_name_size(m, friendnum, NULL);

    if (res >= 0) {
        namebuf[res] = 0;
    } else {
        namebuf[0] = 0;
    }

    return res;
}

static void new_lines_mark(char const *line, uint8_t special)
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

static void new_lines(char const *line)
{
    new_lines_mark(line, 0);
}


static const char ptrn_friend[] = "[i] Friend %i: %s\n+ id: %s";
static const int id_str_len = TOX_ADDRESS_SIZE * 2 + 3;
static void print_friendlist(Tox *m)
{
    new_lines("[i] Friend List:");

    char name[TOX_MAX_NAME_LENGTH + 1];
    uint8_t fraddr_bin[TOX_ADDRESS_SIZE];
    char fraddr_str[FRADDR_TOSTR_BUFSIZE];

    /* account for the longest name and the longest "base" string and number (int) and id_str */
    char fstring[TOX_MAX_NAME_LENGTH + strlen(ptrn_friend) + 21 + id_str_len];

    uint32_t i = 0;

    while (getfriendname_terminated(m, i, name) != -1) {
        if (tox_friend_get_public_key(m, i, fraddr_bin, NULL)) {
            fraddr_to_str(fraddr_bin, fraddr_str);
        } else {
            sprintf(fraddr_str, "???");
        }

        if (strlen(name) <= 0) {
            sprintf(fstring, ptrn_friend, i, "No name?", fraddr_str);
        } else {
            sprintf(fstring, ptrn_friend, i, (uint8_t *)name, fraddr_str);
        }

        i++;
        new_lines(fstring);
    }

    if (i == 0) {
        new_lines("+ no friends! D:");
    }
}

static int fmtmsg_tm_mday = -1;

static void print_formatted_message(Tox *m, char *message, int friendnum, uint8_t outgoing)
{
    char name[TOX_MAX_NAME_LENGTH + 1];
    getfriendname_terminated(m, friendnum, name);

    char msg[100 + strlen(message) + strlen(name) + 1];

    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);

    /* assume that printing the date once a day is enough */
    if (fmtmsg_tm_mday != timeinfo->tm_mday) {
        fmtmsg_tm_mday = timeinfo->tm_mday;
        /* strftime(msg, 100, "Today is %a %b %d %Y.", timeinfo); */
        /* %x is the locale's preferred date format */
        strftime(msg, 100, "Today is %x.", timeinfo);
        new_lines(msg);
    }

    char time[64];
    /* strftime(time, 64, "%I:%M:%S %p", timeinfo); */
    /* %X is the locale's preferred time format */
    strftime(time, 64, "%X", timeinfo);

    if (outgoing) {
        /* tgt: friend */
        sprintf(msg, "[%d] %s =>{%s} %s", friendnum, time, name, message);
    } else {
        /* src: friend */
        sprintf(msg, "[%d] %s <%s>: %s", friendnum, time, name, message);
    }

    new_lines(msg);
}

/* forward declarations */
static int save_data(Tox *m);
static void print_groupchatpeers(Tox *m, int groupnumber);

static void line_eval(Tox *m, char *line)
{
    if (line[0] == '/') {
        char inpt_command = line[1];
        char prompt[STRING_LENGTH + 2] = "> ";
        int prompt_offset = 3;
        strcat(prompt, line);
        new_lines(prompt);

        if (inpt_command == 'f') { // add friend command: /f ID
            int i, delta = 0;
            char temp_id[128];

            for (i = 0; i < 128; i++) {
                temp_id[i - delta] = line[i + prompt_offset];

                if ((temp_id[i - delta] == ' ') || (temp_id[i - delta] == '+')) {
                    delta++;
                }
            }

            unsigned char *bin_string = hex_string_to_bin(temp_id);
            TOX_ERR_FRIEND_ADD error;
            uint32_t num = tox_friend_add(m, bin_string, (const uint8_t *)"Install Gentoo", sizeof("Install Gentoo"), &error);
            free(bin_string);
            char numstring[100];

            switch (error) {
                case TOX_ERR_FRIEND_ADD_TOO_LONG:
                    sprintf(numstring, "[i] Message is too long.");
                    break;

                case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
                    sprintf(numstring, "[i] Please add a message to your request.");
                    break;

                case TOX_ERR_FRIEND_ADD_OWN_KEY:
                    sprintf(numstring, "[i] That appears to be your own ID.");
                    break;

                case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
                    sprintf(numstring, "[i] Friend request already sent.");
                    break;

                case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
                    sprintf(numstring, "[i] Address has a bad checksum.");
                    break;

                case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
                    sprintf(numstring, "[i] New nospam set.");
                    break;

                case TOX_ERR_FRIEND_ADD_MALLOC:
                    sprintf(numstring, "[i] malloc error.");
                    break;

                case TOX_ERR_FRIEND_ADD_NULL:
                    sprintf(numstring, "[i] message was NULL.");
                    break;

                case TOX_ERR_FRIEND_ADD_OK:
                    sprintf(numstring, "[i] Added friend as %d.", num);
                    save_data(m);
                    break;
            }

            new_lines(numstring);
        } else if (inpt_command == 'd') {
            tox_iterate(m, NULL);
        } else if (inpt_command == 'm') { //message command: /m friendnumber messsage
            char *posi[1];
            int num = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                if (tox_friend_send_message(m, num, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) *posi + 1, strlen(*posi + 1), NULL) < 1) {
                    char sss[256];
                    sprintf(sss, "[i] could not send message to friend num %u", num);
                    new_lines(sss);
                } else {
                    print_formatted_message(m, *posi + 1, num, 1);
                }
            } else {
                new_lines("Error, bad input.");
            }
        } else if (inpt_command == 'n') {
            uint8_t name[TOX_MAX_NAME_LENGTH];
            size_t i, len = strlen(line);

            for (i = 3; i < len; i++) {
                if (line[i] == 0 || line[i] == '\n') {
                    break;
                }

                name[i - 3] = line[i];
            }

            name[i - 3] = 0;
            tox_self_set_name(m, name, i - 2, NULL);
            char numstring[100];
            sprintf(numstring, "[i] changed nick to %s", (char *)name);
            new_lines(numstring);
        } else if (inpt_command == 'l') {
            print_friendlist(m);
        } else if (inpt_command == 's') {
            uint8_t status[TOX_MAX_STATUS_MESSAGE_LENGTH];
            size_t i, len = strlen(line);

            for (i = 3; i < len; i++) {
                if (line[i] == 0 || line[i] == '\n') {
                    break;
                }

                status[i - 3] = line[i];
            }

            status[i - 3] = 0;
            tox_self_set_status_message(m, status, strlen((char *)status), NULL);
            char numstring[100];
            sprintf(numstring, "[i] changed status to %s", (char *)status);
            new_lines(numstring);
        } else if (inpt_command == 'a') { // /a #: accept
            uint8_t numf = atoi(line + 3);
            char numchar[100];

            if (numf >= num_requests || pending_requests[numf].accepted) {
                sprintf(numchar, "[i] you either didn't receive that request or you already accepted it");
                new_lines(numchar);
            } else {
                uint32_t num = tox_friend_add_norequest(m, pending_requests[numf].id, NULL);

                if (num != UINT32_MAX) {
                    pending_requests[numf].accepted = 1;
                    sprintf(numchar, "[i] friend request %u accepted as friend no. %d", numf, num);
                    new_lines(numchar);
                    save_data(m);
                } else {
                    sprintf(numchar, "[i] failed to add friend");
                    new_lines(numchar);
                }
            }
        } else if (inpt_command == 'r') { // /r #: remove friend
            uint8_t numf = atoi(line + 3);

            if (!tox_friend_exists(m, numf)) {
                char err[64];
                sprintf(err, "You don't have a friend %i.", numf);
                new_lines(err);
                return;
            }

            char msg[128 + TOX_MAX_NAME_LENGTH];
            char fname[TOX_MAX_NAME_LENGTH ];
            getfriendname_terminated(m, numf, fname);
            sprintf(msg, "Are you sure you want to delete friend %i: %s? (y/n)", numf, fname);
            input_line[0] = 0;
            new_lines(msg);

            int c;

            do {
                c = getchar();
            } while ((c != 'y') && (c != 'n') && (c != EOF));

            if (c == 'y') {
                int res = tox_friend_delete(m, numf, NULL);

                if (res) {
                    sprintf(msg, "[i] [%i: %s] is no longer your friend", numf, fname);
                } else {
                    sprintf(msg, "[i] failed to remove friend");
                }

                new_lines(msg);
            }
        } else if (inpt_command == 'h') { //help
            if (line[2] == ' ') {
                if (line[3] == 'f') {
                    new_lines_mark(help_friend1, 1);
                    new_lines_mark(help_friend2, 1);
                    return;
                }

                if (line[3] == 'g') {
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
            sprintf(msg, "[g] Created new group chat with number: %u", tox_conference_new(m, NULL));
            new_lines(msg);
        } else if (inpt_command == 'i') { //invite friendnum to groupnum
            char *posi[1];
            int friendnumber = strtoul(line + prompt_offset, posi, 0);
            int groupnumber = strtoul(*posi + 1, NULL, 0);
            char msg[256];
            sprintf(msg, "[g] Invited friend number %u to group number %u, returned: %u (0 means success)", friendnumber,
                    groupnumber, tox_conference_invite(m, friendnumber, groupnumber, NULL));
            new_lines(msg);
        } else if (inpt_command == 'z') { //send message to groupnum
            char *posi[1];
            int groupnumber = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                int res = tox_conference_send_message(m, groupnumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)*posi + 1, strlen(*posi + 1),
                                                      NULL);

                if (res == 0) {
                    char msg[32 + STRING_LENGTH];
                    sprintf(msg, "[g] #%u: YOU: %s", groupnumber, *posi + 1);
                    new_lines(msg);
                } else {
                    char msg[128];
                    sprintf(msg, "[i] could not send message to group no. %u: %i", groupnumber, res);
                    new_lines(msg);
                }
            }
        } else if (inpt_command == 't') {
            char *posi[1];
            int friendnum = strtoul(line + prompt_offset, posi, 0);

            if (**posi != 0) {
                char msg[512];
                sprintf(msg, "[t] Sending file %s to friendnum %u filenumber is %i (-1 means failure)", *posi + 1, friendnum,
                        add_filesender(m, friendnum, *posi + 1));
                new_lines(msg);
            }
        } else if (inpt_command == 'q') { //exit
            save_data(m);
            endwin();
            tox_kill(m);
            exit(EXIT_SUCCESS);
        } else if (inpt_command == 'c') { //set conversation partner
            if (line[2] == 'r') {
                if (conversation_default != 0) {
                    conversation_default = 0;
                    new_lines("[i] default conversation reset");
                } else {
                    new_lines("[i] default conversation wasn't set, nothing to do");
                }
            } else if (line[3] != ' ') {
                new_lines("[i] invalid command");
            } else {
                int num = atoi(line + 4);

                /* zero is also returned for not-a-number */
                if (!num && strcmp(line + 4, "0")) {
                    num = -1;
                }

                if (num < 0) {
                    new_lines("[i] invalid command parameter");
                } else if (line[2] == 'f') {
                    conversation_default = num + 1;
                    char buffer[128];
                    sprintf(buffer, "[i] default conversation is now to friend %i", num);
                    new_lines(buffer);
                } else if (line[2] == 'g') {
                    char buffer[128];
                    conversation_default = - (num + 1);
                    sprintf(buffer, "[i] default conversation is now to group %i", num);
                    new_lines(buffer);
                } else {
                    new_lines("[i] invalid command");
                }
            }
        } else if (inpt_command == 'p') { //list peers
            char *posi = NULL;
            int group_number = strtoul(line + prompt_offset, &posi, 0);

            if (posi != NULL) {
                char msg[64];
                uint32_t peer_cnt = tox_conference_peer_count(m, group_number, NULL);

                if (peer_cnt == UINT32_MAX) {
                    new_lines("[g] Invalid group number.");
                } else if (peer_cnt == 0) {
                    sprintf(msg, "[g] #%i: No peers in group.", group_number);
                    new_lines(msg);
                } else {
                    sprintf(msg, "[g] #%i: Group has %i peers. Names:", group_number, peer_cnt);
                    new_lines(msg);
                    print_groupchatpeers(m, group_number);
                }
            }
        } else {
            new_lines("[i] invalid command");
        }
    } else {
        if (conversation_default != 0) {
            if (conversation_default > 0) {
                int friendnumber = conversation_default - 1;
                uint32_t res = tox_friend_send_message(m, friendnumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)line, strlen(line), NULL);

                if (res == 0) {
                    char sss[128];
                    sprintf(sss, "[i] could not send message to friend no. %u", friendnumber);
                    new_lines(sss);
                } else {
                    print_formatted_message(m, line, friendnumber, 1);
                }
            } else {
                int groupnumber = - conversation_default - 1;
                int res = tox_conference_send_message(m, groupnumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)line, strlen(line), NULL);

                if (res == 0) {
                    char msg[32 + STRING_LENGTH];
                    sprintf(msg, "[g] #%u: YOU: %s", groupnumber, line);
                    new_lines(msg);
                } else {
                    char msg[128];
                    sprintf(msg, "[i] could not send message to group no. %u: %i", groupnumber, res);
                    new_lines(msg);
                }
            }
        } else {
            new_lines("[i] invalid input: neither command nor in conversation");
        }
    }
}

/* basic wrap, ignores embedded '\t', '\n' or '|'
 * inserts continuation markers if there's enough space left,
 * otherwise turns spaces into newlines if possible */
static void wrap(char output[STRING_LENGTH_WRAPPED], char input[STRING_LENGTH], int line_width)
{
    size_t i, len = strlen(input);

    if ((line_width < 4) || (len < (size_t)line_width)) {
        /* if line_width ridiculously tiny, it's not worth the effort */
        strcpy(output, input);
        return;
    }

    /* how much can we shift? */
    size_t delta_is = 0, delta_remain = STRING_LENGTH_WRAPPED - len - 1;

    /* if the line is very very short, don't insert continuation markers,
     * as they would use up too much of the line */
    if ((size_t)line_width < 2 * wrap_cont_len) {
        delta_remain = 0;
    }

    for (i = line_width; i < len; i += line_width) {
        /* look backward for a space to expand/turn into a new line */
        size_t k = i;
        size_t m = i - line_width;

        while (input[k] != ' ' && k > m) {
            k--;
        }

        if (k > m) {
            if (delta_remain > wrap_cont_len) {
                /* replace space with continuation, then
                 * set the pos. after the space as new line start
                 * (i.e. space is being "eaten") */
                memcpy(output + m + delta_is, input + m, k - m);
                strcpy(output + k + delta_is, wrap_cont_str);

                delta_remain -= wrap_cont_len - 1;
                delta_is += wrap_cont_len - 1;
                i = k + 1;
            } else {
                /* no more space to push forward: replace the space,
                 * use its pos. + 1 as starting point for the next line */
                memcpy(output + m + delta_is, input + m, k - m);
                output[k + delta_is] = '\n';
                i = k + 1;
            }
        } else {
            /* string ends right here:
             * don't add a continuation marker with nothing following */
            if (i == len - 1) {
                break;
            }

            /* nothing found backwards */
            if (delta_remain > wrap_cont_len) {
                /* break at the end of the line,
                 * i.e. in the middle of the word at the border */
                memcpy(output + m + delta_is, input + m, line_width);
                strcpy(output + i + delta_is, wrap_cont_str);

                delta_remain -= wrap_cont_len;
                delta_is += wrap_cont_len;
            } else {
                /* no more space to push, no space to convert:
                 * just copy the whole line and move on;
                 * means the line count calc'ed will be off */
                memcpy(output + m + delta_is, input + m, line_width);
            }
        }
    }

    i -= line_width;
    memcpy(output + i + delta_is, input + i, len - i);

    output[len + delta_is] = 0;
}

/*
 * extended wrap, honors '\n', accepts '|' as "break here when necessary"
 * marks wrapped lines with "+ " in front, which does expand output
 * does NOT honor '\t': would require a lot more work (and tab width isn't always 8)
 */
static void wrap_bars(char output[STRING_LENGTH_WRAPPED], char input[STRING_LENGTH], size_t line_width)
{
    size_t len = strlen(input);
    size_t ipos, opos = 0;
    size_t bar_avail = 0, space_avail = 0, nl_got = 0;   /* in opos */

    for (ipos = 0; ipos < len; ipos++) {
        if (opos - nl_got < line_width) {
            /* not yet at the limit */
            char c = input[ipos];

            if (c == ' ') {
                space_avail = opos;
            }

            output[opos++] = input[ipos];

            if (opos >= STRING_LENGTH_WRAPPED) {
                opos = STRING_LENGTH_WRAPPED - 1;
                break;
            }

            if (c == '|') {
                output[opos - 1] = ' ';
                bar_avail = opos;

                if (opos + 2 >= STRING_LENGTH_WRAPPED) {
                    opos = STRING_LENGTH_WRAPPED - 1;
                    break;
                }

                output[opos++] = '|';
                output[opos++] = ' ';
            }

            if (c == '\n') {
                nl_got = opos;
            }

            continue;
        }

        /* at the limit */
        if (bar_avail > nl_got) {
            /* overwrite */
            memcpy(output + bar_avail - 1, wrap_cont_str, wrap_cont_len);
            nl_got = bar_avail;

            ipos--;
            continue;
        }

        if (space_avail > nl_got) {
            if (opos + wrap_cont_len - 1 >= STRING_LENGTH_WRAPPED) {
                opos = STRING_LENGTH_WRAPPED - 1;
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
            if (opos + wrap_cont_len >= STRING_LENGTH_WRAPPED) {
                opos = STRING_LENGTH_WRAPPED - 1;
                break;
            }

            memcpy(output + opos, wrap_cont_str, wrap_cont_len);

            nl_got = opos;
            opos += wrap_cont_len;
        }

        output[opos++] = input[ipos];

        if (opos >= STRING_LENGTH_WRAPPED) {
            opos = STRING_LENGTH_WRAPPED - 1;
            break;
        }

        continue;
    }

    if (opos >= STRING_LENGTH_WRAPPED) {
        opos = STRING_LENGTH_WRAPPED - 1;
    }

    output[opos] = 0;
}

static int count_lines(char *string)
{
    size_t i, len = strlen(string);
    int count = 1;

    for (i = 0; i < len; i++) {
        if (string[i] == '\n') {
            count++;
        }
    }

    return count;
}

static char *appender(char *str, const char c)
{
    size_t len = strlen(str);

    if (len < STRING_LENGTH) {
        str[len + 1] = str[len];
        str[len] = c;
    }

    return str;
}

static void do_refresh(void)
{
    int count = 0;
    char wrap_output[STRING_LENGTH_WRAPPED];
    int i;

    for (i = 0; i < HISTORY; i++) {
        if (flag[i]) {
            wrap_bars(wrap_output, lines[i], x);
        } else {
            wrap(wrap_output, lines[i], x);
        }

        int L = count_lines(wrap_output);
        count = count + L;

        if (count < y) {
            move(y - 1 - count, 0);
            printw("%s", wrap_output);
            clrtoeol();
        }
    }

    move(y - 1, 0);
    clrtoeol();
    printw(">> ");
    printw("%s", input_line);
    clrtoeol();
    refresh();
}

static void print_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    new_lines("[i] received friend request with message:");
    new_lines((const char *)data);
    char numchar[100];
    sprintf(numchar, "[i] accept request with /a %u", num_requests);
    new_lines(numchar);
    memcpy(pending_requests[num_requests].id, public_key, TOX_PUBLIC_KEY_SIZE);
    pending_requests[num_requests].accepted = 0;
    ++num_requests;
    do_refresh();
}

static void print_message(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, const uint8_t *string, size_t length,
                          void *userdata)
{
    /* ensure null termination */
    uint8_t null_string[length + 1];
    memcpy(null_string, string, length);
    null_string[length] = 0;
    print_formatted_message(m, (char *)null_string, friendnumber, 0);
}

static void print_nickchange(Tox *m, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    char name[TOX_MAX_NAME_LENGTH + 1];

    if (getfriendname_terminated(m, friendnumber, name) != -1) {
        char msg[100 + length];

        if (name[0] != 0) {
            sprintf(msg, "[i] [%d] %s is now known as %s.", friendnumber, name, string);
        } else {
            sprintf(msg, "[i] [%d] Friend's name is %s.", friendnumber, string);
        }

        new_lines(msg);
    }
}

static void print_statuschange(Tox *m, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    char name[TOX_MAX_NAME_LENGTH + 1];

    if (getfriendname_terminated(m, friendnumber, name) != -1) {
        char msg[100 + length + strlen(name) + 1];

        if (name[0] != 0) {
            sprintf(msg, "[i] [%d] %s's status changed to %s.", friendnumber, name, string);
        } else {
            sprintf(msg, "[i] [%d] Their status changed to %s.", friendnumber, string);
        }

        new_lines(msg);
    }
}

static const char *data_file_name = NULL;

static Tox *load_data(void)
{
    FILE *data_file = fopen(data_file_name, "r");

    if (data_file) {
        fseek(data_file, 0, SEEK_END);
        size_t size = ftell(data_file);
        rewind(data_file);

        uint8_t data[size];

        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            fputs("[!] could not read data file!\n", stderr);
            fclose(data_file);
            return 0;
        }

        struct Tox_Options options;

        tox_options_default(&options);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

        options.savedata_data = data;

        options.savedata_length = size;

        Tox *m = tox_new(&options, NULL);

        if (fclose(data_file) < 0) {
            perror("[!] fclose failed");
            /* we got it open and the expected data read... let it be ok */
            /* return 0; */
        }

        return m;
    }

    return tox_new(NULL, NULL);
}

static int save_data(Tox *m)
{
    FILE *data_file = fopen(data_file_name, "w");

    if (!data_file) {
        perror("[!] load_key");
        return 0;
    }

    int res = 1;
    size_t size = tox_get_savedata_size(m);
    uint8_t data[size];
    tox_get_savedata(m, data);

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

static int save_data_file(Tox *m, const char *path)
{
    data_file_name = path;

    if (save_data(m)) {
        return 1;
    }

    return 0;
}

static void print_help(char *prog_name)
{
    printf("nTox %.1f - Command-line tox-core client\n", 0.1);
    printf("Usage: %s [--ipv4|--ipv6] IP PORT KEY [-f keyfile]\n", prog_name);

    puts("Options: (order IS relevant)");
    puts("  --ipv4 / --ipv6 [Optional] Support IPv4 only or IPv4 & IPv6.");
    puts("  IP PORT KEY     [REQUIRED] A node to connect to (IP/Port) and its key.");
    puts("  -f keyfile      [Optional] Specify a keyfile to read from and write to.");
}

static void print_invite(Tox *m, uint32_t friendnumber, TOX_CONFERENCE_TYPE type, const uint8_t *data, size_t length,
                         void *userdata)
{
    char msg[256];

    if (type == TOX_CONFERENCE_TYPE_TEXT) {
        sprintf(msg, "[i] received group chat invite from: %u, auto accepting and joining. group number: %u", friendnumber,
                tox_conference_join(m, friendnumber, data, length, NULL));
    } else {
        sprintf(msg, "[i] Group chat invite received of type %u that could not be accepted by ntox.", type);
    }

    new_lines(msg);
}

static void print_groupchatpeers(Tox *m, int groupnumber)
{
    uint32_t num = tox_conference_peer_count(m, groupnumber, NULL);

    if (num == UINT32_MAX) {
        return;
    }

    if (!num) {
        new_lines("[g]+ no peers left in group.");
        return;
    }

    uint8_t names[num][TOX_MAX_NAME_LENGTH];
    size_t lengths[num];

    uint32_t i;

    for (i = 0; i < num; ++i) {
        lengths[i] = tox_conference_peer_get_name_size(m, groupnumber, i, NULL);
        tox_conference_peer_get_name(m, groupnumber, i, names[i], NULL);
    }

    char numstr[16];
    char header[] = "[g]+ ";
    size_t header_len = strlen(header);
    char msg[STRING_LENGTH];
    strcpy(msg, header);
    size_t len_total = header_len;

    for (i = 0; i < num; ++i) {
        size_t len_name = lengths[i];
        size_t len_num = sprintf(numstr, "%i: ", i);

        if (len_num + len_name + len_total + 3 >= STRING_LENGTH) {
            new_lines_mark(msg, 1);

            strcpy(msg, header);
            len_total = header_len;
        }

        strcpy(msg + len_total, numstr);
        len_total += len_num;
        memcpy(msg + len_total, (char *)names[i], len_name);
        len_total += len_name;

        if (i < num - 1) {
            strcpy(msg + len_total, "|");
            len_total++;
        }
    }

    new_lines_mark(msg, 1);
}

static void print_groupmessage(Tox *m, uint32_t groupnumber, uint32_t peernumber, TOX_MESSAGE_TYPE type,
                               const uint8_t *message, size_t length,
                               void *userdata)
{
    char msg[256 + length];

    TOX_ERR_CONFERENCE_PEER_QUERY error;
    size_t len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, &error);
    uint8_t name[TOX_MAX_NAME_LENGTH] = {0};
    tox_conference_peer_get_name(m, groupnumber, peernumber, name, NULL);

    //print_groupchatpeers(m, groupnumber);
    if (len == 0 || error != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        name[0] = 0;
    }

    if (name[0] != 0) {
        sprintf(msg, "[g] %u: %u <%s>: %s", groupnumber, peernumber, name, message);
    } else {
        sprintf(msg, "[g] #%u: %u Unknown: %s", groupnumber, peernumber, message);
    }

    new_lines(msg);
}
static void print_groupnamelistchange(Tox *m, uint32_t groupnumber, uint32_t peernumber,
                                      TOX_CONFERENCE_STATE_CHANGE change,
                                      void *userdata)
{
    char msg[256];

    if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_JOIN) {
        sprintf(msg, "[g] #%i: New peer %i.", groupnumber, peernumber);
        new_lines(msg);
    } else if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_EXIT) {
        /* if peer was the last in list, it simply dropped,
         * otherwise it was overwritten by the last peer
         *
         * adjust output
         */
        uint32_t peers_total = tox_conference_peer_count(m, groupnumber, NULL);

        if (peers_total == peernumber) {
            sprintf(msg, "[g] #%i: Peer %i left.", groupnumber, peernumber);
            new_lines(msg);
        } else {
            TOX_ERR_CONFERENCE_PEER_QUERY error;
            uint8_t peername[TOX_MAX_NAME_LENGTH] = {0};
            size_t len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, &error);
            tox_conference_peer_get_name(m, groupnumber, peernumber, peername, NULL);

            if (len == 0 || error != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peername[0] = 0;
            }

            sprintf(msg, "[g] #%i: Peer %i left. Former peer [%i: <%s>] is now peer %i.", groupnumber, peernumber,
                    peers_total, peername, peernumber);
            new_lines(msg);
        }
    } else if (change == TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE) {
        uint8_t peername[TOX_MAX_NAME_LENGTH] = {0};
        int len = tox_conference_peer_get_name_size(m, groupnumber, peernumber, NULL);
        tox_conference_peer_get_name(m, groupnumber, peernumber, peername, NULL);

        if (len <= 0) {
            peername[0] = 0;
        }

        sprintf(msg, "[g] #%i: Peer %i's name changed: %s", groupnumber, peernumber, peername);
        new_lines(msg);
    } else {
        sprintf(msg, "[g] #%i: Name list changed (peer %i, change %i?):", groupnumber, peernumber, change);
        new_lines(msg);
        print_groupchatpeers(m, groupnumber);
    }
}
static void file_request_accept(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t type,
                                uint64_t file_size,
                                const uint8_t *filename, size_t filename_length, void *user_data)
{
    if (type != TOX_FILE_KIND_DATA) {
        new_lines("Refused invalid file type.");
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
    }

    char msg[512];
    sprintf(msg, "[t] %u is sending us: %s of size %llu", friend_number, filename, (long long unsigned int)file_size);
    new_lines(msg);

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, 0)) {
        sprintf(msg, "Accepted file transfer. (saving file as: %u.%u.bin)", friend_number, file_number);
        new_lines(msg);
    } else {
        new_lines("Could not accept file transfer.");
    }
}

static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                               void *user_data)
{
    char msg[512] = {0};
    sprintf(msg, "[t] control %u received", control);
    new_lines(msg);

    if (control == TOX_FILE_CONTROL_CANCEL) {
        unsigned int i;

        for (i = 0; i < NUM_FILE_SENDERS; ++i) {
            /* This is slow */
            if (file_senders[i].file && file_senders[i].friendnum == friend_number && file_senders[i].filenumber == file_number) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
                sprintf(msg, "[t] %u file transfer: %u cancelled", file_senders[i].friendnum, file_senders[i].filenumber);
                new_lines(msg);
            }
        }
    }
}

static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
    if (length == 0) {
        char msg[512];
        sprintf(msg, "[t] %u file transfer: %u completed", friendnumber, filenumber);
        new_lines(msg);
        return;
    }

    char filename[256];
    sprintf(filename, "%u.%u.bin", friendnumber, filenumber);
    FILE *pFile = fopen(filename, "r+b");

    if (pFile == NULL) {
        pFile = fopen(filename, "wb");
    }

    fseek(pFile, position, SEEK_SET);

    if (fwrite(data, length, 1, pFile) != 1) {
        new_lines("Error writing to file");
    }

    fclose(pFile);
}

static void print_online(Tox *tox, uint32_t friendnumber, TOX_CONNECTION status, void *userdata)
{
    if (status) {
        printf("\nOther went online.\n");
    } else {
        printf("\nOther went offline.\n");
        unsigned int i;

        for (i = 0; i < NUM_FILE_SENDERS; ++i) {
            if (file_senders[i].file != 0 && file_senders[i].friendnum == friendnumber) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
            }
        }
    }
}

static char timeout_getch(Tox *m)
{
    char c;
    int slpval = tox_iteration_interval(m);

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(0, &fds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = slpval * 1000;

    c = ERR;
    int n = select(1, &fds, NULL, NULL, &tv);

    if (n < 0) {
        new_lines("select error: maybe interupted");
    } else if (n == 0) {
    } else {
        c = getch();
    }

    return c;
}

int main(int argc, char *argv[])
{
    /* minimalistic locale support (i.e. when printing dates) */
    setlocale(LC_ALL, "");

    if (argc < 4) {
        if ((argc == 2) && !strcmp(argv[1], "-h")) {
            print_help(argv[0]);
            exit(0);
        }

        printf("Usage: %s [--ipv4|--ipv6] IP PORT KEY [-f keyfile] (or %s -h for help)\n", argv[0], argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    uint8_t ipv6enabled = 1; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    int on = 0;
    const char *filename = "data";
    char idstring[200] = {0};
    Tox *m;

    /* [-f keyfile] MUST be last two arguments, no point in walking over the list
     * especially not a good idea to accept it anywhere in the middle */
    if (argc > argvoffset + 3) {
        if (!strcmp(argv[argc - 2], "-f")) {
            filename = argv[argc - 1];
        }
    }

    data_file_name = filename;
    m = load_data();

    if (!m) {
        fputs("Failed to allocate Messenger datastructure", stderr);
        exit(0);
    }

    save_data_file(m, filename);

    tox_callback_friend_request(m, print_request);
    tox_callback_friend_message(m, print_message);
    tox_callback_friend_name(m, print_nickchange);
    tox_callback_friend_status_message(m, print_statuschange);
    tox_callback_conference_invite(m, print_invite);
    tox_callback_conference_message(m, print_groupmessage);
    tox_callback_conference_namelist_change(m, print_groupnamelistchange);
    tox_callback_file_recv_chunk(m, write_file);
    tox_callback_file_recv_control(m, file_print_control);
    tox_callback_file_recv(m, file_request_accept);
    tox_callback_file_chunk_request(m, tox_file_chunk_request);
    tox_callback_friend_connection_status(m, print_online);

    initscr();
    noecho();
    raw();
    getmaxyx(stdscr, y, x);

    new_lines("/h for list of commands");
    get_id(m, idstring);
    new_lines(idstring);
    strcpy(input_line, "");

    uint16_t port = atoi(argv[argvoffset + 2]);
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = tox_bootstrap(m, argv[argvoffset + 1], port, binary_string, NULL);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        endwin();
        exit(1);
    }

    nodelay(stdscr, TRUE);

    new_lines("[i] change username with /n");
    uint8_t name[TOX_MAX_NAME_LENGTH + 1];
    tox_self_get_name(m, name);
    uint16_t namelen = tox_self_get_name_size(m);
    name[namelen] = 0;

    if (namelen > 0) {
        char whoami[128 + TOX_MAX_NAME_LENGTH];
        snprintf(whoami, sizeof(whoami), "[i] your current username is: %s", name);
        new_lines(whoami);
    }

    time_t timestamp0 = time(NULL);

    while (1) {
        if (on == 0) {
            if (tox_self_get_connection_status(m)) {
                new_lines("[i] connected to DHT");
                on = 1;
            } else {
                time_t timestamp1 = time(NULL);

                if (timestamp0 + 10 < timestamp1) {
                    timestamp0 = timestamp1;
                    tox_bootstrap(m, argv[argvoffset + 1], port, binary_string, NULL);
                }
            }
        }

        tox_iterate(m, NULL);
        do_refresh();

        int c = timeout_getch(m);

        if (c == ERR || c == 27) {
            continue;
        }

        getmaxyx(stdscr, y, x);

        if ((c == 0x0d) || (c == 0x0a)) {
            line_eval(m, input_line);
            strcpy(input_line, "");
        } else if (c == 8 || c == 127) {
            input_line[strlen(input_line) - 1] = '\0';
        } else if (isalnum(c) || ispunct(c) || c == ' ') {
            appender(input_line, (char) c);
        }
    }

    free(binary_string);
    save_data_file(m, filename);
    tox_kill(m);
    endwin();
    return 0;
}
