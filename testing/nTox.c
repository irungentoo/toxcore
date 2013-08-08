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
#include "nTox.h"
#include "misc_tools.h"

#include <stdio.h>
#include <time.h>

#ifdef WIN32
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
    uint8_t id[CLIENT_ID_SIZE];
    uint8_t accepted;
} Friend_request;

Friend_request pending_requests[256];
uint8_t num_requests = 0;

void get_id(char *data)
{
    char idstring0[200];
    char idstring1[PUB_KEY_BYTES][5];
    char idstring2[PUB_KEY_BYTES][5];
    int i = 0;
    for(i = 0; i < PUB_KEY_BYTES; i++)
    {
        if (self_public_key[i] < (PUB_KEY_BYTES / 2))
            strcpy(idstring1[i],"0");
        else
            strcpy(idstring1[i], "");
        sprintf(idstring2[i], "%hhX",self_public_key[i]);
    }
    strcpy(idstring0,"[i] ID: ");
    int j = 0;
    for (j = 0; j < PUB_KEY_BYTES; j++) {
        strcat(idstring0,idstring1[j]);
        strcat(idstring0,idstring2[j]);
    }

    memcpy(data, idstring0, strlen(idstring0));
}

void new_lines(char *line)
{
    int i = 0;
    for (i = HISTORY-1; i > 0; i--)
        strncpy(lines[i], lines[i-1], STRING_LENGTH - 1);

    strncpy(lines[0], line, STRING_LENGTH - 1);
    do_refresh();
}


void print_friendlist()
{
    char name[MAX_NAME_LENGTH];
    int i = 0;
    new_lines("[i] Friend List:");
    while(getname(i, (uint8_t *)name) != -1) {
        /* account for the longest name and the longest "base" string */
        char fstring[MAX_NAME_LENGTH + strlen("[i] Friend: NULL\n\tid: ")];

        if (strlen(name) <= 0) {
            sprintf(fstring, "[i] Friend: No Friend!\n\tid: %i", i);
        } else {
            sprintf(fstring, "[i] Friend: %s\n\tid: %i", (uint8_t*)name, i);
        }
        i++;
        new_lines(fstring);
    }

    if(i == 0)
        new_lines("\tno friends! D:");
}

char *format_message(char *message, int friendnum)
{
    char name[MAX_NAME_LENGTH];
    if (friendnum != -1) {
            getname(friendnum, (uint8_t*)name);
    } else {
            getself_name((uint8_t*)name);
    }
    char *msg = malloc(100+strlen(message)+strlen(name)+1);

    time_t rawtime;
    struct tm * timeinfo;
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* time = asctime(timeinfo);
    size_t len = strlen(time);
    time[len-1] = '\0';
    if (friendnum != -1) {
        sprintf(msg, "[%d] %s <%s> %s", friendnum, time, name, message);
    } else {
        // This message came from ourselves
        sprintf(msg, "%s <%s> %s", time, name, message);
    }
    return msg;
}

void add_friend_error(int code)
{
    switch(code) {
        case FAERR_TOOLONG:
            new_lines("[!] the key was too long!\n");
            break;
        case FAERR_NOMESSAGE:
            new_lines("[!] you didn't give a message!\n");
            break;
        case FAERR_OWNKEY:
            new_lines("[!] that was _your_ key!\n");
            break;
        case FAERR_ALREADYSENT:
            new_lines("[!] you already know that person!\n");
            break;
        case FAERR_UNKNOWN:
            new_lines("[!] something happened!\n");
            break;
        default:
            break;
    }
}

void line_eval(char *line)
{
    char *save_ptr = NULL;
    char *command = NULL;
    int command_char = 0;

    command = strtok_r(line, " ", &save_ptr);

    if(command == NULL || command[0] != '/')
        /* no command, who cares */
        return;

    command_char = command[1];
    if(command_char == 'f') { // add friend: /f ID MESSAGE
        char *id = strtok_r(NULL, " ", &save_ptr);
        char *message = NULL;
        int message_len = 0;
        int rc = 0;

        if(id == NULL)
            new_lines("/f needs an ID to act upon.\n");
        else {
            message = strtok_r(NULL, "", &save_ptr);

            if(message == NULL)
                message = "Install Gentoo";

            unsigned char *bin_string = hex_string_to_bin(id);
            message_len = strlen(message);
            rc = m_addfriend(bin_string, strlen(id),
                    (uint8_t *)message, sizeof(char) * message_len);
            if(rc < 0)
                add_friend_error(rc);
        }
    } else if (command_char == 'd') {
            doMessenger();
    } else if (command_char == 'm') { //message command: /m friendnumber messsage
        char *friend_number = strtok_r(NULL, " ", &save_ptr);
        char *message = strtok_r(NULL, " ", &save_ptr);

        if(friend_number == NULL || message == NULL) {
            new_lines("[!] improper syntax!");
            return;
        }

        if (m_sendmessage(atoi(friend_number), (uint8_t*) message, strlen(message) + 1) != 1)
            new_lines("[i] could not send message");
        else
            new_lines(format_message(message, -1));

    } else if (command_char == 'n') {
        char *name = strtok_r(NULL, " ", &save_ptr);
        if(name == NULL) {
            new_lines("[!] improper syntax!");
            return;
        }
        setname((uint8_t *)name, strlen(name));

        char numstring[100];
        sprintf(numstring, "[i] changed nick to %s", (char*)name);
        new_lines(numstring);
    } else if (command_char == 'l') {
            print_friendlist();
    } else if (command_char == 's') {
        char *status = strtok_r(NULL, "", &save_ptr);

        if(status == NULL) {
            new_lines("[!] improper syntax");
            return;
        }
        m_set_userstatus(USERSTATUS_KIND_ONLINE, (uint8_t *)status, strlen((char*)status) + 1);
        char numstring[100];
        sprintf(numstring, "[i] changed status to %s", (char*)status);
        new_lines(numstring);
    } else if (command_char == 'a') {
        char *num = strtok_r(NULL, " ", &save_ptr);
        uint8_t numf = atoi(num);
        char numchar[100];
        if (numf >= num_requests || pending_requests[numf].accepted)
            new_lines("[i] you either didn't receive that request or you already accepted it");
        else {
            int num = m_addfriend_norequest(pending_requests[numf].id, ID_STRLEN);
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
    } else if (command_char == 'h') { //help
       new_lines(help);
    } else if (command_char == 'i') { //info
       char idstring[200] = {0};
       get_id(idstring);
       new_lines(idstring);
   } else if (command_char == 'q') { //exit
        endwin();
        exit(EXIT_SUCCESS);
    } else {
        new_lines("[i] invalid command");
    }
}

void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width)
{
    strcpy(output,input);
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
        str[len+1] = str[len];
        str[len] = c;
    }
    return str;
}

void do_refresh()
{
    int count=0;
    char wrap_output[STRING_LENGTH];
    int L;
    int i;
    for (i = 0; i < HISTORY; i++) {
        wrap(wrap_output, lines[i], x);
        L = count_lines(wrap_output);
        count = count + L;
        if (count < y) {
            move(y-1-count, 0);
            printw(wrap_output);
            clrtoeol();
        }
    }
    move(y-1, 0);
    clrtoeol();
    printw(">> ");
    printw(line);
    clrtoeol();
    refresh();
}

void print_request(uint8_t *public_key, uint8_t *data, uint16_t length)
{
    new_lines("[i] received friend request with message:");
    new_lines((char *)data);
    char numchar[100];
    sprintf(numchar, "[i] accept request with /a %u", num_requests);
    new_lines(numchar);
    memcpy(pending_requests[num_requests].id, public_key, CLIENT_ID_SIZE);
    pending_requests[num_requests].accepted = 0;
    ++num_requests;
    do_refresh();
}

void print_message(int friendnumber, uint8_t * string, uint16_t length)
{
    new_lines(format_message((char*)string, friendnumber));
}

void print_nickchange(int friendnumber, uint8_t *string, uint16_t length)
{
    char name[MAX_NAME_LENGTH];
    if(getname(friendnumber, (uint8_t*)name) != -1) {
        char msg[100+length];
        sprintf(msg, "[i] [%d] %s is now known as %s.", friendnumber, name, string);
        new_lines(msg);
    }
}

void print_statuschange(int friendnumber, USERSTATUS_KIND kind, uint8_t *string, uint16_t length)
{
    char name[MAX_NAME_LENGTH];
    if(getname(friendnumber, (uint8_t*)name) != -1) {
        char msg[100+length+strlen(name)+1];
        sprintf(msg, "[i] [%d] %s's status changed to %s.", friendnumber, name, string);
        new_lines(msg);
    }
}

void load_key(char *path)
{
    FILE *data_file = fopen(path, "r");
    int size = 0;

    if (data_file) {
        //load keys
        fseek(data_file, 0, SEEK_END);
        size = ftell(data_file);
        rewind(data_file);

        uint8_t data[size];
        if (fread(data, sizeof(uint8_t), size, data_file) != size){
            fputs("[!] could not read data file! exiting...\n", stderr);
            goto FILE_ERROR;
        }
        Messenger_load(data, size);

    } else {
        //else save new keys
        int size = Messenger_size();
        uint8_t data[size];
        Messenger_save(data);
        data_file = fopen(path, "w");

        if(!data_file) {
            perror("[!] load_key");
            exit(1);
        }

        if (fwrite(data, sizeof(uint8_t), size, data_file) != size){
            fputs("[!] could not write data file! exiting...", stderr);
            goto FILE_ERROR;
        }
    }

    if(fclose(data_file) < 0)
        perror("[!] fclose failed");
    return;

FILE_ERROR:
    if(fclose(data_file) < 0)
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

    if (argc < 4) {
        printf("[!] Usage: %s [IP] [port] [public_key] <keyfile>\n", argv[0]);
        exit(0);
    }

    for(i = 0; i < argc; i++) {
      if (argv[i] == NULL){
        break;
      } else if(argv[i][0] == '-') {
            if(argv[i][1] == 'h') {
                print_help();
                exit(0);
            } else if(argv[i][1] == 'f') {
                if(argv[i + 1] != NULL)
                    filename = argv[i + 1];
                else {
                    fputs("[!] you passed '-f' without giving an argument!\n", stderr);
                }
            }
        }
    }

    initMessenger();
    load_key(filename);

    m_callback_friendrequest(print_request);
    m_callback_friendmessage(print_message);
    m_callback_namechange(print_nickchange);
    m_callback_userstatus(print_statuschange);

    initscr();
    noecho();
    raw();
    getmaxyx(stdscr, y, x);

    new_lines("/h for list of commands");
    get_id(idstring);
    new_lines(idstring);
    strcpy(line, "");

    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    int resolved_address = resolve_addr(argv[1]);
    if (resolved_address != 0)
        bootstrap_ip_port.ip.i = resolved_address;
    else
        exit(1);

    unsigned char *binary_string = hex_string_to_bin(argv[3]);
    DHT_bootstrap(bootstrap_ip_port, binary_string);
    free(binary_string);
    nodelay(stdscr, TRUE);
    while(true) {
        if (on == 0 && DHT_isconnected()) {
            new_lines("[i] connected to DHT\n[i] define username with /n");
            on = 1;
        }

        doMessenger();
        c_sleep(1);
        do_refresh();

        c = getch();
        if (c == ERR || c == 27)
            continue;

        getmaxyx(stdscr, y, x);
        if (c == '\n') {
            line_eval(line);
            strcpy(line, "");
        } else if (c == 8 || c == 127) {
            line[strlen(line)-1] = '\0';
        } else if (isalnum(c) || ispunct(c) || c == ' ') {
            strcpy(line, appender(line, (char) c));
        }
    }
    endwin();
    return 0;
}
