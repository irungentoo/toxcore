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
#include <string.h>
#include <time.h>
#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

char lines[HISTORY][STRING_LENGTH];
char line[STRING_LENGTH];
int x,y;

uint8_t pending_requests[256][CLIENT_ID_SIZE];
uint8_t num_requests;

void new_lines(char *line)
{
    int i;
    for (i = HISTORY-1; i > 0; i--) 
        strcpy(lines[i],lines[i-1]);
    
    strcpy(lines[0],line);
    do_refresh();
}


void print_friendlist()
{
    char name[MAX_NAME_LENGTH];
    uint32_t i = 0;

    new_lines("[i] Friend List:");
    while(getname(i++, (uint8_t *)name) != -1) {
        char fstring[128];
        if(strlen(name) <= 0) {
            sprintf(fstring, "[i] Friend: No friend here!\n\tid: %i", i);
        } else {
            sprintf(fstring, "[i] Friend: %s\n\tid: %i", (uint8_t*)name, i);
        }
        new_lines(fstring);
    }
}

char *format_message(char *message, int friendnum)
{
	char name[MAX_NAME_LENGTH];
	if(friendnum != -1) {
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
    time[len-1]='\0';
    sprintf(msg, "[%d] %s <%s> %s", friendnum, time, name, message); // timestamp
    return msg;
}

void add_friend_error(int code)
{
    switch(code) {
        case ERR_KEY_LENGTH:
            new_lines("[!] the key wasn't long enough!");
            break;
        case ERR_OWN_KEY:
            new_lines("[!] that was _your_ key!");
            break;
        case ERR_IS_FRIEND:
            new_lines("[!] you already know that person!");
            break;
        case ERR_OTHER:
            new_lines("[!] something happened!");
            break;
        default:
            break;
    }
}

/* this should be split up into something like eval_info, eval_friend, etc. */
/* evaluate a possible user command in the following format:
     '/[letter] <args>' */
void line_eval(char lines[HISTORY][STRING_LENGTH], char *line)
{
    char *save_ptr = NULL;
    char *command = NULL;
    int command_char = 0;

    /* print out the command entered */
    char command_str[STRING_LENGTH + 2] = "> ";
    strcat(command_str, line);
    new_lines(command_str);

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

        if(id == NULL) {
            new_lines("[!] /f needs an ID to act upon!");
        } else {
            message = strtok_r(NULL, " ", &save_ptr);

            if(message == NULL)
                message = "Install Gentoo";

            message_len = strlen(message);
            rc = m_addfriend(hex_string_to_bin(id), (uint8_t *)message, sizeof(char) * message_len);

            add_friend_error(rc);
        }

    } else if(command_char == 'd') { // main loop
        doMessenger();

    } else if(command_char == 'm') { //message command: /m friendnumber messsage
        char *num = strtok_r(NULL, " ", &save_ptr);
        char *message = NULL;
        int message_len = 0;
        int rc = 0;

        if(num == NULL) {
            new_lines("[!] /m needs a friend number to act upon!");
            return;
        }
        message = strtok_r(NULL, " ", &save_ptr);

        if(message == NULL) {
            new_lines("[!] /m needs a message to send!");
            return;
        }

        message_len = strlen(message);
        rc = m_sendmessage(atoi(num), (uint8_t *)message, sizeof(char) * message_len);
        if(rc == 0)
            new_lines("[!] /m fucked up!");

    } else if(command_char == 'n') { // set name: /n NAME
        char *name = strtok_r(NULL, " ", &save_ptr);
        char name_mem[MAX_NAME_LENGTH];
        char numstring[MAX_NAME_LENGTH];

        if(name == NULL) {
            new_lines("[!] /n needs a name to act upon!");
            return;
        }

        strncpy(name_mem, name, MAX_NAME_LENGTH - 1);
        setname((uint8_t *)name_mem, strlen(name_mem));

        sprintf(numstring, "[i] changed nick to %s", (char*)name);
        new_lines(numstring);

    } else if(command_char == 'l') { // print friends list: /l
        print_friendlist();

    } else if (line[1] == 's') { // set status: /s SOMETHING
        /* what's the user entering here? a digit? a string? */
        char *status = strtok_r(NULL, " ", &save_ptr);
        char numstring[MAX_USERSTATUS_LENGTH];

        if(status == NULL) {
            new_lines("[!] /s needs a...thing! go type it! (pls document /s)");
            return;
        }

        m_set_userstatus((uint8_t *)status, strlen(status));
        sprintf(numstring, "[i] changed status to %s", (char*)status);
        new_lines(numstring);

    } else if (command_char == 'a') { // accept a friend request: /a ID
        char *friend_num = strtok_r(NULL, " ", &save_ptr);
        char numchar[ID_LENGTH];
        int friend = 0;
        int rc = 0;

        if(friend_num == NULL) {
            new_lines("[!] /a needs an ID to act upon!");
            return;
        }

        friend = atoi(friend_num);
        rc = m_addfriend_norequest(pending_requests[friend]);

        if(rc == -1)
            sprintf(numchar, "[!] no such friend (%d)!", friend);
        else {
            sprintf(numchar, "[i] friend request %u accepted", friend);
            new_lines(numchar);
            sprintf(numchar, "[i] added friendnumber %d", friend);
            new_lines(numchar);
        }

    } else if (command_char == 'h') { // help!
        new_lines("[i] commands:\n/f ID (to add friend)\n/m friendnumber "
                 "message (to send message)\n/s status (to change status)");
        new_lines("/l list (list friends)\n/h for help\n/i for info\n/n nick "
                 "(to change nickname)\n/q (to quit)");

    } else if (command_char == 'i') { // print some helpful info: /i
       char idstring0[200];
       char idstring1[32][5];
       char idstring2[32][5];
       uint32_t i;
       for(i = 0; i < 32; i++)
       {
           if(self_public_key[i] < 16)
               strcpy(idstring1[i],"0");
           else 
               strcpy(idstring1[i], "");
           sprintf(idstring2[i], "%hhX",self_public_key[i]);
       }

       strcpy(idstring0,"[i] ID: ");
       for (i=0; i<32; i++) {
           strcat(idstring0,idstring1[i]);
           strcat(idstring0,idstring2[i]);
       }    
      new_lines(idstring0);

   } else if (command_char == 'q') { //exit
        endwin();
        /* where does *line come from?
         *  possible memory leak? */
        exit(EXIT_SUCCESS);

    } else
        new_lines("[i] invalid command");

    do_refresh();
}

void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width)
{
    int i = 0;
    strcpy(output,input);
    size_t len = strlen(output);
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
    int i;
    int count = 1;
    for (i=0; i < len; i++) {
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
    int i;
    int count=0;
    int l;
    char wrap_output[STRING_LENGTH];
    for (i=0; i<HISTORY; i++) {
        wrap(wrap_output, lines[i], x);
        l = count_lines(wrap_output);
        count = count + l;
        if (count < y) {
            move(y-1-count,0);
            printw(wrap_output);
            clrtoeol();
        }
    }
    move(y-1,0);
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
    memcpy(pending_requests[num_requests], public_key, CLIENT_ID_SIZE);
    ++num_requests;
    do_refresh();
}

void print_message(int friendnumber, uint8_t * string, uint16_t length)
{
    char name[MAX_NAME_LENGTH];
    getname(friendnumber, (uint8_t*)name);
    char msg[100+length+strlen(name)+1];
    time_t rawtime;
    struct tm * timeinfo;
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    char* temp = asctime(timeinfo);
    size_t len = strlen(temp);
    temp[len-1]='\0';
    sprintf(msg, "[%d] %s <%s> %s", friendnumber, temp, name, string); // timestamp
    new_lines(format_message((char*)string, friendnumber));
}

void print_nickchange(int friendnumber, uint8_t *string, uint16_t length) {
    char name[MAX_NAME_LENGTH];
    getname(friendnumber, (uint8_t*)name);
    char msg[100+length];
    sprintf(msg, "[i] [%d] %s is now known as %s.", friendnumber, name, string);
    new_lines(msg);
}

void print_statuschange(int friendnumber, uint8_t *string, uint16_t length) {
    char name[MAX_NAME_LENGTH];
    getname(friendnumber, (uint8_t*)name);
    char msg[100+length+strlen(name)+1];
    sprintf(msg, "[i] [%d] %s's status changed to %s.", friendnumber, name, string);
    new_lines(msg);
}

void load_key(){
    FILE *data_file = NULL;
    if ((data_file = fopen("data","r"))) {
        //load keys
        fseek(data_file, 0, SEEK_END);
        int size = ftell(data_file);
        fseek(data_file, 0, SEEK_SET);
        uint8_t data[size];
        if(fread(data, sizeof(uint8_t), size, data_file) != size){
            printf("[i] could not read data file\n[i] exiting\n");
            exit(1);
        }
        Messenger_load(data, size);
    } else { 
        //else save new keys
        int size = Messenger_size();
        uint8_t data[size];
        Messenger_save(data);
        data_file = fopen("data","w");
        if(fwrite(data, sizeof(uint8_t), size, data_file) != size){
            printf("[i] could not write data file\n[i] exiting\n");
            exit(1);
        }
    }
   fclose(data_file);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("[!] Usage: %s [IP] [port] [public_key] <nokey>\n", argv[0]);
        exit(0);
    }
    int c;
    int on = 0;
    initMessenger();
    //if keyfiles exist
    if(argc > 4){
        if(strncmp(argv[4], "nokey", 6) < 0){
        //load_key();
        }
    } else {
        load_key();
    }
    m_callback_friendrequest(print_request);
    m_callback_friendmessage(print_message);
    m_callback_namechange(print_nickchange);
    m_callback_userstatus(print_statuschange);
    char idstring0[200];
    char idstring1[32][5];
    char idstring2[32][5];
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16)
            strcpy(idstring1[i],"0");
        else 
            strcpy(idstring1[i], "");
        sprintf(idstring2[i], "%hhX",self_public_key[i]);
    }
    strcpy(idstring0,"[i] your ID: ");
    for (i=0; i<32; i++) {
        strcat(idstring0,idstring1[i]);
        strcat(idstring0,idstring2[i]);
    }
    initscr();
    noecho();
    raw();
    getmaxyx(stdscr,y,x);
    new_lines(idstring0);
    new_lines("[i] commands: /f ID (to add friend), /m friendnumber message  (to send message), /s status (to change status)");
    new_lines("[i] /l list (list friends), /h for help, /i for info, /n nick (to change nickname), /q (to quit)");
    strcpy(line, "");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    int resolved_address = resolve_addr(argv[1]);
    if (resolved_address != -1)
        bootstrap_ip_port.ip.i = resolved_address;
    else 
        exit(1);
    
    DHT_bootstrap(bootstrap_ip_port, hex_string_to_bin(argv[3]));
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
            line_eval(lines, line);
            strcpy(line, "");
        } else if (c == 127) {
            line[strlen(line) - 1] = '\0';
        } else if (isalnum(c) || ispunct(c) || c == ' ') {
            strcpy(line, appender(line, (char) c));
        }
    }
    endwin();
    return 0;
}
