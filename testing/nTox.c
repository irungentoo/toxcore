#include "nTox.h"

#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

char lines[HISTORY][STRING_LENGTH];
char line[STRING_LENGTH];
int x,y;

void new_lines(char *line)
{
    int i;
    for (i = HISTORY-1; i > 0; i--) {
        strcpy(lines[i],lines[i-1]);
    }
    strcpy(lines[0],line);
    do_refresh();
}

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

void line_eval(char lines[HISTORY][STRING_LENGTH], char *line)
{
    if (line[0] == '/') {
        char command[STRING_LENGTH + 2] = "> ";
        strcat(command, line);
        new_lines(command);
        if (line[1] == 'f') { // add friend command: /f ID
            int i;
            char temp_id[128];
            for (i=0; i<128; i++) {
                temp_id[i] = line[i+3];
            }
            int num = m_addfriend(hex_string_to_bin(temp_id), (uint8_t*)"Install Gentoo", sizeof("Install Gentoo"));
            char numstring[100];
            sprintf(numstring, "Friend added, number: %d", num);
            new_lines(numstring);
            do_refresh();
        } else if (line[1] == 'd') {
            doMessenger();
        } else if (line[1] == 'm') { //message command: /m friendnumber messsage
            int i;
            int len = strlen(line);
            char numstring[len-3];
            char message[len-3];
            for (i=0; i<len; i++) {
                if (line[i+3] != ' ') {
                    numstring[i] = line[i+3];
                } else {
                    int j;
                    for (j=i+1; j<len; j++) {
                        message[j-i-1] = line[j+3];
                    }
                    break;
                }
            }
            int num = atoi(numstring);
            m_sendmessage(num, (uint8_t*) message, sizeof(message));
        } else if (line[1] == 'q') { //exit
		endwin();
		exit(EXIT_SUCCESS);
        }
    } else {
        //new_lines(line);
    }
}

void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width) 
{
    int i = 0;
    strcpy(output,input);
    for (i=line_width; i < strlen(output); i = i + line_width) {
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
    int len = strlen(string);
    int i;
    int count = 1;
    for (i=0; i < len; i++) {
        if (string[i] == '\n') {
            count++;
        }
    }
    return count;
}

char *appender(char *str, const char c)
{
    int len = strlen(str);
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
void print_request(uint8_t * public_key, uint8_t * data, uint16_t length)
{
    new_lines("Friend request");
    do_refresh();
    if(memcmp(data , "Install Gentoo", sizeof("Install Gentoo")) == 0 )
    //if the request contained the message of peace the person is obviously a friend so we add him.
    {
        new_lines("Friend request accepted.");
        do_refresh();
        int num = m_addfriend_norequest(public_key);
        char numchar[100];
        sprintf(numchar, "Friend added, number: %d", num);
        new_lines(numchar);
    }
}
void print_message(int friendnumber, uint8_t * string, uint16_t length)
{
    char msg[100+length];
    sprintf(msg, "Message [%d]: %s", friendnumber, string);
    new_lines(msg);
}
int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("usage %s ip port public_key (of the DHT bootstrap node)\n", argv[0]);
        exit(0);
    }
    int c;
    int on = 0;
    initMessenger();
    m_callback_friendrequest(print_request);
    m_callback_friendmessage(print_message);
    char idstring0[200];
    char idstring1[32][5];
    char idstring2[32][5];
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16) {
            strcpy(idstring1[i],"0");
        } else {
            strcpy(idstring1[i], "");
        }
        sprintf(idstring2[i], "%hhX",self_public_key[i]);
    }
    strcpy(idstring0,"Your ID is: ");
    for(i=0; i<32; i++) {
        strcat(idstring0,idstring1[i]);
        strcat(idstring0,idstring2[i]);
    }
    initscr();
    noecho();
    raw();
    getmaxyx(stdscr,y,x);
    new_lines(idstring0);
    new_lines("/f ID (to add friend), /m friendnumber message (to send message)");
    strcpy(line, "");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    bootstrap_ip_port.ip.i = inet_addr(argv[1]);
    DHT_bootstrap(bootstrap_ip_port, hex_string_to_bin(argv[3]));
    nodelay(stdscr, TRUE);
    while(true) {
        c=getch();
        if (c != ERR) {
            if (c != 27) {
                getmaxyx(stdscr,y,x);
                if (c == '\n') {
                    line_eval(lines, line);
                    strcpy(line, "");
                } else if (c == 127) {
                    line[strlen(line)-1] = '\0';
                } else if (isalnum(c) || ispunct(c) || c == ' ') {
                    strcpy(line,appender(line, (char) c));
                }
            } else {
                break;
            }
        }
        if(on == 0)
        {
            if(DHT_isconnected())
            {
                new_lines("You are now connected to the DHT.");
                on = 1;
            }
        }
        doMessenger();
        c_sleep(1);
        do_refresh();
    }
    endwin();
    return 0;
}
