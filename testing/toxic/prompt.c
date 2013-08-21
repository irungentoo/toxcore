/*
* Toxic -- Tox Curses Client
*/

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curses.h>

#include "../../core/Messenger.h"
#include "../../core/network.h"

#include "windows.h"
#include "prompt.h"

extern char *DATA_FILE;
extern int store_data(Messenger *m, char *path);

uint8_t pending_requests[MAX_STR_SIZE][CLIENT_ID_SIZE]; // XXX
uint8_t num_requests = 0; // XXX

static char prompt_buf[MAX_STR_SIZE] = {0};
static int prompt_buf_pos = 0;

/* commands */
void cmd_accept(ToxWindow *, Messenger *m, char **);
void cmd_add(ToxWindow *, Messenger *m, char **);
void cmd_clear(ToxWindow *, Messenger *m, char **);
void cmd_connect(ToxWindow *, Messenger *m, char **);
void cmd_help(ToxWindow *, Messenger *m, char **);
void cmd_msg(ToxWindow *, Messenger *m, char **);
void cmd_myid(ToxWindow *, Messenger *m, char **);
void cmd_nick(ToxWindow *, Messenger *m, char **);
void cmd_mynick(ToxWindow *, Messenger *m, char **);
void cmd_quit(ToxWindow *, Messenger *m, char **);
void cmd_status(ToxWindow *, Messenger *m, char **);
void cmd_statusmsg(ToxWindow *, Messenger *m, char **);

#define NUM_COMMANDS 14

static struct {
    char *name;
    int numargs;
    void (*func)(ToxWindow *, Messenger *m, char **);
} commands[] = {
    { "accept",    1, cmd_accept    },
    { "add",       1, cmd_add       },
    { "clear",     0, cmd_clear     },
    { "connect",   3, cmd_connect   },
    { "exit",      0, cmd_quit      },
    { "help",      0, cmd_help      },
    { "msg",       2, cmd_msg       },
    { "myid",      0, cmd_myid      },
    { "nick",      1, cmd_nick      },
    { "mynick",    0, cmd_mynick    },
    { "q",         0, cmd_quit      },
    { "quit",      0, cmd_quit      },
    { "status",    2, cmd_status    },
    { "statusmsg", 1, cmd_statusmsg },
};

// XXX:
int add_req(uint8_t *public_key)
{
    memcpy(pending_requests[num_requests], public_key, CLIENT_ID_SIZE);
    ++num_requests;
    return num_requests - 1;
}

// XXX: FIX
unsigned char *hex_string_to_bin(char hex_string[])
{
    size_t len = strlen(hex_string);
    unsigned char *val = malloc(len);
    char *pos = hex_string;
    int i;

    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &val[i]);

    return val;
}

void cmd_accept(ToxWindow *self, Messenger *m, char **args)
{
    int num = atoi(args[1]);

    if (num >= num_requests) {
        wprintw(self->window, "Invalid syntax.\n");
        return;
    }

    num = m_addfriend_norequest(m, pending_requests[num]);

    if (num == -1)
        wprintw(self->window, "Failed to add friend.\n");
    else {
        wprintw(self->window, "Friend accepted as: %d.\n", num);
        on_friendadded(m, num);
    }
}

void cmd_add(ToxWindow *self, Messenger *m, char **args)
{
    uint8_t id_bin[FRIEND_ADDRESS_SIZE];
    char xx[3];
    uint32_t x;
    char *id = args[1];
    char *msg = args[2];

    if (!id) {
        wprintw(self->window, "Invalid command: add expected at least one argument.\n");
        return;
    }

    if (!msg)
        msg = "";

    if (strlen(id) != 2 * FRIEND_ADDRESS_SIZE) {
        wprintw(self->window, "Invalid ID length.\n");
        return;
    }

    int i;

    for (i = 0; i < FRIEND_ADDRESS_SIZE; ++i) {
        xx[0] = id[2 * i];
        xx[1] = id[2 * i + 1];
        xx[2] = '\0';

        if (sscanf(xx, "%02x", &x) != 1) {
            wprintw(self->window, "Invalid ID.\n");
            return;
        }

        id_bin[i] = x;
    }

    for (i = 0; i < FRIEND_ADDRESS_SIZE; i++) {
        id[i] = toupper(id[i]);
    }

    int num = m_addfriend(m, id_bin, (uint8_t *) msg, strlen(msg) + 1);

    switch (num) {
        case FAERR_TOOLONG:
            wprintw(self->window, "Message is too long.\n");
            break;

        case FAERR_NOMESSAGE:
            wprintw(self->window, "Please add a message to your request.\n");
            break;

        case FAERR_OWNKEY:
            wprintw(self->window, "That appears to be your own ID.\n");
            break;

        case FAERR_ALREADYSENT:
            wprintw(self->window, "Friend request already sent.\n");
            break;

        case FAERR_UNKNOWN:
            wprintw(self->window, "Undefined error when adding friend.\n");
            break;

        case FAERR_BADCHECKSUM:
            wprintw(self->window, "Bad checksum in address.\n");
            break;

        case FAERR_SETNEWNOSPAM:
            wprintw(self->window, "Nospam was different.\n");
            break;

        default:
            wprintw(self->window, "Friend added as %d.\n", num);
            on_friendadded(m, num);
            break;
    }
}

void cmd_clear(ToxWindow *self, Messenger *m, char **args)
{
    wclear(self->window);
}

void cmd_connect(ToxWindow *self, Messenger *m, char **args)
{
    IP_Port dht;
    char *ip = args[1];
    char *port = args[2];
    char *key = args[3];

    if (atoi(port) == 0) {
        wprintw(self->window, "Invalid syntax.\n");
        return;
    }

    dht.port = htons(atoi(port));
    uint32_t resolved_address = resolve_addr(ip);

    if (resolved_address == 0) {
        return;
    }

    dht.ip.i = resolved_address;
    unsigned char *binary_string = hex_string_to_bin(key);
    DHT_bootstrap(m->dht, dht, binary_string);
    free(binary_string);
}

void cmd_quit(ToxWindow *self, Messenger *m, char **args)
{
    endwin();
    exit(0);
}

void cmd_help(ToxWindow *self, Messenger *m, char **args)
{
    wclear(self->window);
    wattron(self->window, COLOR_PAIR(2) | A_BOLD);
    wprintw(self->window, "Commands:\n");
    wattroff(self->window, A_BOLD);

    wprintw(self->window, "      connect <ip> <port> <key> : Connect to DHT server\n");
    wprintw(self->window, "      add <id> <message>        : Add friend\n");
    wprintw(self->window, "      status <type> <message>   : Set your status\n");
    wprintw(self->window, "      statusmsg  <message>      : Set your status\n");
    wprintw(self->window, "      nick <nickname>           : Set your nickname\n");
    wprintw(self->window, "      mynick                    : Print your current nickname\n");
    wprintw(self->window, "      accept <number>           : Accept friend request\n");
    wprintw(self->window, "      myid                      : Print your ID\n");
    wprintw(self->window, "      quit/exit                 : Exit program\n");
    wprintw(self->window, "      help                      : Print this message again\n");
    wprintw(self->window, "      clear                     : Clear this window\n");

    wattron(self->window, A_BOLD);
    wprintw(self->window, "TIP: Use the TAB key to navigate through the tabs.\n\n");
    wattroff(self->window, A_BOLD);

    wattroff(self->window, COLOR_PAIR(2));
}

void cmd_msg(ToxWindow *self, Messenger *m, char **args)
{
    char *id = args[1];
    char *msg = args[2];

    if (m_sendmessage(m, atoi(id), (uint8_t *) msg, strlen(msg) + 1) == 0)
        wprintw(self->window, "Error occurred while sending message.\n");
    else
        wprintw(self->window, "Message successfully sent.\n");
}

void cmd_myid(ToxWindow *self, Messenger *m, char **args)
{
    char id[FRIEND_ADDRESS_SIZE * 2 + 1] = {0};
    size_t i;
    uint8_t address[FRIEND_ADDRESS_SIZE];
    getaddress(m, address);

    for (i = 0; i < FRIEND_ADDRESS_SIZE; ++i) {
        char xx[3];
        snprintf(xx, sizeof(xx), "%02X", address[i] & 0xff);
        strcat(id, xx);
    }

    wprintw(self->window, "%s\n", id);
}

void cmd_nick(ToxWindow *self, Messenger *m, char **args)
{
    char *nick = args[1];
    setname(m, (uint8_t *) nick, strlen(nick) + 1);
    wprintw(self->window, "Nickname set to: %s\n", nick);

    if (store_data(m, DATA_FILE)) {
        wprintw(self->window, "\nCould not store Messenger data\n");
    }
}

void cmd_mynick(ToxWindow *self, Messenger *m, char **args)
{
    uint8_t *nick = malloc(m->name_length);
    getself_name(m, nick, m->name_length);
    wprintw(self->window, "Current nickname: %s\n", nick);
    free(nick);
}

void cmd_status(ToxWindow *self, Messenger *m, char **args)
{
    char *status = args[1];
    char *status_text;

    USERSTATUS status_kind;

    if (!strncmp(status, "online", strlen("online"))) {
        status_kind = USERSTATUS_NONE;
        status_text = "ONLINE";
    } else if (!strncmp(status, "away", strlen("away"))) {
        status_kind = USERSTATUS_AWAY;
        status_text = "AWAY";
    } else if (!strncmp(status, "busy", strlen("busy"))) {
        status_kind = USERSTATUS_BUSY;
        status_text = "BUSY";
    } else {
        wprintw(self->window, "Invalid status.\n");
        return;
    }

    char *msg = args[2];

    if (msg == NULL) {
        m_set_userstatus(m, status_kind);
        wprintw(self->window, "Status set to: %s\n", status_text);
    } else {
        m_set_userstatus(m, status_kind);
        m_set_statusmessage(m, (uint8_t *) msg, strlen(msg) + 1);
        wprintw(self->window, "Status set to: %s, %s\n", status_text, msg);
    }
}

void cmd_statusmsg(ToxWindow *self, Messenger *m, char **args)
{
    char *msg = args[1];
    m_set_statusmessage(m, (uint8_t *) msg, strlen(msg) + 1);
    wprintw(self->window, "Status set to: %s\n", msg);
}

static void execute(ToxWindow *self, Messenger *m, char *u_cmd)
{
    int newlines = 0;
    char cmd[MAX_STR_SIZE] = {0};
    int i;

    for (i = 0; i < strlen(prompt_buf); ++i) {
        if (u_cmd[i] == '\n')
            ++newlines;
        else
            cmd[i - newlines] = u_cmd[i];
    }

    int leading_spc = 0;

    for (i = 0; i < MAX_STR_SIZE && isspace(cmd[i]); ++i)
        leading_spc++;

    memmove(cmd, cmd + leading_spc, MAX_STR_SIZE - leading_spc);

    int cmd_end = strlen(cmd);

    while (cmd_end > 0 && cmd_end--)
        if (!isspace(cmd[cmd_end]))
            break;

    cmd[cmd_end + 1] = '\0';

    /* insert \0 at argument boundaries */
    int numargs = 0;

    for (i = 0; i < MAX_STR_SIZE; i++) {
        char quote_chr;
        if (cmd[i] == '\"' || cmd[i] == '\'') {
            quote_chr = cmd[i];
            while (cmd[++i] != quote_chr && i < MAX_STR_SIZE); /* skip over strings */
            /* Check if got qoute character */
            if (cmd[i] != quote_chr) {
                wprintw(self->window, "Missing terminating %c character\n", quote_chr);
                return;
            }
	}

        if (cmd[i] == ' ') {
            cmd[i] = '\0';

            int j = i;

            while (++j < MAX_STR_SIZE && isspace(cmd[j]));

            i = j - 1;

            numargs++;
        }
    }

    /* excessive arguments */
    if (numargs > 3) {
        wprintw(self->window, "Invalid command: too many arguments.\n");
        return;
    }

    /* read arguments into array */
    char *cmdargs[5];
    int pos = 0;

    for (i = 0; i < 5; i++) {
        cmdargs[i] = cmd + pos;
        pos += strlen(cmdargs[i]) + 1;

        while (isspace(cmd[pos]) && pos < MAX_STR_SIZE)
            ++pos;
    }

    /* no input */
    if (strlen(cmdargs[0]) == 0)
        return;

    /* match input to command list */
    for (i = 0; i < NUM_COMMANDS; i++) {
        if (!strcmp(cmdargs[0], commands[i].name)) {
            /* check for missing arguments */
            int j;

            for (j = 0; j <= commands[i].numargs; j++) {
                if (strlen(cmdargs[j]) == 0) {
                    wprintw(self->window, "Invalid command: %s expected %d arguments, got %d.\n",
                            commands[i].name, commands[i].numargs, j - 1);
                    return;
                }
            }

            /* check for excess arguments */
            if (strcmp(cmdargs[0], "add") && strlen(cmdargs[j]) != 0) {
                wprintw(self->window, "Invalid command: too many arguments to %s.\n", commands[i].name);
                return;
            }

            /* pass arguments to command function */
            (commands[i].func)(self, m, cmdargs);
            return;
        }
    }

    /* no match */
    wprintw(self->window, "Invalid command.\n");
}

static void prompt_onKey(ToxWindow *self, Messenger *m, int key)
{
    /* Add printable characters to line */
    if (isprint(key)) {
        if (prompt_buf_pos == (sizeof(prompt_buf) - 1)) {
            wprintw(self->window, "\nToo Long.\n");
            prompt_buf_pos = 0;
            prompt_buf[0] = 0;
        } else if (!(prompt_buf_pos == 0) && (prompt_buf_pos < COLS)
                   && (prompt_buf_pos % (COLS - 3) == 0)) {
            prompt_buf[prompt_buf_pos++] = '\n';
        } else if (!(prompt_buf_pos == 0) && (prompt_buf_pos > COLS)
                   && ((prompt_buf_pos - (COLS - 3)) % (COLS) == 0)) {
            prompt_buf[prompt_buf_pos++] = '\n';
        }

        prompt_buf[prompt_buf_pos++] = key;
        prompt_buf[prompt_buf_pos] = 0;
    }

    /* RETURN key: execute command */
    else if (key == '\n') {
        wprintw(self->window, "\n");
        execute(self, m, prompt_buf);
        prompt_buf_pos = 0;
        prompt_buf[0] = 0;
    }

    /* BACKSPACE key: Remove one character from line */
    else if (key == 0x107 || key == 0x8 || key == 0x7f) {
        if (prompt_buf_pos != 0) {
            prompt_buf[--prompt_buf_pos] = 0;
        }
    }
}

static void prompt_onDraw(ToxWindow *self, Messenger *m)
{
    curs_set(1);
    int x, y;
    getyx(self->window, y, x);
    (void) x;
    int i;

    for (i = 0; i < (strlen(prompt_buf)); ++i) {
        if ((prompt_buf[i] == '\n') && (y != 0))
            --y;
    }

    wattron(self->window, COLOR_PAIR(1));
    mvwprintw(self->window, y, 0, "# ");
    wattroff(self->window, COLOR_PAIR(1));
    mvwprintw(self->window, y, 2, "%s", prompt_buf);
    wclrtoeol(self->window);
    wrefresh(self->window);
}

static void prompt_onInit(ToxWindow *self, Messenger *m)
{
    scrollok(self->window, 1);
    cmd_help(self, m, NULL);
    wclrtoeol(self->window);
}

ToxWindow new_prompt()
{
    ToxWindow ret;
    memset(&ret, 0, sizeof(ret));
    ret.onKey = &prompt_onKey;
    ret.onDraw = &prompt_onDraw;
    ret.onInit = &prompt_onInit;
    strcpy(ret.title, "[prompt]");
    return ret;
}
