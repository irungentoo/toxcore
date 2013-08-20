/*
 * Toxic -- Tox Curses Client
 */

#include <curses.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#include "../../core/Messenger.h"
#include "../../core/network.h"

#include "windows.h"
#include "friendlist.h"
#include "chat.h"

#define CURS_Y_OFFSET 3

typedef struct {
    int friendnum;
    char line[MAX_STR_SIZE];
    size_t pos;
    WINDOW *history;
    WINDOW *linewin;
} ChatContext;

void print_help(ChatContext *self);
void execute(ToxWindow *self, ChatContext *ctx, Messenger *m, char *cmd);

struct tm *get_time(void)
{
    struct tm *timeinfo;
    time_t now;
    time(&now);
    timeinfo = localtime(&now);
    return timeinfo;
}

static void chat_onMessage(ToxWindow *self, Messenger *m, int num, uint8_t *msg, uint16_t len)
{
    ChatContext *ctx = (ChatContext *) self->x;
    uint8_t nick[MAX_NAME_LENGTH] = {0};
    struct tm *timeinfo = get_time();

    if (ctx->friendnum != num)
        return;

    getname(m, num, (uint8_t *) &nick);
    msg[len - 1] = '\0';
    nick[MAX_NAME_LENGTH - 1] = '\0';
    fix_name(msg);
    fix_name(nick);

    wattron(ctx->history, COLOR_PAIR(2));
    wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    wattroff(ctx->history, COLOR_PAIR(2));
    wattron(ctx->history, COLOR_PAIR(4));
    wprintw(ctx->history, "%s: ", nick);
    wattroff(ctx->history, COLOR_PAIR(4));
    wprintw(ctx->history, "%s\n", msg);

    self->blink = true;
    beep();
}

static void chat_onAction(ToxWindow *self, Messenger *m, int num, uint8_t *action, uint16_t len)
{
    ChatContext *ctx = (ChatContext *) self->x;
    struct tm *timeinfo = get_time();

    if (ctx->friendnum != num)
        return;

    action[len - 1] = '\0';
    fix_name(action);

    wattron(ctx->history, COLOR_PAIR(2));
    wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    wattroff(ctx->history, COLOR_PAIR(2));

    wattron(ctx->history, COLOR_PAIR(5));
    wprintw(ctx->history, "%s\n", action);
    wattroff(ctx->history, COLOR_PAIR(5));

    self->blink = true;
    beep();
}

static void chat_onNickChange(ToxWindow *self, int num, uint8_t *nick, uint16_t len)
{
    ChatContext *ctx = (ChatContext *) self->x;
    struct tm *timeinfo = get_time();

    if (ctx->friendnum != num)
        return;

    wattron(ctx->history, COLOR_PAIR(2));
    wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    wattroff(ctx->history, COLOR_PAIR(2));

    nick[len - 1] = '\0';
    fix_name(nick);
    snprintf(self->title, sizeof(self->title), "[%s (%d)]", nick, num);

    wattron(ctx->history, COLOR_PAIR(3));
    wprintw(ctx->history, "* Your partner changed nick to '%s'\n", nick);
    wattroff(ctx->history, COLOR_PAIR(3));
}

static void chat_onStatusChange(ToxWindow *self, int num, uint8_t *status, uint16_t len)
{
    ChatContext *ctx = (ChatContext *) self->x;
    struct tm *timeinfo = get_time();

    if (ctx->friendnum != num)
        return;

    wattron(ctx->history, COLOR_PAIR(2));
    wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    wattroff(ctx->history, COLOR_PAIR(2));

    status[len - 1] = '\0';
    fix_name(status);
    
    wattron(ctx->history, COLOR_PAIR(3));
    wprintw(ctx->history, "* Your partner changed status to '%s'\n", status);
    wattroff(ctx->history, COLOR_PAIR(3));

}

/* check that the string has one non-space character */
int string_is_empty(char *string)
{
    int rc = 0;
    char *copy = strdup(string);
    rc = ((strtok(copy, " ") == NULL) ? 1 : 0);
    free(copy);
    return rc;
}

static void chat_onKey(ToxWindow *self, Messenger *m, int key)
{
    ChatContext *ctx = (ChatContext *) self->x;
    struct tm *timeinfo = get_time();

    int x, y, y2, x2;
    getyx(self->window, y, x);
    getmaxyx(self->window, y2, x2);

    /* Add printable chars to buffer and print on input space */
    if (isprint(key)) {
        if (ctx->pos != sizeof(ctx->line) - 1) {
            mvwaddch(self->window, y, x, key);
            ctx->line[ctx->pos++] = key;
            ctx->line[ctx->pos] = '\0';
        }
    }

    /* BACKSPACE key: Remove one character from line */
    else if (key == 0x107 || key == 0x8 || key == 0x7f) {
        if (ctx->pos > 0) {
            ctx->line[--ctx->pos] = '\0';

            if (x == 0)
                mvwdelch(self->window, y - 1, x2 - 1);
            else
                mvwdelch(self->window, y, x - 1);
        }
    }

    /* RETURN key: Execute command or print line */
    else if (key == '\n') {
        wclear(ctx->linewin);
        wmove(self->window, y2 - CURS_Y_OFFSET, 0);
        wclrtobot(self->window);

        if (ctx->line[0] == '/')
            execute(self, ctx, m, ctx->line);
        else {
            /* make sure the string has at least non-space character */
            if (!string_is_empty(ctx->line)) {
                uint8_t selfname[MAX_NAME_LENGTH];
                getself_name(m, selfname, sizeof(selfname));
                fix_name(selfname);

                wattron(ctx->history, COLOR_PAIR(2));
                wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
                wattroff(ctx->history, COLOR_PAIR(2));
                wattron(ctx->history, COLOR_PAIR(1));
                wprintw(ctx->history, "%s: ", selfname);
                wattroff(ctx->history, COLOR_PAIR(1));
                wprintw(ctx->history, "%s\n", ctx->line);

                if (m_sendmessage(m, ctx->friendnum, (uint8_t *) ctx->line, strlen(ctx->line) + 1) == 0) {
                    wattron(ctx->history, COLOR_PAIR(3));
                    wprintw(ctx->history, " * Failed to send message.\n");
                    wattroff(ctx->history, COLOR_PAIR(3));
                }
            }
        }

        ctx->line[0] = '\0';
        ctx->pos = 0;
    }
}

void execute(ToxWindow *self, ChatContext *ctx, Messenger *m, char *cmd)
{
    if (!strcmp(cmd, "/clear") || !strcmp(cmd, "/c")) {
        wclear(self->window);
        wclear(ctx->history);
        int x, y;
        getmaxyx(self->window, y, x);
        (void) x;
        wmove(self->window, y - CURS_Y_OFFSET, 0);
    }

    else if (!strcmp(cmd, "/help") || !strcmp(cmd, "/h"))
        print_help(ctx);

    else if (!strcmp(cmd, "/quit") || !strcmp(cmd, "/exit") || !strcmp(cmd, "/q")) {
        endwin();
        exit(0);
    }

    else if (!strncmp(cmd, "/me ", strlen("/me "))) {
        struct tm *timeinfo = get_time();
        char *action = strchr(cmd, ' ');

        if (action == NULL) {
            wprintw(self->window, "Invalid syntax.\n");
            return;
        }

        action++;

        wattron(ctx->history, COLOR_PAIR(2));
        wprintw(ctx->history, "[%02d:%02d:%02d] ", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
        wattroff(ctx->history, COLOR_PAIR(2));

        uint8_t selfname[MAX_NAME_LENGTH];
        int len = getself_name(m, selfname, sizeof(selfname));
        char msg[MAX_STR_SIZE - len - 4];
        snprintf(msg, sizeof(msg), "* %s %s\n", (uint8_t *) selfname, action);

        wattron(ctx->history, COLOR_PAIR(5));
        wprintw(ctx->history, msg);
        wattroff(ctx->history, COLOR_PAIR(5));

        if (m_sendaction(m, ctx->friendnum, (uint8_t *) msg, strlen(msg) + 1) < 0) {
            wattron(ctx->history, COLOR_PAIR(3));
            wprintw(ctx->history, " * Failed to send action\n");
            wattroff(ctx->history, COLOR_PAIR(3));
        }
    }

    else if (!strncmp(cmd, "/status ", strlen("/status "))) {
        char *status = strchr(cmd, ' ');
        char *msg;
        char *status_text;

        if (status == NULL) {
            wprintw(ctx->history, "Invalid syntax.\n");
            return;
        }

        status++;
        USERSTATUS status_kind;

        if (!strncmp(status, "online", strlen("online"))) {
            status_kind = USERSTATUS_NONE;
            status_text = "ONLINE";
        }

        else if (!strncmp(status, "away", strlen("away"))) {
            status_kind = USERSTATUS_AWAY;
            status_text = "AWAY";
        }

        else if (!strncmp(status, "busy", strlen("busy"))) {
            status_kind = USERSTATUS_BUSY;
            status_text = "BUSY";
        }

        else {
            wprintw(ctx->history, "Invalid status.\n");
            return;
        }

        msg = strchr(status, ' ');

        if (msg == NULL) {
            m_set_userstatus(m, status_kind);
            wprintw(ctx->history, "Status set to: %s\n", status_text);
        } else {
            msg++;
            m_set_userstatus(m, status_kind);
            m_set_statusmessage(m, ( uint8_t *) msg, strlen(msg) + 1);
            wprintw(ctx->history, "Status set to: %s, %s\n", status_text, msg);
        }
    }

    else if (!strncmp(cmd, "/nick ", strlen("/nick "))) {
        char *nick;
        nick = strchr(cmd, ' ');

        if (nick == NULL) {
            wprintw(ctx->history, "Invalid syntax.\n");
            return;
        }

        nick++;
        setname(m, (uint8_t *) nick, strlen(nick) + 1);
        wprintw(ctx->history, "Nickname set to: %s\n", nick);
    }

    else if (!strcmp(cmd, "/myid")) {
        char id[FRIEND_ADDRESS_SIZE * 2 + 1] = {0};
        int i;
        uint8_t address[FRIEND_ADDRESS_SIZE];
        getaddress(m, address);

        for (i = 0; i < FRIEND_ADDRESS_SIZE; i++) {
            char xx[3];
            snprintf(xx, sizeof(xx), "%02X",  address[i] & 0xff);
            strcat(id, xx);
        }

        wprintw(ctx->history, "%s\n", id);
    }

    else if (strcmp(ctx->line, "/close") == 0) {
        int f_num = ctx->friendnum;
        delwin(ctx->linewin);
        del_window(self);
        disable_chatwin(f_num);
    }

    else
        wprintw(ctx->history, "Invalid command.\n");
}

static void chat_onDraw(ToxWindow *self, Messenger *m)
{
    curs_set(1);
    int x, y;
    getmaxyx(self->window, y, x);
    (void) y;
    ChatContext *ctx = (ChatContext *) self->x;
    mvwhline(ctx->linewin, 0, 0, '_', x);
    wrefresh(self->window);
}

static void chat_onInit(ToxWindow *self, Messenger *m)
{
    int x, y;
    ChatContext *ctx = (ChatContext *) self->x;
    getmaxyx(self->window, y, x);
    ctx->history = subwin(self->window, y - 4, x, 0, 0);
    scrollok(ctx->history, 1);
    ctx->linewin = subwin(self->window, 2, x, y - 4, 0);
    print_help(ctx);
    wmove(self->window, y - CURS_Y_OFFSET, 0);
}

void print_help(ChatContext *self)
{
    wattron(self->history, COLOR_PAIR(2) | A_BOLD);
    wprintw(self->history, "Commands:\n");
    wattroff(self->history, A_BOLD);

    wprintw(self->history, "      /status <type> <message>   : Set your status\n");
    wprintw(self->history, "      /nick <nickname>           : Set your nickname\n");
    wprintw(self->history, "      /me <action>               : Do an action\n");
    wprintw(self->history, "      /myid                      : Print your ID\n");
    wprintw(self->history, "      /clear                     : Clear the screen\n");
    wprintw(self->history, "      /close                     : Close the current chat window\n");
    wprintw(self->history, "      /quit or /exit             : Exit program\n");
    wprintw(self->history, "      /help                      : Print this message again\n\n");

    wattroff(self->history, COLOR_PAIR(2));
}

ToxWindow new_chat(Messenger *m, int friendnum)
{
    ToxWindow ret;
    memset(&ret, 0, sizeof(ret));

    ret.onKey = &chat_onKey;
    ret.onDraw = &chat_onDraw;
    ret.onInit = &chat_onInit;
    ret.onMessage = &chat_onMessage;
    ret.onNickChange = &chat_onNickChange;
    ret.onStatusChange = &chat_onStatusChange;
    ret.onAction = &chat_onAction;

    uint8_t nick[MAX_NAME_LENGTH] = {0};
    getname(m, friendnum, (uint8_t *) &nick);
    fix_name(nick);

    snprintf(ret.title, sizeof(ret.title), "[%s (%d)]", nick, friendnum);

    ChatContext *x = calloc(1, sizeof(ChatContext));
    x->friendnum = friendnum;
    ret.x = (void *) x;
    return ret;
}
