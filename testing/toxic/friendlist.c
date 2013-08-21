/*
 * Toxic -- Tox Curses Client
 */

#include <curses.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "../../core/Messenger.h"
#include "../../core/network.h"

#include "windows.h"
#include "friendlist.h"


typedef struct {
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t status[MAX_STATUSMESSAGE_LENGTH];
    int num;
    int chatwin;
} friend_t;

static friend_t friends[MAX_FRIENDS_NUM];
static int num_friends = 0;
static int num_selected = 0;

void fix_name(uint8_t *name)
{
    /* Remove all non alphanumeric characters */
    uint8_t *p = name;
    uint8_t *q = name;

    while (*p != 0) {
        if (isprint(*p))
            *q++ = *p;

        p++;
    }

    *q = 0;
}

void friendlist_onMessage(ToxWindow *self, Messenger *m, int num, uint8_t *str, uint16_t len)
{
    if (num >= num_friends)
        return;

    if (friends[num].chatwin == -1) {
        friends[num].chatwin = add_window(m, new_chat(m, num));
    }
}

void friendlist_onNickChange(ToxWindow *self, int num, uint8_t *str, uint16_t len)
{
    if (len >= MAX_NAME_LENGTH || num >= num_friends)
        return;

    memcpy((char *) &friends[num].name, (char *) str, len);
    friends[num].name[len] = 0;
    fix_name(friends[num].name);
}

void friendlist_onStatusChange(ToxWindow *self, int num, uint8_t *str, uint16_t len)
{
    if (len >= MAX_STATUSMESSAGE_LENGTH || num >= num_friends)
        return;

    memcpy((char *) &friends[num].status, (char *) str, len);
    friends[num].status[len] = 0;
    fix_name(friends[num].status);
}

int friendlist_onFriendAdded(Messenger *m, int num)
{
    if (num_friends == MAX_FRIENDS_NUM)
        return -1;

    friends[num_friends].num = num;
    getname(m, num, friends[num_friends].name);
    strcpy((char *) friends[num_friends].name, "unknown");
    strcpy((char *) friends[num_friends].status, "unknown");
    friends[num_friends++].chatwin = -1;
    return 0;
}

static void friendlist_onKey(ToxWindow *self, Messenger *m, int key)
{
    if (key == KEY_UP) {
        if (--num_selected < 0)
            num_selected = num_friends - 1;
    } else if (key == KEY_DOWN) {
        if (num_friends != 0)
            num_selected = (num_selected + 1) % num_friends;
    } else if (key == '\n') {
        /* Jump to chat window if already open */
        if (friends[num_selected].chatwin != -1) {
            set_active_window(friends[num_selected].chatwin);
        } else {
            friends[num_selected].chatwin = add_window(m, new_chat(m, num_selected));
        }
    }
}

static void friendlist_onDraw(ToxWindow *self, Messenger *m)
{
    curs_set(0);
    werase(self->window);

    if (num_friends == 0) {
        wprintw(self->window, "Empty. Add some friends! :-)\n");
    } else {
        wattron(self->window, COLOR_PAIR(2) | A_BOLD);
        wprintw(self->window, "Open chat with.. (up/down keys, enter)\n");
        wattroff(self->window, COLOR_PAIR(2) | A_BOLD);
    }

    wprintw(self->window, "\n");
    int i;

    for (i = 0; i < num_friends; ++i) {
        if (i == num_selected) wattron(self->window, COLOR_PAIR(3));

        wprintw(self->window, "  [#%d] ", friends[i].num);

        if (i == num_selected) wattroff(self->window, COLOR_PAIR(3));

        attron(A_BOLD);
        wprintw(self->window, "%s ", friends[i].name);
        attroff(A_BOLD);

        wprintw(self->window, "(%s)\n", friends[i].status);
    }

    wrefresh(self->window);
}

void disable_chatwin(int f_num)
{
    friends[f_num].chatwin = -1;
}

static void friendlist_onInit(ToxWindow *self, Messenger *m)
{

}

ToxWindow new_friendlist()
{
    ToxWindow ret;
    memset(&ret, 0, sizeof(ret));

    ret.onKey = &friendlist_onKey;
    ret.onDraw = &friendlist_onDraw;
    ret.onInit = &friendlist_onInit;
    ret.onMessage = &friendlist_onMessage;
    ret.onAction = &friendlist_onMessage;    // Action has identical behaviour to message
    ret.onNickChange = &friendlist_onNickChange;
    ret.onStatusChange = &friendlist_onStatusChange;

    strcpy(ret.title, "[friends]");
    return ret;
}
