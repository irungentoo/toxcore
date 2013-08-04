/*
 * Toxic -- Tox Curses Client
 */

#include <curses.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "../../core/messenger.h"
#include "../../core/network.h"

#include "windows.h"

extern int add_window(ToxWindow w);
extern int focus_window(int num);
extern ToxWindow new_chat(int friendnum);

#define MAX_FRIENDS_NUM 100

typedef struct {
  uint8_t name[MAX_NAME_LENGTH];
  uint8_t status[MAX_USERSTATUS_LENGTH];
  int     num;
  int     chatwin;
} friend_t;

static friend_t friends[MAX_FRIENDS_NUM];
static int num_friends = 0;
static int num_selected = 0;


void fix_name(uint8_t* name) {

  // Remove all non alphanumeric characters.
  uint8_t* p = name;
  uint8_t* q = name;

  while(*p != 0) {
    if(isprint(*p)) {
      *q++ = *p;
    }

    p++;
  }

  *q = 0;
}

void friendlist_onMessage(ToxWindow* self, int num, uint8_t* str, uint16_t len) {

  if(num >= num_friends)
    return;

  if(friends[num].chatwin == -1) {
    friends[num].chatwin = add_window(new_chat(num));
  }
}

void friendlist_onNickChange(ToxWindow* self, int num, uint8_t* str, uint16_t len) {

  if(len >= MAX_NAME_LENGTH || num >= num_friends)
    return;

  memcpy((char*) &friends[num].name, (char*) str, len);
  friends[num].name[len] = 0;
  fix_name(friends[num].name);
}

void friendlist_onStatusChange(ToxWindow* self, int num, uint8_t* str, uint16_t len) {

  if(len >= MAX_USERSTATUS_LENGTH || num >= num_friends)
    return;

  memcpy((char*) &friends[num].status, (char*) str, len);
  friends[num].status[len] = 0;
  fix_name(friends[num].status);
}

int friendlist_onFriendAdded(int num) {

  if(num_friends == MAX_FRIENDS_NUM)
    return -1;

  friends[num_friends].num = num;
  get_friend_name(num, friends[num_friends].name);
  strcpy((char*) friends[num_friends].name, "unknown");
  strcpy((char*) friends[num_friends].status, "unknown");
  friends[num_friends].chatwin = -1;

  num_friends++;
  return 0;
}

static void friendlist_onKey(ToxWindow* self, int key) {

  if(key == KEY_UP) {
    if(num_selected != 0)
      num_selected--;
  }
  else if(key == KEY_DOWN) {
    if(num_friends != 0)
      num_selected = (num_selected+1) % num_friends;
  }
  else if(key == '\n') {

    if(friends[num_selected].chatwin != -1)
      return;

    friends[num_selected].chatwin = add_window(new_chat(num_selected));
    focus_window(friends[num_selected].chatwin);
  }
}

static void friendlist_onDraw(ToxWindow* self) {
  size_t i;

  wclear(self->window);

  if(num_friends == 0) {
    wprintw(self->window, "Empty. Add some friends! :-)\n");
  }
  else {
    wattron(self->window, COLOR_PAIR(2) | A_BOLD);
    wprintw(self->window, "Open chat with.. (up/down keys, enter)\n");
    wattroff(self->window, COLOR_PAIR(2) | A_BOLD);
  }

  wprintw(self->window, "\n");

  for(i=0; i<num_friends; i++) {

    if(i == num_selected) wattron(self->window, COLOR_PAIR(3));
    wprintw(self->window, "  [#%d] ", friends[i].num);
    if(i == num_selected) wattroff(self->window, COLOR_PAIR(3));

    attron(A_BOLD);
    wprintw(self->window, "%s ", friends[i].name);
    attroff(A_BOLD);

    wprintw(self->window, "(%s)\n", friends[i].status);
  }

  wrefresh(self->window);
}

static void friendlist_onInit(ToxWindow* self) {

}


ToxWindow new_friendlist() {
  ToxWindow ret;

  memset(&ret, 0, sizeof(ret));

  ret.onKey = &friendlist_onKey;
  ret.onDraw = &friendlist_onDraw;
  ret.onInit = &friendlist_onInit;
  ret.onMessage = &friendlist_onMessage;
  ret.onNickChange = &friendlist_onNickChange;
  ret.onStatusChange = &friendlist_onStatusChange;
  strcpy(ret.title, "[friends]");

  return ret;
}
