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

typedef struct {
  int friendnum;

  char line[256];
  size_t pos;

  WINDOW* history;
  WINDOW* linewin;

} ChatContext;

extern void fix_name(uint8_t* name);

static void chat_onMessage(ToxWindow* self, int num, uint8_t* msg, uint16_t len) {
  ChatContext* ctx = (ChatContext*) self->x;
  uint8_t nick[MAX_NAME_LENGTH] = {0};

  time_t now;
  time(&now);
  struct tm * timeinfo;
  timeinfo = localtime(&now);

  if(ctx->friendnum != num)
    return;

  getname(num, (uint8_t*) &nick);

  msg[len-1] = '\0';
  nick[MAX_NAME_LENGTH-1] = '\0';

  fix_name(msg);
  fix_name(nick);

  int inthour = timeinfo->tm_hour;
  int intmin = timeinfo->tm_min;
  char min[2];
  char hour[2];
  sprintf(hour,"%d",inthour);
  if (intmin < 10) {
    sprintf(min,"0%d",intmin);
  } else {
    sprintf(min,"%d",intmin);
  }


  wattron(ctx->history, COLOR_PAIR(2));
  wprintw(ctx->history,"%s",hour);
  wprintw(ctx->history,":%s  ",min);
  wattron(ctx->history, COLOR_PAIR(4));
  wprintw(ctx->history, "%s: ", nick);
  wattroff(ctx->history, COLOR_PAIR(4));
  wprintw(ctx->history, "%s\n", msg);

  self->blink = true;
}

static void chat_onNickChange(ToxWindow* self, int num, uint8_t* nick, uint16_t len) {
  ChatContext* ctx = (ChatContext*) self->x;

  if(ctx->friendnum != num)
    return;

  nick[len-1] = '\0';
  fix_name(nick);

  snprintf(self->title, sizeof(self->title), "[%s (%d)]", nick, num);

  wattron(ctx->history, COLOR_PAIR(3));
  wprintw(ctx->history, " * Your partner changed nick to '%s'\n", nick);
  wattroff(ctx->history, COLOR_PAIR(3));
}

static void chat_onStatusChange(ToxWindow* self, int num, uint8_t* status, uint16_t len) {

}

static void chat_onKey(ToxWindow* self, int key) {
  ChatContext* ctx = (ChatContext*) self->x;

  time_t now;
  time(&now);
  struct tm * timeinfo;
  timeinfo = localtime(&now);

  if(isprint(key)) {

    if(ctx->pos != sizeof(ctx->line)-1) {
      ctx->line[ctx->pos++] = key;
      ctx->line[ctx->pos] = '\0';
    }
  }
  else if(key == '\n') {

    int inthour = timeinfo->tm_hour; //Pretty bad, but it gets the job done
    int intmin = timeinfo->tm_min;
    char min[2];
    char hour[2];
    sprintf(hour,"%d",inthour);
    if (intmin < 10) {
      sprintf(min,"0%d",intmin);
    } else {
      sprintf(min,"%d",intmin);
    }
    wattron(ctx->history, COLOR_PAIR(2));
    wprintw(ctx->history,"%s",hour);
    wprintw(ctx->history,":%s  ",min);
    wattron(ctx->history, COLOR_PAIR(1));
    wprintw(ctx->history, "you: ", ctx->line);
    wattroff(ctx->history, COLOR_PAIR(1));

    wprintw(ctx->history, "%s\n", ctx->line);

    if(m_sendmessage(ctx->friendnum, (uint8_t*) ctx->line, strlen(ctx->line)+1) < 0) {
      wattron(ctx->history, COLOR_PAIR(3));
      wprintw(ctx->history, " * Failed to send message.\n");
      wattroff(ctx->history, COLOR_PAIR(3));
    }

    ctx->line[0] = '\0';
    ctx->pos = 0;
  }
  else if(key == 0x107 || key == 0x8 || key == 0x7f) {
    if(ctx->pos != 0) {
      ctx->line[--ctx->pos] = '\0';
    }
  }
  
}

static void chat_onDraw(ToxWindow* self) {
  curs_set(1);
  int x, y;
  ChatContext* ctx = (ChatContext*) self->x;

  getmaxyx(self->window, y, x);

  (void) x;
  if(y < 3)
    return;

  wclear(ctx->linewin);
  mvwhline(ctx->linewin, 0, 0, '_', COLS);
  mvwprintw(self->window, y-1, 0, "%s\n", ctx->line);

  wrefresh(self->window);
}

static void chat_onInit(ToxWindow* self) {
  int x, y;
  ChatContext* ctx = (ChatContext*) self->x;

  getmaxyx(self->window, y, x);

  ctx->history = subwin(self->window, y - 4, x, 0, 0);
  scrollok(ctx->history, 1);

  ctx->linewin = subwin(self->window, 2, x, y - 3, 0);
}

ToxWindow new_chat(int friendnum) {
  ToxWindow ret;

  memset(&ret, 0, sizeof(ret));

  ret.onKey = &chat_onKey;
  ret.onDraw = &chat_onDraw;
  ret.onInit = &chat_onInit;
  ret.onMessage = &chat_onMessage;
  ret.onNickChange = &chat_onNickChange;
  ret.onStatusChange = &chat_onStatusChange;

  uint8_t nick[MAX_NAME_LENGTH] = {0};
  getname(friendnum, (uint8_t*) &nick);
  fix_name(nick);
  
  snprintf(ret.title, sizeof(ret.title), "[%s (%d)]", nick, friendnum);

  ChatContext* x = calloc(1, sizeof(ChatContext));
  x->friendnum = friendnum;

  ret.x = (void*) x;

  return ret;
}
