/*
 * Toxic -- Tox Curses Client
 */

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../core/Messenger.h"
#include "../../core/network.h"

#include "windows.h"

extern ToxWindow new_prompt();
extern ToxWindow new_friendlist();

extern int friendlist_addfriend(int num);
extern int friendlist_nickchange(int num, uint8_t* str, uint16_t len);
extern int friendlist_statuschange(int num, uint8_t* str, uint16_t len);

extern int add_req(uint8_t* public_key); // XXX

#define TOXWINDOWS_MAX_NUM 32

static ToxWindow windows[TOXWINDOWS_MAX_NUM];
static int w_num;
static int w_active;
static ToxWindow* prompt;

// CALLBACKS START
void on_request(uint8_t* public_key, uint8_t* data, uint16_t length) {
  int n = add_req(public_key);

  wprintw(prompt->window, "\nFriend request.\nUse \"accept %d\" to accept it.\n", n);
}

void on_message(int friendnumber, uint8_t* string, uint16_t length) {
  wprintw(prompt->window, "\n(message) %d: %s!\n", friendnumber, string);
}

void on_nickchange(int friendnumber, uint8_t* string, uint16_t length) {
  wprintw(prompt->window, "\n(nickchange) %d: %s!\n", friendnumber, string);

  friendlist_nickchange(friendnumber, string, length);
}

void on_statuschange(int friendnumber, uint8_t* string, uint16_t length) {
  wprintw(prompt->window, "\n(statuschange) %d: %s!\n", friendnumber, string);

  friendlist_statuschange(friendnumber, string, length);
}

void on_friendadded(int friendnumber) {
  friendlist_addfriend(friendnumber);
}
// CALLBACKS END

static void init_term() {
  // Setup terminal.
  initscr();
  cbreak();
  keypad(stdscr, 1);
  noecho();
  timeout(2000);

  if(has_colors()) {
    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_CYAN, COLOR_BLACK);
    init_pair(3, COLOR_RED, COLOR_BLACK);
    init_pair(4, COLOR_BLUE, COLOR_BLACK);
  }

  refresh();
}

static void init_tox() {
  // Init core.
  initMessenger();

  // Callbacks.
  m_callback_friendrequest(on_request);
  m_callback_friendmessage(on_message);
  m_callback_namechange(on_nickchange);
  m_callback_userstatus(on_statuschange);
}

static int add_window(ToxWindow w) {
  if(w_num == TOXWINDOWS_MAX_NUM)
    return -1;

  if(LINES < 2)
    return -1;

  w.window = newwin(LINES - 2, COLS, 0, 0);

  if(w.window == NULL)
    return -1;

  windows[w_num++] = w;
  w.onInit(&w);

  return w_num;
}

static void init_windows() {
  w_num = 0;
  w_active = 0;

  if(add_window(new_prompt()) == -1 || add_window(new_friendlist()) == -1) {
    fprintf(stderr, "add_window() failed.\n");

    endwin();
    exit(1);
  }

  prompt = &windows[0];
}

static void do_tox() {
  static bool dht_on = false;

  if(!dht_on && DHT_isconnected()) {
    dht_on = true;
    wprintw(prompt->window, "\nDHT connected!\n");
  }
  else if(dht_on && !DHT_isconnected()) {
    dht_on = false;
    wprintw(prompt->window, "\nDHT disconnected!\n");
  }

  doMessenger();
}

static void load_data() {
  FILE* fd;
  size_t len;
  uint8_t* buf;

  if((fd = fopen("data", "r")) != NULL) {
    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    buf = malloc(len);

    if(buf == NULL) {
      fprintf(stderr, "malloc() failed.\n");

      fclose(fd);
      endwin();
      exit(1);
    }

    if(fread(buf, len, 1, fd) != 1){
      fprintf(stderr, "fread() failed.\n");

      free(buf);
      fclose(fd);
      endwin();
      exit(1);
    }

    Messenger_load(buf, len);
  }
  else { 
    len = Messenger_size();
    buf = malloc(len);

    if(buf == NULL) {
      fprintf(stderr, "malloc() failed.\n");
      endwin();
      exit(1);
    }

    Messenger_save(buf);

    fd = fopen("data", "w");
    if(fd == NULL) {
      fprintf(stderr, "fopen() failed.\n");

      free(buf);
      endwin();
      exit(1);
    }

    if(fwrite(buf, len, 1, fd) != 1){
      fprintf(stderr, "fwrite() failed.\n");

      free(buf);
      fclose(fd);
      endwin();
      exit(1);
    }
  }

  free(buf);
  fclose(fd);
}

static void draw_bar() {
  size_t i;

  attron(COLOR_PAIR(4));
  mvhline(LINES - 2, 0, '_', COLS);
  attroff(COLOR_PAIR(4));

  move(LINES - 1, 0);

  attron(COLOR_PAIR(3) | A_BOLD);
  printw(" TOXIC 1.0 |");
  attroff(COLOR_PAIR(3) | A_BOLD);

  for(i=0; i<w_num; i++) {
    if(i == w_active) {
      attron(A_BOLD);
    }

    printw(" %s", windows[i].title);

    if(i == w_active) {
      attroff(A_BOLD);
    }
  }

  refresh();
}

void prepare_window(WINDOW* w) {
  mvwin(w, 0, 0);
  wresize(w, LINES-2, COLS);
}

int main(int argc, char* argv[]) {
  int ch;
  ToxWindow* a;

  init_term();
  init_tox();
  load_data();
  init_windows();

  while(true) {
    // Update tox.
    do_tox();

    // Draw.
    a = &windows[w_active];
    prepare_window(a->window);
    a->onDraw(a);
    draw_bar();

    // Handle input.
    ch = getch();
    if(ch == '\t') {
      w_active = (w_active + 1) % w_num;
    }
    else if(ch != ERR) {
      a->onKey(a, ch);
    }

  }

  return 0;
}

