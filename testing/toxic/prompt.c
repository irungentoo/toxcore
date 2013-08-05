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

uint8_t pending_requests[256][CLIENT_ID_SIZE]; // XXX
uint8_t num_requests=0; // XXX

extern void on_friendadded(int friendnumber);
static void print_usage(ToxWindow* self);

// XXX:
int add_req(uint8_t* public_key) {
  memcpy(pending_requests[num_requests], public_key, CLIENT_ID_SIZE);
  ++num_requests;

  return num_requests-1;
}

// XXX: FIX
unsigned char * hex_string_to_bin(char hex_string[])
{
    size_t len = strlen(hex_string);
    unsigned char *val = malloc(len);
    char *pos = hex_string;
    int i;
    for(i = 0; i < len; ++i, pos+=2)
        sscanf(pos,"%2hhx",&val[i]);
    return val;
}

static char prompt_buf[256] = {0};
static int prompt_buf_pos=0;

static void execute(ToxWindow* self, char* cmd) {

  if(!strcmp(cmd, "quit") || !strcmp(cmd, "exit") || !strcmp(cmd, "q")) {
    endwin();
    exit(0);
  }
  else if(!strncmp(cmd, "connect ", strlen("connect "))) {
    char* ip;
    char* port;
    char* key;
    IP_Port dht;

    ip = strchr(cmd, ' ');
    if(ip == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    ip++;

    port = strchr(ip, ' ');
    if(port == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    port[0] = 0;
    port++;

    key = strchr(port, ' ');
    if(key == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    key[0] = 0;
    key++;

    if(atoi(port) == 0) {
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
    DHT_bootstrap(dht, binary_string);
    free(binary_string); 
  }
  else if(!strncmp(cmd, "add ", strlen("add "))) {
    uint8_t id_bin[32];
    size_t i;
    char xx[3];
    uint32_t x;

    char* id;
    char* msg;
    int num;

    id = strchr(cmd, ' ');
    if(id == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    id++;

    msg = strchr(id, ' ');
    if(msg != NULL) {
      msg[0] = 0;
      msg++;
    }
    else msg = "";

    if(strlen(id) != 2*32) {
      wprintw(self->window, "Invalid ID length.\n");
      return;
    }

    for(i=0; i<32; i++) {
      xx[0] = id[2*i];
      xx[1] = id[2*i+1];
      xx[2] = '\0';

      if(sscanf(xx, "%02x", &x) != 1) {
        wprintw(self->window, "Invalid ID.\n");
        return;
      }

      id_bin[i] = x;
    }

    num = m_addfriend(id_bin, (uint8_t*) msg, strlen(msg)+1);
    switch (num) {
    case -1: 
      wprintw(self->window, "Message is too long.\n");
      break;
    case -2:
      wprintw(self->window, "Please add a message to your request.\n");
      break;
    case -3:
      wprintw(self->window, "That appears to be your own ID.\n");
      break;
    case -4:
      wprintw(self->window, "Friend request already sent.\n");
      break;
    case -5:
      wprintw(self->window, "Undefined error when adding friend.\n");
      break; 
    default:
      wprintw(self->window, "Friend added as %d.\n", num);
      on_friendadded(num);
      break;
    }
  }
  else if(!strcmp(cmd, "clear")) { 
  	wclear(self->window);
  }
  else if(!strcmp(cmd, "help")) {
	  print_usage(self);
  }
  else if(!strncmp(cmd, "status ", strlen("status "))) {
    char* msg;

    msg = strchr(cmd, ' ');
    if(msg == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    msg++;

    m_set_userstatus((uint8_t*) msg, strlen(msg)+1);
    wprintw(self->window, "Status set to: %s\n", msg);
  }
  else if(!strncmp(cmd, "nick ", strlen("nick "))) {
    char* nick;

    nick = strchr(cmd, ' ');
    if(nick == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    nick++;

    setname((uint8_t*) nick, strlen(nick)+1);
    wprintw(self->window, "Nickname set to: %s\n", nick);
  }
  else if(!strcmp(cmd, "myid")) {
    char id[32*2 + 1] = {0};
    size_t i;

    for(i=0; i<32; i++) {
      char xx[3];
      snprintf(xx, sizeof(xx), "%02x",  self_public_key[i] & 0xff);
      strcat(id, xx);
    }
    
    wprintw(self->window, "Your ID: %s\n", id);
  }
  else if(!strncmp(cmd, "accept ", strlen("accept "))) {
    char* id;
    int num;

    id = strchr(cmd, ' ');
    if(id == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    id++;

    num = atoi(id);
    if(num >= num_requests) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }

    num = m_addfriend_norequest(pending_requests[num]);

    if(num == -1) {
      wprintw(self->window, "Failed to add friend.\n");
    }
    else {
      wprintw(self->window, "Friend accepted as: %d.\n", num);
      on_friendadded(num);
    }
  }
  else if(!strncmp(cmd, "msg ", strlen("msg "))) {
    char* id;
    char* msg;

    id = strchr(cmd, ' ');

    if(id == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    id++;

    msg = strchr(id, ' ');
    if(msg == NULL) {
      wprintw(self->window, "Invalid syntax.\n");
      return;
    }
    msg[0] = 0;
    msg++;

    if(m_sendmessage(atoi(id), (uint8_t*) msg, strlen(msg)+1) < 0) {
      wprintw(self->window, "Error occurred while sending message.\n");
    }
    else {
      wprintw(self->window, "Message successfully sent.\n");
    }
  }

  else {
    wprintw(self->window, "Invalid command.\n");
  }
}

static void prompt_onKey(ToxWindow* self, int key) {
  // PRINTABLE characters: Add to line.
  if(isprint(key)) {
    if(prompt_buf_pos == (sizeof(prompt_buf) - 1)) {
      return;
    }
    prompt_buf[prompt_buf_pos++] = key;
    prompt_buf[prompt_buf_pos] = 0;
  }

  // RETURN key: execute command.
  else if(key == '\n') {
    wprintw(self->window, "\n");
    execute(self, prompt_buf);
    prompt_buf_pos = 0;
    prompt_buf[0] = 0;
  }

  // BACKSPACE key: Remove one character from line.
  else if(key == 0x107 || key == 0x8 || key == 0x7f) {
    if(prompt_buf_pos != 0) {
      prompt_buf[--prompt_buf_pos] = 0;
    }
  }
}

static void prompt_onDraw(ToxWindow* self) {
  curs_set(1);
  int x, y;

  getyx(self->window, y, x);
  (void) x;

  wattron(self->window, COLOR_PAIR(1));
  mvwprintw(self->window, y, 0, "# ");
  wattroff(self->window, COLOR_PAIR(1));

  mvwprintw(self->window, y, 2, "%s", prompt_buf);
  wclrtoeol(self->window);

  wrefresh(self->window);
}

static void print_usage(ToxWindow* self) {
  wattron(self->window, COLOR_PAIR(2) | A_BOLD);
  wprintw(self->window, "Commands:\n");
  wattroff(self->window, A_BOLD);
  
  wprintw(self->window, "      connect <ip> <port> <key> : Connect to DHT server\n");
  wprintw(self->window, "      add <id> <message>        : Add friend\n");
  wprintw(self->window, "      status <message>          : Set your status\n");
  wprintw(self->window, "      nick <nickname>           : Set your nickname\n");
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

static void prompt_onInit(ToxWindow* self) {
  scrollok(self->window, 1);

  print_usage(self);
  wclrtoeol(self->window);
}

ToxWindow new_prompt() {
  ToxWindow ret;

  memset(&ret, 0, sizeof(ret));

  ret.onKey = &prompt_onKey;
  ret.onDraw = &prompt_onDraw;
  ret.onInit = &prompt_onInit;
  strcpy(ret.title, "[prompt]");

  return ret;
}
