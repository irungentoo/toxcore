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

  // quit/exit: Exit program.
  if(!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) {
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
      return;
    }

    ip++;

    port = strchr(ip, ' ');
    if(port == NULL) {
      return;
    }

    port[0] = 0;
    port++;

    key = strchr(port, ' ');
    if(key == NULL) {
      return;
    }

    key[0] = 0;
    key++;

    if(atoi(port) == 0) {
      return;
    }

    wprintw(self->window, "ip=%s, port=%s, key=%s\n", ip, port, key);

    dht.port = htons(atoi(port));

    int resolved_address = resolve_addr(ip);
    if (resolved_address == -1) {
      return;
    }

    dht.ip.i = resolved_address;
    DHT_bootstrap(dht, hex_string_to_bin(key));
  }
  else if(!strncmp(cmd, "add ", strlen("add "))) {
    char* id;
    char* msg;
    int num;

    id = strchr(cmd, ' ');

    if(id == NULL) {
      return;
    }

    id++;

    msg = strchr(id, ' ');
    if(msg == NULL) {
      return;
    }

    msg[0] = 0;
    msg++;

    num = m_addfriend((uint8_t*) id, (uint8_t*) msg, strlen(msg)+1);
    wprintw(self->window, "Friend added as %d.\n", num);
  }
  else if(!strncmp(cmd, "status ", strlen("status "))) {
    char* msg;

    msg = strchr(cmd, ' ');
    if(msg == NULL) {
      return;
    }

    msg++;
    m_set_userstatus((uint8_t*) msg, strlen(msg)+1);
    wprintw(self->window, "Status set to: %s.\n", msg);
  }
  else if(!strncmp(cmd, "nick ", strlen("nick "))) {
    char* nick;

    nick = strchr(cmd, ' ');
    if(nick == NULL) {
      return;
    }

    nick++;
    setname((uint8_t*) nick, strlen(nick)+1);
    wprintw(self->window, "Nickname set to: %s.\n", nick);
  }
  else if(!strcmp(cmd, "myid")) {
    // XXX: Clean this up
    char idstring0[200];
    char idstring1[32][5];
    char idstring2[32][5];
    uint32_t i;

    for(i = 0; i < 32; i++) {
      if(self_public_key[i] < 16)
	strcpy(idstring1[i], "0");
      else 
	strcpy(idstring1[i], "");

      sprintf(idstring2[i], "%hhX", self_public_key[i]);
    }
    
    for (i=0; i<32; i++) {
      strcat(idstring0, idstring1[i]);
      strcat(idstring0, idstring2[i]);
    }

    wprintw(self->window, "%s\n", idstring0);
  }
  else if(!strncmp(cmd, "accept ", strlen("accept "))) {
    char* id;
    int num;

    id = strchr(cmd, ' ');
    if(id == NULL) {
      return;
    }
    id++;
   
    num = atoi(id);
    if(num >= num_requests) {
      return;
    }

    num = m_addfriend_norequest(pending_requests[num]);
    wprintw(self->window, "Friend accepted as: %d.\n", num);
  }
  else if(!strncmp(cmd, "msg ", strlen("msg "))) {
    char* id;
    char* msg;

    id = strchr(cmd, ' ');

    if(id == NULL) {
      return;
    }

    id++;

    msg = strchr(id, ' ');
    if(msg == NULL) {
      return;
    }

    msg[0] = 0;
    msg++;

    if(m_sendmessage(atoi(id), (uint8_t*) msg, strlen(msg)+1) != 1) {
      wprintw(self->window, "Error occurred while sending message.\n");
    }
    else {
      wprintw(self->window, "Message successfully sent.\n");
    }
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
  else if(key == 0x107) {

    if(prompt_buf_pos != 0) {
      prompt_buf[--prompt_buf_pos] = 0;
    }
  }
}

static void prompt_onDraw(ToxWindow* self) {
  int x, y;

  mvwin(self->window,0,0);
  wresize(self->window, LINES-2, COLS);

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
  wprintw(self->window, "Usage:\n");
  wattroff(self->window, A_BOLD);
  
  wprintw(self->window, "      connect <ip> <port> <key> : Connect to DHT server\n");
  wprintw(self->window, "      add <id> <message>        : Add friend\n");
  wprintw(self->window, "      status <message>          : Set your status\n");
  wprintw(self->window, "      nick <nickname>           : Set your nickname\n");
  wprintw(self->window, "      accept <number>           : Accept friend request\n");
  wprintw(self->window, "      myid                      : Print your ID\n");
  wprintw(self->window, "      quit/exit                 : Exit program\n");
  wattroff(self->window, COLOR_PAIR(2));
}

static void prompt_onInit(ToxWindow* self) {
  scrollok(self->window, 1);

  print_usage(self);
  wclrtoeol(self->window);
}

ToxWindow new_prompt() {
  ToxWindow ret;

  ret.onKey = &prompt_onKey;
  ret.onDraw = &prompt_onDraw;
  ret.onInit = &prompt_onInit;
  strcpy(ret.title, "[prompt]");

  return ret;
}
