/*
 * Toxic -- Tox Curses Client
 */

#include <curses.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef _win32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "../../core/Messenger.h"
#include "../../core/network.h"

#include "configdir.h"
#include "windows.h"
#include "prompt.h"
#include "friendlist.h"


static void init_term()
{
  /* Setup terminal */
  initscr();
  cbreak();
  keypad(stdscr, 1);
  noecho();
  timeout(100);

  if (has_colors()) {
    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_CYAN, COLOR_BLACK);
    init_pair(3, COLOR_RED, COLOR_BLACK);
    init_pair(4, COLOR_BLUE, COLOR_BLACK);
    init_pair(5, COLOR_YELLOW, COLOR_BLACK);
  }
  refresh();
}

static Messenger *init_tox()
{
  /* Init core */
  Messenger *m = initMessenger();

  /* Callbacks */
  m_callback_friendrequest(m, on_request, NULL);
  m_callback_friendmessage(m, on_message, NULL);
  m_callback_namechange(m, on_nickchange, NULL);
  m_callback_statusmessage(m, on_statuschange, NULL);
  m_callback_action(m, on_action, NULL);
#ifdef __linux__
  setname(m, (uint8_t*) "Cool guy", sizeof("Cool guy"));
#elif WIN32
  setname(m, (uint8_t*) "I should install GNU/Linux", sizeof("I should install GNU/Linux"));
#else
  setname(m, (uint8_t*) "Hipster", sizeof("Hipster"));
#endif
  return m;
}

#define MAXLINE 90    /* Approx max number of chars in a sever line (IP + port + key) */
#define MINLINE 70
#define MAXSERVERS 50

/* Connects to a random DHT server listed in the DHTservers file */
int init_connection(void)
{
  if (DHT_isconnected())
    return 0;

  FILE *fp = fopen("../../../other/DHTservers", "r");
  if (!fp)
    return 1;

  char servers[MAXSERVERS][MAXLINE];
  char line[MAXLINE];
  int linecnt = 0;
  while (fgets(line, sizeof(line), fp) && linecnt < MAXSERVERS) {
    if (strlen(line) > MINLINE)
      strcpy(servers[linecnt++], line);
  }
  if (linecnt < 1) {
    fclose(fp);
    return 2;
  }
  fclose(fp);

  char *server = servers[rand() % linecnt];
  char *ip = strtok(server, " ");
  char *port = strtok(NULL, " ");
  char *key = strtok(NULL, " ");
  if (!ip || !port || !key)
    return 3;

  IP_Port dht;
  dht.port = htons(atoi(port));
  uint32_t resolved_address = resolve_addr(ip);
  if (resolved_address == 0)
    return 0;
  dht.ip.i = resolved_address;
  unsigned char *binary_string = hex_string_to_bin(key);
  DHT_bootstrap(dht, binary_string);
  free(binary_string);
  return 0;
}

static void do_tox(Messenger *m, ToxWindow * prompt)
{
  static int conn_try = 0;
  static int conn_err = 0;
  static bool dht_on = false;
  if (!dht_on && !DHT_isconnected() && !(conn_try++ % 100)) {
    if (!conn_err) {
      conn_err = init_connection();
      wprintw(prompt->window, "\nEstablishing connection...\n");
      if (conn_err)
	wprintw(prompt->window, "\nAuto-connect failed with error code %d\n", conn_err);
    }
  }
  else if (!dht_on && DHT_isconnected()) {
    dht_on = true;
    wprintw(prompt->window, "\nDHT connected.\n");
  }
  else if (dht_on && !DHT_isconnected()) {
    dht_on = false;
    wprintw(prompt->window, "\nDHT disconnected. Attempting to reconnect.\n");
  }
  doMessenger(m);
}

static void load_data(Messenger *m, char *path)
{
  FILE *fd;
  size_t len;
  uint8_t *buf;

  if ((fd = fopen(path, "r")) != NULL) {
    fseek(fd, 0, SEEK_END);
    len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    buf = malloc(len);
    if (buf == NULL) {
      fprintf(stderr, "malloc() failed.\n");
      fclose(fd);
      endwin();
      exit(1);
    }
    if (fread(buf, len, 1, fd) != 1){
      fprintf(stderr, "fread() failed.\n");
      free(buf);
      fclose(fd);
      endwin();
      exit(1);
    }
    Messenger_load(m, buf, len);
  }
  else {
    len = Messenger_size(m);
    buf = malloc(len);
    if (buf == NULL) {
      fprintf(stderr, "malloc() failed.\n");
      endwin();
      exit(1);
    }
    Messenger_save(m, buf);

    fd = fopen(path, "w");
    if (fd == NULL) {
      fprintf(stderr, "fopen() failed.\n");
      free(buf);
      endwin();
      exit(1);
    }

    if (fwrite(buf, len, 1, fd) != 1){
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

int main(int argc, char *argv[])
{
  char *user_config_dir = get_user_config_dir();
  char *DATA_FILE = NULL;
  int config_err = 0;

  int f_loadfromfile = 1;
  int f_flag = 0;
  int i = 0;
  for (i = 0; i < argc; ++i) {
    if (argv[i] == NULL)
      break;
    else if (argv[i][0] == '-') {
      if (argv[i][1] == 'f') {
        if (argv[i + 1] != NULL)
          DATA_FILE = strdup(argv[i + 1]);
        else
          f_flag = -1;
      } else if (argv[i][1] == 'n') {
          f_loadfromfile = 0;
      }
    }
  }

  if (DATA_FILE == NULL ) {
    config_err = create_user_config_dir(user_config_dir);
    if (config_err) {
      DATA_FILE = strdup("data");
    } else {
      DATA_FILE = malloc(strlen(user_config_dir) + strlen(CONFIGDIR) + strlen("data") + 1);
      strcpy(DATA_FILE, user_config_dir);
      strcat(DATA_FILE, CONFIGDIR);
      strcat(DATA_FILE, "data");
    }
  }
  free(user_config_dir);

  init_term();
  Messenger *m = init_tox();
  ToxWindow *prompt = init_windows(m);
  init_window_status();

  if(f_loadfromfile)
    load_data(m, DATA_FILE);
  free(DATA_FILE);

  if (f_flag == -1) {
    attron(COLOR_PAIR(3) | A_BOLD);
    wprintw(prompt->window, "You passed '-f' without giving an argument.\n"
                            "defaulting to 'data' for a keyfile...\n");
    attroff(COLOR_PAIR(3) | A_BOLD);
  }

  if(config_err) {
    attron(COLOR_PAIR(3) | A_BOLD);
    wprintw(prompt->window, "Unable to determine configuration directory.\n"
                            "defaulting to 'data' for a keyfile...\n");
    attroff(COLOR_PAIR(3) | A_BOLD);
  }
  while(true) {
    /* Update tox */
    do_tox(m, prompt);

    /* Draw */
    draw_active_window(m);
  }
  cleanupMessenger(m);
  return 0;
}
