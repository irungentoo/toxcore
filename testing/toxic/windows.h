/*
 * Toxic -- Tox Curses Client
 */

#include <stdbool.h>
#define TOXWINDOWS_MAX_NUM 32
#define MAX_FRIENDS_NUM 100
#define MAX_STR_SIZE 256
#define KEY_SIZE_BYTES 32

/* number of permanent default windows */
#define N_DEFAULT_WINS 2

/* maximum window slots for WINDOW_STATUS array */
#define MAX_WINDOW_SLOTS N_DEFAULT_WINS+MAX_FRIENDS_NUM

typedef struct ToxWindow_ ToxWindow;

struct ToxWindow_ {
  void(*onKey)(ToxWindow*, Messenger*, int);
  void(*onDraw)(ToxWindow*);
  void(*onInit)(ToxWindow*, Messenger*);
  void(*onFriendRequest)(ToxWindow*, uint8_t*, uint8_t*, uint16_t);
  void(*onMessage)(ToxWindow*, Messenger*, int, uint8_t*, uint16_t);
  void(*onNickChange)(ToxWindow*, int, uint8_t*, uint16_t);
  void(*onStatusChange)(ToxWindow*, int, uint8_t*, uint16_t);
  void(*onAction)(ToxWindow*, Messenger*, int, uint8_t*, uint16_t);
  char title[256];

  void* x;
  bool blink;

  WINDOW* window;
};
