typedef struct ToxWindow_ ToxWindow;

struct ToxWindow_ {
  void(*onKey)(ToxWindow*, int);
  void(*onDraw)(ToxWindow*);
  void(*onInit)(ToxWindow*);
  void(*onFriendRequest)(ToxWindow*, uint8_t*, uint8_t*, uint16_t);
  void(*onMessage)(ToxWindow*, int, uint8_t*, uint16_t);
  void(*onNickChange)(ToxWindow*, int, uint8_t*, uint16_t);
  void(*onStatusChange)(ToxWindow*, int, uint8_t*, uint16_t);
  char title[256];

  void* x;

  WINDOW* window;
};
