typedef struct ToxWindow_ ToxWindow;

struct ToxWindow_ {
  void(*onKey)(ToxWindow*, int);
  void(*onDraw)(ToxWindow*);
  void(*onInit)(ToxWindow*);
  char title[256];

  WINDOW* window;
};
