#ifndef CHAT_H_6489PZ13
#define CHAT_H_6489PZ13

typedef void (delWindowFn)(ToxWindow *w, int f_num);
ToxWindow new_chat(Messenger *m, int friendnum, delWindowFn f);

#endif /* end of include guard: CHAT_H_6489PZ13 */
