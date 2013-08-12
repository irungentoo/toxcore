#ifndef FRIENDLIST_H_53I41IM
#define FRIENDLIST_H_53I41IM


#include "windows.h"
#include "chat.h"
typedef void (setActiveWindowFn)(int ch);
typedef int (addWindowFn)(Messenger *m, ToxWindow w, int n);
ToxWindow new_friendlist(delWindowFn dw, setActiveWindowFn saw, addWindowFn aw,  char * ws);
int friendlist_onFriendAdded(Messenger *m, int num);
void disable_chatwin(int f_num);
void fix_name(uint8_t *name);

#endif /* end of include guard: FRIENDLIST_H_53I41IM */
