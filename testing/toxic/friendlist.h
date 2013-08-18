#ifndef FRIENDLIST_H_53I41IM
#define FRIENDLIST_H_53I41IM

#include "windows.h"
#include "chat.h"

ToxWindow new_friendlist();
int friendlist_onFriendAdded(Messenger *m, int num);
void disable_chatwin(int f_num);
void fix_name(uint8_t *name);

#endif /* end of include guard: FRIENDLIST_H_53I41IM */
