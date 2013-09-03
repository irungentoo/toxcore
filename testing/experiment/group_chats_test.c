#include "group_chats.h"
#define NUM_CHATS 8

int main()
{
    IP ip;
    ip.uint32 = 0;
    uint32_t i;
    Group_Chat *chats[NUM_CHATS];

    for (i = 0; i < NUM_CHATS; ++i) {
        chats[i] = new_groupchat(new_networking(ip, 1234));

        if (chats[i] == 0)
            exit(1);
    }

    return 0;
}
