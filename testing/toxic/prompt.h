#ifndef PROMPT_H_UZYGWFFL
#define PROMPT_H_UZYGWFFL

#include "windows.h"

typedef void (friendAddedFn)(Messenger *m, int friendnumber);

ToxWindow new_prompt(friendAddedFn *f);
int add_req(uint8_t *public_key);
unsigned char *hex_string_to_bin(char hex_string[]);

#endif /* end of include guard: PROMPT_H_UZYGWFFL */


