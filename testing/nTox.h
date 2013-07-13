#ifndef NTOX_H
#define NTOX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <curses.h>
#include <ctype.h>
#include "../core/Messenger.h"
#define STRING_LENGTH 256
#define HISTORY 50

void new_lines(char *line);
void line_eval(char lines[HISTORY][STRING_LENGTH], char *line);
void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width) ;
int count_lines(char *string) ;
char *appender(char *str, const char c);
void do_refresh();

#endif
