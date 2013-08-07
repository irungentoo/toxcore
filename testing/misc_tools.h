/* misc_tools.h
 * 
 * Miscellaneous functions and data structures for doing random things.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *  
 */
 
#ifndef MISC_TOOLS_H
#define MISC_TOOLS_H

unsigned char * hex_string_to_bin(char hex_string[]);

/* WARNING(msg) takes a printf()-styled string and prints it
 * with some additional details.
 * ERROR(exit_status, msg) does the same thing as WARNING(), but
 * also exits the program with the given exit status.
 * Examples:
 * WARNING("<insert warning message here>");
 * int exit_status = 2;
 * ERROR(exit_status, "exiting with status %i", exit_status);
 */
#ifdef DEBUG
    #include <assert.h>
    #include <stdio.h>
    #include <string.h>

    #define DEBUG_PRINT(str, ...) do { \
        char msg[1000]; \
        sprintf(msg, "%s(): line %d (file %s): %s%%c\n", __FUNCTION__, __LINE__, __FILE__, str); \
        fprintf(stderr, msg, __VA_ARGS__); \
    } while (0)

    #define WARNING(...) do { \
        fprintf(stderr, "warning in "); \
        DEBUG_PRINT(__VA_ARGS__, ' '); \
    } while (0)

	#undef ERROR
    #define ERROR(exit_status, ...) do { \
        fprintf(stderr, "error in "); \
        DEBUG_PRINT(__VA_ARGS__, ' '); \
        exit(exit_status); \
    } while (0)
#else
    #define WARNING(...)
    #undef ERROR
    #define ERROR(...)
#endif // DEBUG

/************************Linked List***********************
 * This is a simple linked list implementation, very similar
 * to Linux kernel's /include/linux/list.h (which we can't 
 * use because Tox is GPLv3 and Linux is GPLv2.)
 *
 * TODO: Make the lists easier to use with some sweat pre-
 * processor syntactic sugar.
 **********************************************************/

/* Example usage

This sample program makes a new struct which contains a
character and a tox_list_t. It then prompts a user for
input until he enters q or e. It then adds each character
to the list, and uses a special for loop to print them.
It then removes all the 'z' characters, and prints the list
again.

//Notice that the data to be put in the list *contains* tox_list_t;
//usually, this is the other way around!
typedef struct tox_string {
   char c;
   tox_list_t tox_lst; //Notice that tox_lst is *NOT* a pointer.
} tox_string_t;

int main()
{
   tox_list_t head;
   tox_list_new(&head); //initialize head
   
   //input a new character, until user enters q or e
   char c = '\0';
   while (c != 'q' && c != 'e') {
      scanf("%c", &c);
      tox_string_t* tmp = malloc(sizeof(tox_string_t));
      tmp->c = c;
      tox_list_add(&head, &tmp->tox_lst); //add it to the list
   }
   
TOX_LIST_FOR_EACH() takes a struct tox_list and a name for a temporary pointer to use in the loop.
   
TOX_LIST_GET_VALUE() uses magic to return an instance of a structure that contains tox_list_t.
You have to give it a temporary tox_string_t, name of tox_list_t member inside our structure (tox_lst),
and the type of structure to return.
   
   TOX_LIST_FOR_EACH(head, tmp)
      printf("%c", TOX_LIST_GET_VALUE(*tmp, tox_lst, tox_string_t).c);
   
   TOX_LIST_FOR_EACH(head, tmp) {
      if (TOX_LIST_GET_VALUE(*tmp, tox_lst, tox_string_t).c == 'z') {
         //If you delete tmp, you have to quit the loop, or it will go on infinitly.
         //This will be fixed later on.
         tox_list_remove(tmp);
         break;
      }
   }
   
   printf("\n");
   TOX_LIST_FOR_EACH(head, tmp)
      printf("%c", TOX_LIST_GET_VALUE(*tmp, tox_lst, tox_string_t).c);
   
   
   return 0;
}
*/

#define MEMBER_OFFSET(var_name_in_parent, parent_type) \
   (&(((parent_type*)0)->var_name_in_parent))

#define GET_PARENT(var, var_name_in_parent, parent_type) \
   (*((parent_type*)((uint64_t)(&(var)) - (uint64_t)(MEMBER_OFFSET(var_name_in_parent, parent_type)))))

#define TOX_LIST_FOR_EACH(lst, tmp_name) \
   for (tox_list_t* tmp_name = lst.next; tmp_name != &lst; tmp_name = tmp_name->next)

#define TOX_LIST_GET_VALUE(tmp_name, name_in_parent, parent_type) GET_PARENT(tmp_name, name_in_parent, parent_type)

typedef struct tox_list {
   struct tox_list *prev, *next;
} tox_list_t;

/* Returns a new tox_list_t. */
static inline void tox_list_new(tox_list_t* lst) {
   lst->prev = lst->next = lst;
}
      
/* Inserts a new tox_lst after lst and returns it. */
static inline void tox_list_add(tox_list_t* lst, tox_list_t* new_lst) {
   tox_list_new(new_lst);

   new_lst->next = lst->next;
   new_lst->next->prev = new_lst;

   lst->next = new_lst;
   new_lst->prev = lst;
}

static inline void tox_list_remove(tox_list_t* lst) {
#ifdef DEBUG /* TODO: check how debugging is done in Tox. */
   assert(lst->next != lst && lst->prev != lst);
#endif
   lst->prev->next = lst->next;
   lst->next->prev = lst->prev;
}

#endif // MISC_TOOLS_H
