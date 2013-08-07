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

#define DEBUG

unsigned char * hex_string_to_bin(char hex_string[]);

/* See http://wiki.tox.im/index.php/Internal_functions_and_data_structures#Debugging for usage info. */
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

    #define ERROR(exit_status, ...) do { \
        fprintf(stderr, "error in "); \
        DEBUG_PRINT(__VA_ARGS__, ' '); \
        exit(exit_status); \
    } while (0)
#else
    #define WARNING(...)
    #define ERROR(...)
#endif // DEBUG

/************************Linked List***********************/
/* See http://wiki.tox.im/index.php/Internal_functions_and_data_structures#Linked_List for usage info. */

#define MEMBER_OFFSET(var_name_in_parent, parent_type) \
   (&(((parent_type*)0)->var_name_in_parent))

#define GET_PARENT(var, var_name_in_parent, parent_type) \
   (*((parent_type*)((uint64_t)(&(var)) - (uint64_t)(MEMBER_OFFSET(var_name_in_parent, parent_type)))))

/* LIFO */
#define TOX_LIST_FOR_EACH_REVERSE(lst, tmp_name) \
   for (struct tox_list* tmp_name = lst.next; tmp_name != &lst; tmp_name = tmp_name->next)

/* LILO */
#define TOX_LIST_FOR_EACH(lst, tmp_name) \
   for (struct tox_list* tmp_name = lst.prev; tmp_name != &lst; tmp_name = tmp_name->prev)

#define TOX_LIST_GET_VALUE(tmp_name, name_in_parent, parent_type) GET_PARENT(tmp_name, name_in_parent, parent_type)

struct tox_list
{
    struct tox_list *prev, *next;
};

/* only call this for the head */
static inline void tox_list_init(struct tox_list * head)
{
    head->prev = head->next = head;
}
      
/* Inserts a new tox_lst after lst and returns it. */
static inline void tox_list_add(struct tox_list * lst, struct tox_list * new_lst)
{
    /* tox_list_new(new_lst); */
    new_lst->next = lst->next;
    new_lst->next->prev = new_lst;

    lst->next = new_lst;
    new_lst->prev = lst;
}

static inline void tox_list_remove(struct tox_list * lst) {
    lst->prev->next = lst->next;
    lst->next->prev = lst->prev;
}

#endif // MISC_TOOLS_H
