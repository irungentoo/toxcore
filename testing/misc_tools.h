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

#include <stdlib.h>
#include <stdint.h>

unsigned char* hex_string_to_bin(char hex_string[]);

/*********************Debugging Macros********************
 * wiki.tox.im/index.php/Internal_functions_and_data_structures#Debugging
 *********************************************************/
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

    #define INFO(...) do { \
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
    #define INFO(...)
    #undef ERROR
    #define ERROR(...)
#endif // DEBUG

/************************Linked List***********************
 * http://wiki.tox.im/index.php/Internal_functions_and_data_structures#Linked_List
 **********************************************************/

#define MEMBER_OFFSET(var_name_in_parent, parent_type) \
   (&(((parent_type*)0)->var_name_in_parent))

#define GET_PARENT(var, var_name_in_parent, parent_type) \
   ((parent_type*)((uint64_t)(&(var)) - (uint64_t)(MEMBER_OFFSET(var_name_in_parent, parent_type))))

#define TOX_LIST_FOR_EACH(lst, tmp_name) \
   for (tox_list_t* tmp_name = lst.next; tmp_name != &lst; tmp_name = tmp_name->next)

#define TOX_LIST_GET_VALUE(tmp_name, name_in_parent, parent_type) GET_PARENT(tmp_name, name_in_parent, parent_type)

typedef struct tox_list {
   struct tox_list *prev, *next;
} tox_list_t;

/* Returns a new tox_list_t. */
static inline void tox_list_new(tox_list_t* lst)
{
   lst->prev = lst->next = lst;
}
      
/* Inserts a new tox_lst after lst and returns it. */
static inline void tox_list_add(tox_list_t* lst, tox_list_t* new_lst)
{
   tox_list_new(new_lst);

   new_lst->next = lst->next;
   new_lst->next->prev = new_lst;

   lst->next = new_lst;
   new_lst->prev = lst;
}

static inline void tox_list_remove(tox_list_t* lst)
{
   lst->prev->next = lst->next;
   lst->next->prev = lst->prev;
}

/****************************Array***************************
 * Array to store pointers which tracks it's own size.
 * TODO: Figure out if it shold store values instead of
 * pointers?
 * TODO: Add wiki info usage.
 ************************************************************/

struct tox_array {
    void **data;
    uint32_t size, length;
};

static inline void tox_array_init(struct tox_array *arr)
{
    arr->size = 1;
    arr->length = 0;
    arr->data = malloc(sizeof(void*));
}

static inline void tox_array_delete(struct tox_array *arr)
{
    free(arr->data);
    arr->size = arr->length = 0;
}

/* shrinks arr so it will not have unused space. If you want to have
 * addtional space, extra species the amount of extra space.
 */
static inline void tox_array_shrink_to_fit(struct tox_array *arr, int32_t extra)
{
    arr->size = arr->length + extra;
    arr->data = realloc(arr->data, arr->size * sizeof(void*));
}

static inline void _tox_array_push(struct tox_array *arr, void *new)
{
    if (arr->length+1 >= arr->size)
        tox_array_shrink_to_fit(arr, arr->size);
    arr->data[arr->length++] = new;
}
#define tox_array_push(arr, new) _tox_array_push(arr, (void*)new)

static inline void* tox_array_pop(struct tox_array *arr)
{
    if (arr->length-1 < arr->size/4)
        tox_array_shrink_to_fit(arr, arr->length*2); 
    return arr->data[arr->length--]; 
}

#endif // MISC_TOOLS_H
