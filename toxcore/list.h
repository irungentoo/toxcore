/* list.h
 *
 * Simple struct with functions to create a list which associates ids with data
 * -Allows for finding ids associated with data such as IPs or public keys in a short time
 * -Should only be used if there are relatively few add/remove calls to the list
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t n; //number of elements
    uint32_t size; //size of the elements
    void *data; //array of elements
    int *ids; //array of element ids
} LIST;

/* Initialize a list, element_size is the size of the elements in the list */
void list_init(LIST *list, uint32_t element_size);

/* Free a list initiated with list_init */
void list_free(LIST *list);

/* Retrieve the id of an element in the list
 *
 * return value:
 *  >= 0 : id associated with data
 *  -1   : failure
 */
int list_find(LIST *list, void *data);

/* Add an element with associated id to the list
 *
 * return value:
 *  1 : success
 *  0 : failure (data already in list)
 */
int list_add(LIST *list, void *data, int id);

/* Remove an element from the list */
void list_remove(LIST *list, int id);
