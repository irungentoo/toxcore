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

#include "list.h"

/* Basically, the elements in the list are placed in order so that they can be searched for easily
 * -each element is seen as a big-endian integer when ordering them
 * -the ids array is maintained so that each id always matches
 * -the search algorithm cuts down the time to find the id associated with a piece of data
 *   at the cost of slow add/remove functions for large lists
 * -Starts at 1/2 of the array, compares the element in the array with the data,
 *   then moves +/- 1/4 of the array depending on whether the value is greater or lower,
 *   then +- 1/8, etc, until the value is matched or its position where it should be in the array is found
 * -some considerations since the array size is never perfect
 */

#define INDEX(i) (-i -1)

/* Find data in list
 *
 * return value:
 *  >= 0 : id associated with data
 *  < 0  : no match, returns index (return value is INDEX(index)) where
 *         the data should be inserted
 */
static int find(LIST *list, void *data)
{
    //should work well, but could be improved
    if(list->n == 0) {
        return INDEX(0);
    }

    uint32_t i = list->n / 2; //current position in the array
    uint32_t delta = i / 2;   //how much we move in the array

    int d = -1; //used to determine if closest match is found
    //closest match is found if we move back to where we have already been

    while(1) {
        int r = memcmp(data, list->data + list->size * i, list->size);
        if(r == 0) {
            return list->ids[i];
        }

        if(r > 0) {
            //data is greater
            //move down
            i += delta;

            if(d == 0 || i == list->n) {
                //reached bottom of list, or closest match
                return INDEX(i);
            }

            delta = (delta) / 2;
            if(delta == 0) {
                delta = 1;
                d = 1;
            }
        } else {
            //data is smaller
            if(d == 1 || i == 0) {
                //reached top or list or closest match
                return INDEX(i);
            }

            //move up
            i -= delta;

            delta = (delta) / 2;
            if(delta == 0) {
                delta = 1;
                d = 0;
            }
        }
    }
}


void list_init(LIST *list, uint32_t element_size)
{
    //set initial values
    list->n = 0;
    list->size = element_size;
    list->data = NULL;
    list->ids = NULL;
}

void list_free(LIST *list)
{
    //free both arrays
    free(list->data);
    free(list->ids);
}

int list_find(LIST *list, void *data)
{
    int r = find(list, data);
    //return only -1 and positive values
    if(r < 0) {
        r = -1;
    }

    return r;
}

int list_add(LIST *list, void *data, int id)
{
    //find where the new element should be inserted
    //see: return value of find()
    int i = find(list, data);
    if(i >= 0) {
        //already in list
        return 0;
    }

    i = -i - 1;

    //increase the size of the arrays by one
    list->data = realloc(list->data, list->size * (list->n + 1));
    list->ids = realloc(list->ids, sizeof(int) * (list->n + 1));

    if(!list->data || !list->ids)
    {
        return 0;
    }

    //insert data to element array
    memmove(list->data + (i + 1) * list->size, list->data + i * list->size, (list->n - i) * list->size);
    memcpy(list->data + i * list->size, data, list->size);

    //insert id to id array
    memmove(&list->ids[i + 1], &list->ids[i], (list->n - i) * sizeof(int));
    list->ids[i] = id;

    //increase n
    list->n++;

    return 1;
}

void list_remove(LIST *list, int id)
{
    int i;
    for(i = 0; i < list->n; i++) {
        if(list->ids[i] == id) {
            //decrease number of elements
            list->n--;

            //move elements in both arrays down by one
            memmove(list->data + i * list->size, list->data + (i + 1) * list->size, (list->n - i) * list->size);
            memmove(&list->ids[i], &list->ids[i + 1], (list->n - i) * sizeof(int));

            //return causes it to only remove the first element with the specified id
            //(as opposed to all elements with that id if there are more than one - but there normally should not be)
            //i--;
            return;
        }
    }
}
