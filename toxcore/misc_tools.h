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

/****************************Algorithms***************************
 * Macro/generic definitions for useful algorithms
 *****************************************************************/

/* Creates a new quick_sort implementation for arrays of the specified type.
 * For a type T (eg: int, char), creates a function named T_quick_sort.
 *
 * Quick Sort: Complexity O(nlogn)
 * arr   - the array to sort
 * n     - the sort index (should be called with n = length(arr))
 * cmpfn - a function that compares two values of type type.
 *         Must return -1, 0, 1 for a < b, a == b, and a > b respectively.
 */
/* Must be called in the header file. */
#define declare_quick_sort(type) \
void type##_quick_sort(type *arr, int n, int (*cmpfn)(type, type));

/* Must be called in the C file. */
#define make_quick_sort(type) \
void type##_quick_sort(type *arr, int n, int (*cmpfn)(type, type)) \
{ \
    if ((n) < 2) \
        return; \
    type _p_ = (arr)[(n) / 2]; \
    type *_l_ = (arr); \
    type *_r_ = (arr) + n - 1; \
    while (_l_ <= _r_) { \
        if (cmpfn(*_l_, _p_) == -1) { \
            ++_l_; \
            continue; \
        } \
        if (cmpfn(*_r_, _p_) == 1) { \
            --_r_; \
            continue; \
        } \
        type _t_ = *_l_; \
        *_l_++ = *_r_; \
        *_r_-- = _t_; \
    } \
    type##_quick_sort((arr), _r_ - (arr) + 1, cmpfn); \
    type##_quick_sort(_l_, (arr) + n - _l_, cmpfn); \
}

#endif // MISC_TOOLS_H
