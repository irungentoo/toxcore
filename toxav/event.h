/**  event.h
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *   Report bugs/suggestions at #tox-dev @ freenode.net:6667
 */


#ifndef __TOXEVENT
#define __TOXEVENT


/**
 * - Events are, in fact, ran in their own threads upon execution.
 * - Event handler is initialized at the start, before the main() function
 *      and terminated after it's execution.
 * - Timers are checked for timeout every ~10000 ns.
 * - Timers can be canceled or ran immediately via
 *      timer_release() or timer_now() functions.
 * - Timeout is measured in milliseconds.
 *
 * NOTE: timer_reset () and timer_now() are not tested nor usable atm
 *
 */
extern struct _Event {
    ptrdiff_t (*rise) (void * ( func ) ( void * ), void *arg);
    ptrdiff_t (*timer_reset ) ( ptrdiff_t id, size_t timeout );
    ptrdiff_t (*timer_alloc) (void * ( func ) ( void * ), void *arg, size_t timeout);
    ptrdiff_t (*timer_release) (ptrdiff_t id);
    ptrdiff_t (*timer_now) ( ptrdiff_t id );
} event;

#endif /* _MSI__EVENT_H_ */
