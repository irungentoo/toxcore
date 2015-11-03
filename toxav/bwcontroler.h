/**  bwcontroler.h
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
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
 */

#ifndef BWCONROLER_H
#define BWCONROLER_H
#include "../toxcore/Messenger.h"

typedef struct BWControler_s BWControler;

BWControler *bwc_new(Messenger *m, uint32_t friendnumber,
                     void (*mcb) (BWControler *, uint32_t, float, void *),
                     void *udata);
void bwc_kill(BWControler *bwc);

void bwc_feed_avg(BWControler *bwc, uint32_t bytes);
void bwc_add_lost(BWControler *bwc, uint32_t bytes);
void bwc_add_recv(BWControler *bwc, uint32_t bytes);

#endif /* BWCONROLER_H */
