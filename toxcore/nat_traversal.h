/* nat_traversal.h -- Functions to traverse a NAT (UPnP, NAT-PMP).
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
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

#ifndef NAT_TRAVERSAL_H
#define NAT_TRAVERSAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>


/**
 * The protocol that will be used by the nat traversal.
 */
#if defined(HAVE_LIBMINIUPNPC) || defined(HAVE_LIBNATPMP)
typedef enum NAT_TRAVERSAL_PROTO {

    /* UDP */
    NAT_TRAVERSAL_UDP,

    /* TCP */
    NAT_TRAVERSAL_TCP,

} NAT_TRAVERSAL_PROTO;
#endif


#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
void upnp_map_port(NAT_TRAVERSAL_PROTO proto, uint16_t port);
#endif

#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
void natpmp_map_port(NAT_TRAVERSAL_PROTO proto, uint16_t port);
#endif

#endif
