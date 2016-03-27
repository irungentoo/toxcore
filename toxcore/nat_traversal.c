/* nat_traversal.c -- Functions to traverse a NAT (UPnP, NAT-PMP).
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBMINIUPNPC
#include <stdio.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

#ifdef HAVE_LIBNATPMP
#include <unistd.h>
#include <natpmp.h>
#endif

#include "nat_traversal.h"
#include "logger.h"

#ifdef HAVE_LIBMINIUPNPC
/* Setup port forwarding using UPnP */
void upnp_map_port(NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    LOGGER_DEBUG("Attempting to set up UPnP port forwarding");

    int error = 0;
    struct UPNPDev *devlist = NULL;

#if MINIUPNPC_API_VERSION < 14
    devlist = upnpDiscover(1000, NULL, NULL, 0, 0, &error);
#else
    devlist = upnpDiscover(1000, NULL, NULL, 0, 0, 2, &error);
#endif

    if (error) {
        LOGGER_WARNING("UPnP discovery failed (error = %d)", error);
        return;
    }

    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[64];

    error = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    freeUPNPDevlist(devlist);
    if (error) {
        if (error == 1) {
            LOGGER_INFO("A valid IGD has been found.");

            char portstr[10];
            snprintf(portstr, sizeof(portstr), "%d", port);

            if (proto == NAT_TRAVERSAL_UDP)
                error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "UDP", 0, "0");
            else if (proto == NAT_TRAVERSAL_TCP)
                error = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, portstr, portstr, lanaddr, "Tox", "TCP", 0, "0");
            else
                LOGGER_WARNING("UPnP port mapping failed (unknown NAT_TRAVERSAL_PROTO)");

            if (error)
                LOGGER_WARNING("UPnP port mapping failed (error = %d)", error);
            else
                LOGGER_INFO("UPnP mapped port %d", port);
        } else if (error == 2)
            LOGGER_WARNING("IGD was found but reported as not connected.");
        else if (error == 3)
            LOGGER_WARNING("UPnP device was found but not recoginzed as IGD.");
        else
            LOGGER_WARNING("Unknown error finding IGD: %d", error);

        FreeUPNPUrls(&urls);
    } else
        LOGGER_WARNING("No IGD was found.");
}
#endif


#ifdef HAVE_LIBNATPMP
/* Setup port forwarding using NAT-PMP */
void natpmp_map_port(NAT_TRAVERSAL_PROTO proto, uint16_t port)
{
    LOGGER_DEBUG("Attempting to set up NAT-PMP port forwarding");

    int error;
    natpmp_t natpmp;
    natpmpresp_t resp;

    error = initnatpmp(&natpmp, 0, 0);
    if (error) {
        LOGGER_WARNING("NAT-PMP initialization failed (error = %d)", error);
        return;
    }

    if (proto == NAT_TRAVERSAL_UDP)
        error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, port, port, 3600);
    else if (proto == NAT_TRAVERSAL_TCP)
        error = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
    else {
        LOGGER_WARNING("NAT-PMP port mapping failed (unknown NAT_TRAVERSAL_PROTO)");
        closenatpmp(&natpmp);
        return;
    }

    if (error != 12) {
        LOGGER_WARNING("NAT-PMP send request failed (error = %d)", error);
        closenatpmp(&natpmp);
        return;
    }

    error = readnatpmpresponseorretry(&natpmp, &resp);
    for ( ; error == NATPMP_TRYAGAIN ; error = readnatpmpresponseorretry(&natpmp, &resp) )
        sleep(1);

    if (error)
        LOGGER_WARNING("NAT-PMP port mapping failed (error = %d)", error);
    else
        LOGGER_INFO("NAT-PMP mapped port %d", port);

    closenatpmp(&natpmp);
}
#endif
