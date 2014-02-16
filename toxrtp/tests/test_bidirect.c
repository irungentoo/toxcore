/* test_bidirect.c
 *
 * Tox DHT bootstrap server daemon.
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
 
#define _BSD_SOURCE

#include "../toxrtp.h"
#include "../toxrtp_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "test_helper.h"
#include "../../toxcore/tox.h"

#ifdef _CT_BIDIRECT

int _print_help( const char* name )
{
    char* _help = malloc( 300 );
    memset(_help, '\0', 300);

    strcat(_help, " Usage: ");
    strcat(_help, name);
    strcat(_help, "\n -d IP ( destination )\n"
                    " -p PORT ( dest Port )\n"
                    " -l PORT ( listen Port ) \n");

    puts ( _help );

    free(_help);
    return FAILURE;
}

int main( int argc, char* argv[] )
{
    int status;
    tox_IP_Port     Ip_port;
    const char* ip, *psend, *plisten;
    uint16_t    port_send, port_listen;
    const uint8_t* test_bytes = "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789";


    rtp_session_t* _m_session;
    rtp_msg_t     *_m_msg_R, *_m_msg_S;
    arg_t* _list = parse_args ( argc, argv );

    ip = find_arg_duble(_list, "-d");
    psend = find_arg_duble(_list, "-p");
    plisten = find_arg_duble(_list, "-l");

    if ( !ip || !plisten || !psend )
        return _print_help(argv[0]);

    port_send = atoi(psend);
    port_listen = atoi(plisten);

    IP_Port local, remote;

    /*
     * This is the Local ip. We initiate networking on
     * this value for it's the local one. To make stuff simpler we receive over this value
     * and send on the other one ( see remote )
     */
    local.ip.i = htonl(INADDR_ANY);
    local.port = port_listen;
    Networking_Core* _networking = new_networking(local.ip, port_listen);

    if ( !_networking )
        return FAILURE;

    int _socket = _networking->sock;
    /*
     * Now this is the remote. It's used by rtp_session_t to determine the receivers ip etc.
     */
    t_setipport ( ip, port_send, &remote );
    _m_session = rtp_init_session(-1, -1);
    rtp_add_receiver( _m_session, &remote );

    /* Now let's start our main loop in both recv and send mode */

    for ( ;; )
    {
        /*
         * This part checks for received messages and if gotten one
         * display 'Received msg!' indicator and free message
         */
        _m_msg_R = rtp_recv_msg ( _m_session );

        if ( _m_msg_R ) {
            puts ( "Received msg!" );
            rtp_free_msg(_m_session, _m_msg_R);
        }
        /* -------------------- */

        /*
         * This one makes a test msg and sends that message to the 'remote'
         */
        _m_msg_S = rtp_msg_new ( _m_session, test_bytes, 280 ) ;
        rtp_send_msg ( _m_session, _m_msg_S, _socket );
        usleep ( 10000 );
        /* -------------------- */
    }

    return SUCCESS;
}

#endif /* _CT_BIDIRECT */
