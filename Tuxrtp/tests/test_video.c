/*   test_regular.c
 *
 *   Tests regular RTP flow. Use this for data transport. !Red!
 *
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
 *   along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "../rtp_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "test_helper.h"
#include "AV_codec.h"


int print_help()
    {
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
                        "                     [-r ( recv mode ) ]";
    puts ( _help );
    return FAILURE;
    }

int main ( int argc, char* argv[] )
{
    call_state      *cs;
    cs = av_mallocz(sizeof(call_state));
    
    
    int status;
    IP_Port     Ip_port;
    const char* ip, *psend, *plisten;
    uint16_t    port_send, port_listen;

    arg_t* _list = parse_args ( argc, argv );


    if ( _list == NULL ) { /* failed */
        return print_help();
    }
    
    ip = find_arg_duble(_list, "-d");
    psend = find_arg_duble(_list, "-p");
    plisten = find_arg_duble(_list, "-l");

    if ( !ip || !plisten || !psend )
        return print_help(argv[0]);

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
    status = init_networking(local.ip, port_listen);
    
    /*
     * Now this is the remote. It's used by rtp_session_t to determine the receivers ip etc.
     */
    set_ip_port ( ip, port_send, &remote );
    cs->_m_session = rtp_init_session(-1);
    rtp_add_receiver( cs->_m_session, &remote );


	init_encoder(cs);
	init_decoder(cs);
	
	if(cs->support_send_video) {
	    uint8_t *buffer;
	    int numBytes;
	    // Determine required buffer size and allocate buffer
	    numBytes=avpicture_get_size(PIX_FMT_YUV420P, cs->webcam_decoder_ctx->width,cs->webcam_decoder_ctx->height);
	    buffer=(uint8_t *)av_malloc(numBytes*sizeof(uint8_t));
	    avpicture_fill((AVPicture *)cs->scaled_webcam_frame, buffer, PIX_FMT_YUV420P,cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height);
	    cs->sws_ctx = sws_getContext(cs->webcam_decoder_ctx->width,cs->webcam_decoder_ctx->height,cs->webcam_decoder_ctx->pix_fmt,cs->webcam_decoder_ctx->width,cs->webcam_decoder_ctx->height,PIX_FMT_YUV420P,SWS_BILINEAR,NULL,NULL,NULL);
	}
	cs->quit = 0;
	cs->SDL_initialised=0;
	
	if(cs->support_send_audio) pthread_create(&cs->encode_audio_thread, NULL, encode_audio_thread, cs);
	if(cs->support_send_video) pthread_create(&cs->encode_video_thread, NULL, encode_video_thread, cs);
	
	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER | SDL_INIT_EVENTTHREAD);
	
	if(cs->support_receive_video||cs->support_receive_audio) pthread_create(&cs->decode_thread, NULL, decode_thread, cs);
	
	cs->SDL_initialised=1;
	
	
	while(1)
	{
	    SDL_WaitEvent(&cs->SDL_event);
	    switch(cs->SDL_event.type)
	    {
		case FF_QUIT_EVENT:
		case SDL_QUIT:
		cs->quit = 1;
		SDL_Quit();
		exit(0);
		break;
		default:
		break;
	    }
	}

        if ( cs->_m_session->_last_error ) {
            puts ( cs->_m_session->_last_error );
        }

    return SUCCESS;
}
