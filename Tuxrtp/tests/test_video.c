#include "../rtp_handler.h"
#include "../rtp_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "test_helper.h"

#include "AV_codec.h"
#include <arpa/inet.h>

/*
int print_help()
{
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
  		"		 			  [-r ( recv mode ) ]";
    puts ( _help );
    return FAILURE;
}
*/
int __main(int argc, char* argv[])
{
    VideoState      *is;
    is = av_mallocz(sizeof(VideoState));
    SDL_Event       event;

    int status;
    IP_Port     Ip_port[1];
    const char* ip;
    uint16_t    port;

    arg_t* _list = parse_args ( argc, argv );

    if ( _list == NULL ) { /* failed */
    return print_help();
    }

    if ( find_arg_simple ( _list, "-r" ) != FAILURE )
    {
	IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
	LOCAL_IP.ip.i = inet_addr ( "93.157.198.212" );
	LOCAL_IP.port = RTP_PORT;
	LOCAL_IP.padding = -1;
	is->_m_session = rtp_init_session ( LOCAL_IP, -1 ); /* You can even init it at the starting session */
	status     = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );

	if (status < 0)
	{
	    is->_m_session->_last_error = strerror ( errno );
	    puts ( is->_m_session->_last_error );
	    return FAILURE;
	}

	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER);

	init_decoder(is);
	int width=640;
	int height=472;
	screen = SDL_SetVideoMode(width, height, 0, 0);
	is->pFrameWebcam=avcodec_alloc_frame();
	is->pDFrame=avcodec_alloc_frame();
	is->VP.bmp = SDL_CreateYUVOverlay(width,height,SDL_YV12_OVERLAY,screen);
	is->sws_ctx = sws_getContext(width,height,is->pDCodecCtx2->pix_fmt,width,height,PIX_FMT_YUV420P,SWS_BILINEAR,NULL,NULL,NULL);

	is->parse_tid = SDL_CreateThread(decode_thread,is);

	/* start in recv mode */
	while (1)
	{
	    printf("Started\n");
	    SDL_WaitEvent(&event);
	    switch(event.type)
	    {
		case FF_QUIT_EVENT:
		case SDL_QUIT:
            is->quit = 1;
            SDL_Quit();
            exit(0);
		break;
		default:
		break;
	    }
	}
    }
    else if ( find_arg_simple ( _list, "-s" ) != FAILURE )
    {
	ip = find_arg_duble ( _list, "-d" );
	if ( ip == NULL )
	return FAILURE;

	const char* _port = find_arg_duble ( _list, "-p" );

	if ( _port != NULL )
	port = atoi ( _port );

	set_ip_port ( ip, port, Ip_port );
	//printf ( "Remote: %s:%d\n", ip, port );
	status = init_networking ( Ip_port[0].ip, RTP_PORT );
	is->_m_session = rtp_init_session ( Ip_port[0], -1 );
	//puts ( "Now sending..." );

	init_webcam_decoder(is);
	init_encoder(is);
	is->pFrameWebcam=avcodec_alloc_frame();
	//is->parse_tid = SDL_CreateThread(encode_thread, is);
	encode_thread(is);

	while(1)
	{
	    SDL_WaitEvent(&event);
	    switch(event.type)
	    {
		case FF_QUIT_EVENT:
		case SDL_QUIT:
		is->quit = 1;
		SDL_Quit();
		exit(0);
		break;
		default:
		break;
	    }
	}

	if ( is->_m_session->_last_error ) {
	puts ( is->_m_session->_last_error );
	}

	return status;
    }
    else {
    return FAILURE;
    }

    return SUCCESS;
}

