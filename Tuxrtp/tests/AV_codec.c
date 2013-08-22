/* AV_codec.c
//  *
 * Audio and video codec intitialisation, encoding/decoding and playback
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

/*----------------------------------------------------------------------------------*/

#include <stdio.h>
#include <math.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavdevice/avdevice.h>
#include <libavutil/opt.h>
#include <AL/al.h>
#include <AL/alc.h>
#include <AL/alut.h>
#include <SDL.h>
#include <SDL_thread.h>
#include <pthread.h>

#include "../rtp_impl.h"
#include "test_helper.h"
#include "AV_codec.h"


int display_received_frame(call_state *cs)
{
    AVPicture pict;
    SDL_LockYUVOverlay(cs->video_picture.bmp);
    
    pict.data[0] = cs->video_picture.bmp->pixels[0];
    pict.data[1] = cs->video_picture.bmp->pixels[2];
    pict.data[2] = cs->video_picture.bmp->pixels[1];
    pict.linesize[0] = cs->video_picture.bmp->pitches[0];
    pict.linesize[1] = cs->video_picture.bmp->pitches[2];
    pict.linesize[2] = cs->video_picture.bmp->pitches[1];

    //Convert the image into YUV format that SDL uses
    sws_scale(cs->sws_SDL_r_ctx, (uint8_t const * const *)cs->r_video_frame->data, cs->r_video_frame->linesize, 0, cs->video_decoder_ctx->height, pict.data, pict.linesize );
    
    SDL_UnlockYUVOverlay(cs->video_picture.bmp);
    SDL_Rect rect;  
    rect.x = 0;
    rect.y = 0;
    rect.w = cs->video_decoder_ctx->width;
    rect.h = cs->video_decoder_ctx->height;
    SDL_DisplayYUVOverlay(cs->video_picture.bmp, &rect);
    return 1;
}


int decode_video_frame(call_state *cs)
{
    avcodec_decode_video2(cs->video_decoder_ctx, cs->r_video_frame, &cs->dec_frame_finished, &cs->dec_video_packet);
    return 1;
}


int encode_audio_frame(call_state *cs)
{
    int got_packet_ptr=0;
    avcodec_encode_audio2(cs->audio_encoder_ctx,&cs->enc_audio_packet,cs->enc_audio_frame,&got_packet_ptr);
    if(!got_packet_ptr){printf("Could not encode audio packet\n");}
    return 1;
}

int init_receive_audio(call_state *cs)
{
    cs->audio_decoder = avcodec_find_decoder(AUDIO_CODEC);
    if(!cs->audio_decoder) {
	printf("init audio_decoder failed\n");
	return 0;
    }
    cs->audio_decoder_ctx = avcodec_alloc_context3(cs->audio_decoder);
    if(!cs->audio_decoder_ctx) {
	printf("init audio_decoder_ctx failed\n");
	return 0;
    }
    cs->audio_decoder_ctx->sample_rate=48000;
    cs->audio_decoder_ctx->channels=1;
    cs->audio_decoder_ctx->channel_layout=av_get_default_channel_layout(1);
    cs->audio_decoder_ctx->request_sample_fmt=AV_SAMPLE_FMT_S16;
    av_opt_set(cs->audio_decoder_ctx->priv_data, "complexity", "10", 0);
    AVDictionary *options = NULL;
    av_dict_set(&options, "complexity", "10", 0);
    if(avcodec_open2(cs->audio_decoder_ctx,cs->audio_decoder,&options)<0) {
	av_dict_free(&options);
	printf("opening audio decoder failed\n");
	return 0;
    }
    av_dict_free(&options);
    cs->audio_frame=avcodec_alloc_frame();
    printf("init audio decoder successful\n");
    return 1;
}

int init_receive_video(call_state *cs)
{
    cs->video_decoder = avcodec_find_decoder(VIDEO_CODEC);
    if(!cs->video_decoder) {
	printf("init video_decoder failed\n");
	return 0;
    }
    cs->video_decoder_ctx = avcodec_alloc_context3(cs->video_decoder);
    if(!cs->video_decoder_ctx) {
	printf("init video_decoder_ctx failed\n");
	return 0;
    }
    if(avcodec_open2(cs->video_decoder_ctx,cs->video_decoder,NULL)<0) {
	printf("opening video decoder failed\n");
	return 0;
    }
    cs->webcam_frame=avcodec_alloc_frame();
    cs->r_video_frame=avcodec_alloc_frame();
    printf("init video decoder successful\n");
    return 1;
}




int init_send_video(call_state *cs)
{

    cs->video_input_format=av_find_input_format(VIDEO_DRIVER);
    if(avformat_open_input(&cs->video_format_ctx,DEFAULT_WEBCAM, cs->video_input_format, NULL)!=0) {
	printf("opening video_input_format failed\n");
	return 0; 
    }
    avformat_find_stream_info(cs->video_format_ctx, NULL);
    av_dump_format(cs->video_format_ctx, 0, DEFAULT_WEBCAM, 0);
    
    int i;
    for(i=0; i<cs->video_format_ctx->nb_streams; ++i) {
	if(cs->video_format_ctx->streams[i]->codec->codec_type==AVMEDIA_TYPE_VIDEO) {
	    cs->video_stream=i;
	    break;
	}
    }
    
    cs->webcam_decoder_ctx=cs->video_format_ctx->streams[cs->video_stream]->codec;
    cs->webcam_decoder=avcodec_find_decoder(cs->webcam_decoder_ctx->codec_id); 
    if(cs->webcam_decoder==NULL) {
	printf("Unsupported codec\n");
	return 0;
    }
    if(cs->webcam_decoder_ctx==NULL) {
      	printf("init webcam_decoder_ctx failed\n");
	return 0;
    }
    
    if(avcodec_open2(cs->webcam_decoder_ctx, cs->webcam_decoder, NULL)<0) {
	printf("opening webcam decoder failed\n");
	return 0;
    }
    cs->webcam_frame=avcodec_alloc_frame();
    cs->s_video_frame=avcodec_alloc_frame();
    
    cs->video_encoder = avcodec_find_encoder(VIDEO_CODEC);
    if(!cs->video_encoder) {
	printf("init video_encoder failed\n");
	return 0;
    }
    cs->video_encoder_ctx = avcodec_alloc_context3(cs->video_encoder);
    if(!cs->video_encoder_ctx) {
	printf("init video_encoder_ctx failed\n");
	return 0;
    }

    cs->video_encoder_ctx->bit_rate = VIDEO_BITRATE;
    cs->video_encoder_ctx->rc_min_rate = cs->video_encoder_ctx->rc_max_rate = cs->video_encoder_ctx->bit_rate;
    av_opt_set_double(cs->video_encoder_ctx->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(cs->video_encoder_ctx->priv_data, "quality", "realtime", 0);
    
    cs->video_encoder_ctx->thread_count = 4;
    cs->video_encoder_ctx->rc_buffer_aggressivity = 0.95;
    cs->video_encoder_ctx->rc_buffer_size = VIDEO_BITRATE*6;
    cs->video_encoder_ctx->profile = 3;
    cs->video_encoder_ctx->qmax = 54;
    cs->video_encoder_ctx->qmin = 4;
    AVRational myrational = {1,25};
    cs->video_encoder_ctx->time_base= myrational;
    cs->video_encoder_ctx->gop_size = 99999;
    cs->video_encoder_ctx->pix_fmt = PIX_FMT_YUV420P; 
    cs->video_encoder_ctx->width = cs->webcam_decoder_ctx->width;
    cs->video_encoder_ctx->height = cs->webcam_decoder_ctx->height;
    if(avcodec_open2(cs->video_encoder_ctx,cs->video_encoder,NULL)<0) {
	printf("opening video encoder failed\n");
	return 0;
    }
    printf("init video encoder successful\n");  
    return 1;
}

int init_send_audio(call_state *cs)
{
    cs->support_send_audio=0;
    cs->audio_input_format=av_find_input_format(AUDIO_DRIVER);
    AVDictionary *mic_options=NULL;
    av_dict_set(&mic_options, "channels", "1", 0);
    char *rate = (char *) av_malloc(100);
    snprintf(rate, 100, "%d", AUDIO_SAMPLE_RATE);
    av_dict_set(&mic_options, "sample_rate", rate, AV_DICT_DONT_STRDUP_VAL);
    if(avformat_open_input(&cs->audio_format_ctx,DEFAULT_AUDIO_DEVICE, cs->audio_input_format, &mic_options)!=0)
    return 0; 
    cs->audio_format_ctx->max_analyze_duration= AV_TIME_BASE;
    av_dict_free(&mic_options);
    cs->audio_stream = av_find_best_stream(cs->audio_format_ctx, AVMEDIA_TYPE_AUDIO, -1, -1, &cs->microphone_decoder, 0);
    cs->microphone_decoder_ctx=cs->audio_format_ctx->streams[cs->audio_stream]->codec;
    if(avcodec_open2(cs->microphone_decoder_ctx, cs->microphone_decoder, NULL)<0) {
    printf("opening microphone decoder failed\n");
    return 0;
    }
    cs->microphone_frame=avcodec_alloc_frame();

    printf("init microphone decoder successful\n");

    cs->audio_encoder = avcodec_find_encoder(AUDIO_CODEC);
    if(!cs->audio_encoder) {
	printf("init audio_encoder failed\n");
	return 0;
    }
    cs->audio_encoder_ctx = avcodec_alloc_context3(cs->audio_encoder);
    if(!cs->audio_encoder_ctx) {
	printf("init audio_encoder_ctx failed\n");
	return 0;
    }
    cs->audio_encoder_ctx->channels=1;
    cs->audio_encoder_ctx->channel_layout=av_get_default_channel_layout(1);
    cs->audio_encoder_ctx->bit_rate = AUDIO_BITRATE;
    cs->audio_encoder_ctx->sample_rate = AUDIO_SAMPLE_RATE;
    cs->audio_encoder_ctx->sample_fmt = AV_SAMPLE_FMT_S16;
    cs->audio_encoder_ctx->frame_size = AUDIO_FRAME_SIZE;
    av_opt_set_double(cs->audio_encoder_ctx->priv_data, "frame_duration", AUDIO_FRAME_DURATION, 0);
    av_opt_set(cs->audio_encoder_ctx->priv_data, "vbr","constrained",0);
    if(avcodec_open2(cs->audio_encoder_ctx,cs->audio_encoder,NULL)<0) {
	  printf("opening audio encoder failed\n");
	  return 0;
    }
    cs->enc_audio_frame=avcodec_alloc_frame();
    printf("init audio encoder successful\n");
    
    if(cs->audio_encoder_ctx->frame_size!=AUDIO_FRAME_SIZE)
	printf("frame size is not equal to requested frame size, expect audio issues.\n");
    
    return 1;
}

int init_encoder(call_state *cs)
{
    avdevice_register_all(); 
    avcodec_register_all();    
    avdevice_register_all();
    av_register_all(); 
    
    pthread_mutex_init(&cs->rtp_msg_mutex_lock, NULL);
    cs->support_send_video=init_send_video(cs);
    cs->support_send_audio=init_send_audio(cs);

    cs->send_audio=1;
    cs->send_video=1;
    
    return 1;
}

int init_decoder(call_state *cs)
{       
    avdevice_register_all(); 
    avcodec_register_all();    
    avdevice_register_all();
    av_register_all(); 
    
    cs->receive_video=0;
    cs->receive_audio=0;

    cs->support_receive_video=init_receive_video(cs);
    cs->support_receive_audio=init_receive_audio(cs);
    cs->receive_audio=1;
    cs->receive_video=1;

    return 1;
}


int video_encoder_refresh(call_state *cs, int bps)
{
 if(cs->video_encoder_ctx) 
  avcodec_close(cs->video_encoder_ctx);
 
        cs->video_encoder = avcodec_find_encoder(VIDEO_CODEC);
    if(!cs->video_encoder) {
	printf("init video_encoder failed\n");
	return -1;
    }
    cs->video_encoder_ctx = avcodec_alloc_context3(cs->video_encoder);
    if(!cs->video_encoder_ctx) {
	printf("init video_encoder_ctx failed\n");
	return -1;
    }
    cs->video_encoder_ctx->bit_rate = bps;
    cs->video_encoder_ctx->rc_min_rate = cs->video_encoder_ctx->rc_max_rate = cs->video_encoder_ctx->bit_rate;
    av_opt_set_double(cs->video_encoder_ctx->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(cs->video_encoder_ctx->priv_data, "quality", "realtime", 0);
    
    cs->video_encoder_ctx->thread_count = 4;
    cs->video_encoder_ctx->rc_buffer_aggressivity = 0.95;
    cs->video_encoder_ctx->rc_buffer_size = bps*6;
    cs->video_encoder_ctx->profile = 0;
    cs->video_encoder_ctx->qmax = 54;
    cs->video_encoder_ctx->qmin = 4;
    AVRational myrational = {1,25};
    cs->video_encoder_ctx->time_base= myrational;
    cs->video_encoder_ctx->gop_size = 99999;
    cs->video_encoder_ctx->pix_fmt = PIX_FMT_YUV420P; 
    cs->video_encoder_ctx->width = cs->webcam_decoder_ctx->width;
    cs->video_encoder_ctx->height = cs->webcam_decoder_ctx->height;
    if(avcodec_open2(cs->video_encoder_ctx,cs->video_encoder,NULL)<0) {
	printf("opening video encoder failed\n");
	return -1;
    }
}

void *encode_video_thread(void *arg)
{
  call_state *cs = (call_state *)arg;
  AVPacket pkt1, *packet = &pkt1;
  int p=0;
  int err;
  int got_packet;

    while(1) {
	if(cs->quit) 
	    break;
	
	if(cs->send_video) {
	    if(av_read_frame(cs->video_format_ctx, packet) < 0) {
	     printf("error reading frame\n");
		if(cs->video_format_ctx->pb->error != 0) 
		break;
	    continue;
	    }
	    if(packet->stream_index == cs->video_stream) {
		if(avcodec_decode_video2(cs->webcam_decoder_ctx, cs->webcam_frame, &cs->video_frame_finished, packet)<0)
		{
		  printf("couldn't decode\n");
		  continue;
		  
		}
		av_free_packet(packet);
		sws_scale(cs->sws_ctx,(uint8_t const * const *)cs->webcam_frame->data,cs->webcam_frame->linesize, 0, cs->webcam_decoder_ctx->height, cs->s_video_frame->data,cs->s_video_frame->linesize);
		
		/* create a new I-frame every 60 frames */
		++p;
		if(p==60) {
	
			cs->s_video_frame->pict_type=AV_PICTURE_TYPE_BI ;
		} else if(p==61) {
			cs->s_video_frame->pict_type=AV_PICTURE_TYPE_I ;
			p=0;
		    }
		    else {
		    cs->s_video_frame->pict_type=AV_PICTURE_TYPE_P ;
		}
		
		if(cs->video_frame_finished) {
		      
		    err= avcodec_encode_video2(cs->video_encoder_ctx,&cs->enc_video_packet,cs->s_video_frame,&got_packet);
		    if(err<0) {
			printf("could not encode video frame\n");
			continue;
		    }
		    if(!got_packet) {
			continue;
		    }
		    
		    pthread_mutex_lock(&cs->rtp_msg_mutex_lock);
		    rtp_remove_resolution_marking(cs->_m_session);
		    rtp_add_resolution_marking(cs->_m_session, cs->video_encoder_ctx->width,cs->video_encoder_ctx->height);
		    rtp_set_payload_type(cs->_m_session,106);
		    if(!cs->enc_video_packet.data) fprintf(stderr,"video packet data is NULL\n");
		    cs->s_video_msg = rtp_msg_new ( cs->_m_session, cs->enc_video_packet.data, cs->enc_video_packet.size ) ;
		    rtp_send_msg ( cs->_m_session, cs->s_video_msg );
		    pthread_mutex_unlock(&cs->rtp_msg_mutex_lock);
		    av_free_packet(&cs->enc_video_packet);
		    //printf("Video packet sent\n");
		}
	    } 
	    else {
		av_free_packet(packet);
	    }
	}
	usleep(1000);
    }
    av_free(cs->webcam_frame);
    av_free(cs->s_video_frame);
    sws_freeContext(cs->sws_ctx);
    avcodec_close(cs->webcam_decoder_ctx);
    avcodec_close(cs->video_encoder_ctx);    
}

void *encode_audio_thread(void *arg)
{
    call_state *cs = (call_state *)arg;
    AVPacket pkt1, *packet = &pkt1;
    uint8_t samples_buffer[4096];
    int samples_buffer_size=0;
    int got_packet_ptr=0;
   // int frame_size=AUDIO_FRAME_SIZE;
    int frame_size=cs->audio_encoder_ctx->frame_size;
    if(frame_size!=AUDIO_FRAME_SIZE)
	printf("expect audio issues...\n");
    int buffer_full;
    
    while(1) {
      	if(cs->quit) 
	    break;
	if(cs->send_audio) {  
	    if(av_read_frame(cs->audio_format_ctx, packet) < 0) {
		  if(cs->audio_format_ctx->pb->error != 0) 
		  break;
	    }
	    if(packet->size>frame_size*2)
		printf("error: audio packet too large\n");
	    if(packet->stream_index == cs->audio_stream) {
		int len=avcodec_decode_audio4(cs->microphone_decoder_ctx, cs->enc_audio_frame, &cs->audio_frame_finished, packet);	
		if(!cs->audio_frame_finished) {
		    printf("error: cannot decode microphone stream\n");
		} else {
		    memcpy(&samples_buffer[samples_buffer_size],cs->enc_audio_frame->data[0],len);
		    samples_buffer_size+=len;
		    buffer_full=(samples_buffer_size>=frame_size*2)? 1:0;
		    av_free_packet(packet);
		    while(buffer_full) {
			cs->enc_audio_frame->nb_samples=frame_size;
			avcodec_fill_audio_frame(cs->enc_audio_frame,1,AV_SAMPLE_FMT_S16,&samples_buffer[0],frame_size*2,0);
			memcpy(&samples_buffer[0],&samples_buffer[frame_size*2],(samples_buffer_size-frame_size*2));
			samples_buffer_size-=frame_size*2;
			avcodec_encode_audio2(cs->audio_encoder_ctx,&cs->enc_audio_packet,cs->enc_audio_frame,&got_packet_ptr);
			if(!got_packet_ptr)
			    printf("Could not encode audio packet\n");
			pthread_mutex_lock(&cs->rtp_msg_mutex_lock);
			rtp_remove_resolution_marking(cs->_m_session);
			rtp_set_payload_type(cs->_m_session,96);
			cs->s_audio_msg = rtp_msg_new ( cs->_m_session, cs->enc_audio_packet.data, cs->enc_audio_packet.size ) ;
			rtp_send_msg ( cs->_m_session, cs->s_audio_msg );
			pthread_mutex_unlock(&cs->rtp_msg_mutex_lock);
			//printf("Audio packet sent\n");
			buffer_full=(samples_buffer_size>=frame_size*2)? 1:0;
		    }
		    av_free_packet(&cs->enc_audio_packet);
		}
	    } else {
	    av_free_packet(packet);
	    }
	}
	usleep(1000);
    }
    av_free(cs->enc_audio_frame);
    avcodec_close(cs->microphone_decoder_ctx);
    avcodec_close(cs->audio_encoder_ctx);
}


int video_decoder_refresh(call_state *cs, int width, int height)
{
    screen = SDL_SetVideoMode(width, height, 0, 0);
    if(cs->video_picture.bmp)
	  SDL_FreeYUVOverlay(cs->video_picture.bmp);
    cs->video_picture.bmp = SDL_CreateYUVOverlay(width,height,SDL_YV12_OVERLAY,screen);
    cs->sws_SDL_r_ctx = sws_getContext(width,height,cs->video_decoder_ctx->pix_fmt,width,height,PIX_FMT_YUV420P,SWS_BILINEAR,NULL,NULL,NULL);
    return 1;   
}

int decoder_handle_rtp_packet(call_state *cs)
{
  
    if(!cs->video_decoder_ctx)
	init_receive_video(cs);
    int type = rtp_header_get_setting_payload_type(cs->r_msg->_header);
    if(type!=96&&type!=106) {
	printf("Unknown packet type %d\n",type);
    }
    if(type==96)
	return type;
    if(cs->receive_video) {
	int width=rtp_get_resolution_marking_width(cs->r_msg->_ext_header);
	int height=rtp_get_resolution_marking_height(cs->r_msg->_ext_header);   
	if(cs->video_decoder_ctx->width!=width||cs->video_decoder_ctx->height!=height||!screen) {
	    video_decoder_refresh(cs,width,height);
	}
    }
    return type;  
}

void *decode_thread(void *arg)
{

    call_state *cs = (call_state *)arg;
    cs->video_stream=0;
    av_new_packet (&cs->dec_video_packet, 80000);
    av_new_packet (&cs->dec_audio_packet, 80000); 
    int frame_size=AUDIO_FRAME_SIZE;
      
    int data_size;
    
    cs->dev = alcOpenDevice(NULL);
    cs->ctx = alcCreateContext(cs->dev, NULL);
    alcMakeContextCurrent(cs->ctx);
    int openal_buffers=5;
    
    cs->buffers=malloc(sizeof(ALuint)*openal_buffers);
    alGenBuffers(openal_buffers, cs->buffers);
    alGenSources((ALuint)1, &cs->source);
    alSourcei(cs->source, AL_LOOPING, AL_FALSE);

    ALenum error;
    uint16_t zeros[frame_size];
    int i;
    for(i=0;i<frame_size;i++) {
	zeros[i]=0;
    }
    for(i=0;i<openal_buffers;++i) {
      alBufferData(cs->buffers[i], AL_FORMAT_MONO16, zeros, frame_size, 48000);
    }

    alSourceQueueBuffers(cs->source, openal_buffers, cs->buffers);
    alSourcePlay(cs->source);
    if(alGetError() != AL_NO_ERROR) {
	fprintf(stderr, "Error starting audio\n");
	cs->quit=1;
    }
    
    while(1) { 
	if(cs->quit) break;
	cs->r_msg = rtp_recv_msg ( cs->_m_session );
	if(cs-> r_msg) {
	      int type = decoder_handle_rtp_packet(cs);
	     if(type==106&&cs->receive_video) {
		memcpy(cs->dec_video_packet.data,cs->r_msg->_data,cs->r_msg->_length);
		cs->dec_video_packet.size=cs->r_msg->_length;
		avcodec_decode_video2(cs->video_decoder_ctx, cs->r_video_frame, &cs->dec_frame_finished, &cs->dec_video_packet);
		if(cs->dec_frame_finished) {
		    display_received_frame(cs);
		    rtp_free_msg(cs->_m_session, cs->r_msg);
		}
		else {
		    /* TODO: request the sender to create a new i-frame immediatly */
		    printf("freed video packet\n");
		    rtp_free_msg(cs->_m_session, cs->r_msg);
		}
	    }
	    if(type==96&&cs->receive_audio) {
		memcpy(cs->dec_audio_packet.data,cs->r_msg->_data,cs->r_msg->_length);
		cs->dec_audio_packet.size=cs->r_msg->_length;
		avcodec_decode_audio4(cs->audio_decoder_ctx, cs->audio_frame, &cs->dec_frame_finished, &cs->dec_audio_packet);
		if(cs->dec_frame_finished) {
		    ALuint buffer;
		    ALint val;
		    alGetSourcei(cs->source, AL_BUFFERS_PROCESSED, &val);
		    if(val <= 0)
			continue;

		    alSourceUnqueueBuffers(cs->source, 1, &buffer);
		    data_size = av_samples_get_buffer_size(NULL,cs->audio_frame->channels, cs->audio_frame->nb_samples, cs->audio_decoder_ctx->sample_fmt, 1);
		    alBufferData(buffer, AL_FORMAT_MONO16, cs->audio_frame->data[0], data_size, 48000);
		    int error=alGetError();
		    if(error != AL_NO_ERROR) {
			fprintf(stderr, "Error setting buffer %d\n",error);
			break;
		    }
		    alSourceQueueBuffers(cs->source, 1, &buffer);
		    if(alGetError() != AL_NO_ERROR) {
			fprintf(stderr, "error: could not buffer audio\n");
			break;
		    }
		    alGetSourcei(cs->source, AL_SOURCE_STATE, &val);
		    if(val != AL_PLAYING)
			alSourcePlay(cs->source);

		}
		rtp_free_msg(cs->_m_session, cs->r_msg);
	    }
	        
	}
	usleep(10000);
    }
    
    /* clean up codecs */
    av_free(cs->r_video_frame);
    av_free(cs->webcam_frame);
    av_free(cs->audio_frame);
    sws_freeContext(cs->sws_ctx);
    avcodec_close(cs->video_decoder_ctx);
    avcodec_close(cs->audio_decoder_ctx);

    /* clean up openal */
    alDeleteSources(1, &cs->source);
    alDeleteBuffers(6, cs->buffers);
    alcMakeContextCurrent(NULL);
    alcDestroyContext(cs->ctx);
    alcCloseDevice(cs->dev);
}
