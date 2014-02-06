/**  phone.c
 *
 *   NOTE NOTE NOTE NOTE NOTE NOTE 
 * 
 *   This file is for testing/reference purposes only, hence
 *   it is _poorly_ designed and it does not fully reflect the 
 *   quaility of msi nor rtp. Although toxmsi* and toxrtp* are tested 
 *   there is always possiblity of crashes. If crash occures, 
 *   contact me ( mannol ) on either irc channel #tox-dev @ freenode.net:6667 
 *   or eniz_vukovic@hotmail.com
 * 
 *   NOTE NOTE NOTE NOTE NOTE NOTE 
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <AL/al.h>
#include <AL/alc.h>
#include <SDL/SDL.h>
#include <SDL/SDL_thread.h>
#include <pthread.h>
#include <opus/opus.h>

#include "toxmsi.h"
#include "toxrtp.h"
#include "toxmedia.h"
#include "../toxcore/event.h"
#include "../toxcore/tox.h"

/* Define client version */
#define _USERAGENT "v.0.3.0"


struct SDL_Surface *screen;

typedef struct {
    struct SDL_Overlay *bmp;
    int width, height;
} VideoPicture;


typedef struct av_friend_s {
    int _id;
    int _active; /* 0=false; 1=true; */
} av_friend_t;

typedef struct av_session_s {
    MSISession* _msi;
    RTPSession* _rtp_audio;
    RTPSession* _rtp_video;

    /* Encoding/decoding/capturing/playing */
    
    codec_state* cs;
    VideoPicture    video_picture;    
    struct ALCdevice *audio_capture_device;
    
    /* context for converting image format to something SDL can use*/
    struct SwsContext   *sws_SDL_r_ctx;
    
    /* context for converting webcam image format to something the video encoder can use */
    struct SwsContext   *sws_ctx;
    
    /**/
    
    
    pthread_mutex_t _mutex;
    
    Tox* _messenger;
    av_friend_t*  _friends;
    int _friend_cout;
    char _my_public_id[200];
} av_session_t;


void av_allocate_friend(av_session_t* _phone, int _id, int _active)
{
    static int _new_id = 0;
    
    if ( !_phone->_friends ) {
        _phone->_friends = calloc(sizeof(av_friend_t), 1);
        _phone->_friend_cout = 1;
    } else{
        _phone->_friend_cout ++;
        _phone->_friends = realloc(_phone->_friends, sizeof(av_friend_t) * _phone->_friend_cout);
    }
    
    if ( _id == -1 ) {
        _phone->_friends->_id = _new_id;
        _new_id ++;
    } else _phone->_friends->_id = _id;
    
    _phone->_friends->_active = _active;
}
av_friend_t* av_get_friend(av_session_t* _phone, int _id)
{
    av_friend_t* _friends = _phone->_friends;
    
    if ( !_friends ) return NULL;
    
    int _it = 0;
    for (; _it < _phone->_friend_cout; _it ++)
        if ( _friends[_it]._id == _id ) 
            return _friends + _it;
    
    return NULL;
}


/***************** MISC *****************/

void INFO (const char* _format, ...)
{
    printf("\r[!] ");
    va_list _arg;
    va_start (_arg, _format);
    vfprintf (stdout, _format, _arg);
    va_end (_arg);
    printf("\n\r >> ");
    fflush(stdout);
}

unsigned char *hex_string_to_bin(char hex_string[])
{
    size_t i, len = strlen(hex_string);
    unsigned char *val = calloc(sizeof(unsigned char), len);
    char *pos = hex_string;
    
    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &val[i]);
    
    return val;
}

int getinput( char* _buff, size_t _limit, int* _len )
{
    if ( fgets(_buff, _limit, stdin) == NULL )
        return -1;
    
    *_len = strlen(_buff) - 1;
    
    /* Get rid of newline */
    _buff[*_len] = '\0';
    
    return 0;
}

char* trim_spaces ( char* buff )
{
    
    int _i = 0, _len = strlen(buff);
    
    char* container = calloc(sizeof(char), _len);
    int _ci = 0;
    
    for ( ; _i < _len; _i++ ) {
        while ( _i < _len && buff[_i] == ' ' )
            _i++;
        
        if ( _i < _len ){
            container[_ci] = buff[_i];
            _ci ++;
        }
    }
    
    memcpy( buff, container, _ci );
    buff[_ci] = '\0';
    free(container);
    return buff;
}

#define FRADDR_TOSTR_CHUNK_LEN 8

static void fraddr_to_str(uint8_t *id_bin, char *id_str)
{    
    uint i, delta = 0, pos_extra = 0, sum_extra = 0;
    
    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);
        
        if ((i + 1) == TOX_CLIENT_ID_SIZE)
            pos_extra = 2 * (i + 1) + delta;
        
        if (i >= TOX_CLIENT_ID_SIZE)
            sum_extra |= id_bin[i];
        
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
    }
    
    id_str[2 * i + delta] = 0;
    
    if (!sum_extra)
        id_str[pos_extra] = 0;
}

/*********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 */


/* 
 * How av stuff _should_ look like 
 */

int display_received_frame(av_session_t* _phone, AVFrame *r_video_frame)
{
    codec_state* cs = _phone->cs;
    AVPicture pict;
    SDL_LockYUVOverlay(_phone->video_picture.bmp);
    
    pict.data[0] = _phone->video_picture.bmp->pixels[0];
    pict.data[1] = _phone->video_picture.bmp->pixels[2];
    pict.data[2] = _phone->video_picture.bmp->pixels[1];
    pict.linesize[0] = _phone->video_picture.bmp->pitches[0];
    pict.linesize[1] = _phone->video_picture.bmp->pitches[2];
    pict.linesize[2] = _phone->video_picture.bmp->pitches[1];
    
    /* Convert the image into YUV format that SDL uses */
    sws_scale(_phone->sws_SDL_r_ctx, (uint8_t const * const *)r_video_frame->data, r_video_frame->linesize, 0,
              cs->video_decoder_ctx->height, pict.data, pict.linesize );
    
    SDL_UnlockYUVOverlay(_phone->video_picture.bmp);
    SDL_Rect rect;
    rect.x = 0;
    rect.y = 0;
    rect.w = cs->video_decoder_ctx->width;
    rect.h = cs->video_decoder_ctx->height;
    SDL_DisplayYUVOverlay(_phone->video_picture.bmp, &rect);
    return 1;
}

int video_encoder_refresh(codec_state *cs, int bps)
{
    if (cs->video_encoder_ctx)
        avcodec_close(cs->video_encoder_ctx);
    
    cs->video_encoder = avcodec_find_encoder(VIDEO_CODEC);
    
    if (!cs->video_encoder) {
        printf("init video_encoder failed\n");
        return -1;
    }
    
    cs->video_encoder_ctx = avcodec_alloc_context3(cs->video_encoder);
    
    if (!cs->video_encoder_ctx) {
        printf("init video_encoder_ctx failed\n");
        return -1;
    }
    
    cs->video_encoder_ctx->bit_rate = bps;
    cs->video_encoder_ctx->rc_min_rate = cs->video_encoder_ctx->rc_max_rate = cs->video_encoder_ctx->bit_rate;
    av_opt_set_double(cs->video_encoder_ctx->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(cs->video_encoder_ctx->priv_data, "quality", "realtime", 0);
    
    cs->video_encoder_ctx->thread_count = 4;
    cs->video_encoder_ctx->rc_buffer_aggressivity = 0.95;
    cs->video_encoder_ctx->rc_buffer_size = bps * 6;
    cs->video_encoder_ctx->profile = 0;
    cs->video_encoder_ctx->qmax = 54;
    cs->video_encoder_ctx->qmin = 4;
    AVRational myrational = {1, 25};
    cs->video_encoder_ctx->time_base = myrational;
    cs->video_encoder_ctx->gop_size = 99999;
    cs->video_encoder_ctx->pix_fmt = PIX_FMT_YUV420P;
    cs->video_encoder_ctx->width = cs->webcam_decoder_ctx->width;
    cs->video_encoder_ctx->height = cs->webcam_decoder_ctx->height;
    
    if (avcodec_open2(cs->video_encoder_ctx, cs->video_encoder, NULL) < 0) {
        printf("opening video encoder failed\n");
        return -1;
    }
    return 0;
}

int video_decoder_refresh(av_session_t* _phone, int width, int height)
{
    printf("need to refresh\n");
    screen = SDL_SetVideoMode(width, height, 0, 0);
    
    if (_phone->video_picture.bmp)
        SDL_FreeYUVOverlay(_phone->video_picture.bmp);
    
    _phone->video_picture.bmp = SDL_CreateYUVOverlay(width, height, SDL_YV12_OVERLAY, screen);
    _phone->sws_SDL_r_ctx = sws_getContext(width, height, _phone->cs->video_decoder_ctx->pix_fmt, width, height, PIX_FMT_YUV420P,
                                       SWS_BILINEAR, NULL, NULL, NULL);
    return 1;
}

void *encode_video_thread(void *arg)
{
    INFO("Started encode video thread!");
    
    av_session_t* _phone = arg;
    
    codec_state *cs = _phone->cs;
    AVPacket pkt1, *packet = &pkt1;
    int p = 0;
    int got_packet;
    int video_frame_finished;
    AVFrame *s_video_frame;
    AVFrame *webcam_frame;
    s_video_frame = avcodec_alloc_frame();
    webcam_frame = avcodec_alloc_frame();
    AVPacket enc_video_packet;
    
    uint8_t *buffer;
    int numBytes;
    /* Determine required buffer size and allocate buffer */
    numBytes = avpicture_get_size(PIX_FMT_YUV420P, cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height);
    buffer = (uint8_t *)av_calloc(numBytes * sizeof(uint8_t),1);
    avpicture_fill((AVPicture *)s_video_frame, buffer, PIX_FMT_YUV420P, cs->webcam_decoder_ctx->width,
                   cs->webcam_decoder_ctx->height);
    _phone->sws_ctx = sws_getContext(cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height,
                                 cs->webcam_decoder_ctx->pix_fmt, cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height, PIX_FMT_YUV420P,
                                 SWS_BILINEAR, NULL, NULL, NULL);
    
    while (cs->send_video) {
        
        if (av_read_frame(cs->video_format_ctx, packet) < 0) {
            printf("error reading frame\n");
            
            if (cs->video_format_ctx->pb->error != 0)
                break;
            
            continue;
        }
        
        if (packet->stream_index == cs->video_stream) {
            if (avcodec_decode_video2(cs->webcam_decoder_ctx, webcam_frame, &video_frame_finished, packet) < 0) {
                printf("couldn't decode\n");
                continue;
            }
            
            av_free_packet(packet);
            sws_scale(_phone->sws_ctx, (uint8_t const * const *)webcam_frame->data, webcam_frame->linesize, 0,
                      cs->webcam_decoder_ctx->height, s_video_frame->data, s_video_frame->linesize);
            /* create a new I-frame every 60 frames */
            ++p;
            
            if (p == 60) {
                
                s_video_frame->pict_type = AV_PICTURE_TYPE_BI ;
            } else if (p == 61) {
                s_video_frame->pict_type = AV_PICTURE_TYPE_I ;
                p = 0;
            } else {
                s_video_frame->pict_type = AV_PICTURE_TYPE_P ;
            }
            
            if (video_frame_finished) {
                
                if (avcodec_encode_video2(cs->video_encoder_ctx, &enc_video_packet, s_video_frame, &got_packet) < 0) {
                    printf("could not encode video frame\n");
                    continue;
                }
                
                if (!got_packet) {
                    continue;
                }
                                
                if (!enc_video_packet.data) fprintf(stderr, "video packet data is NULL\n");
                
                if ( 0 > rtp_send_msg ( _phone->_rtp_video, _phone->_messenger, enc_video_packet.data, enc_video_packet.size) ) {
                    printf("Failed sending message\n");
                }
                
                av_free_packet(&enc_video_packet);
            }
        } else {
            av_free_packet(packet);
        }
    }
    
    /* clean up codecs */
    pthread_mutex_lock(&cs->ctrl_mutex);
    av_free(buffer);
    av_free(webcam_frame);
    av_free(s_video_frame);
    sws_freeContext(_phone->sws_ctx);
    avcodec_close(cs->webcam_decoder_ctx);
    avcodec_close(cs->video_encoder_ctx);
    pthread_mutex_unlock(&cs->ctrl_mutex);
    pthread_exit ( NULL );
}

void *encode_audio_thread(void *arg)
{
    INFO("Started encode audio thread!");
    av_session_t* _phone = arg;
    
    codec_state *cs = _phone->cs;
    unsigned char encoded_data[4096];
    int encoded_size = 0;
    int16_t frame[4096];
    int frame_size = AUDIO_FRAME_SIZE;
    ALint sample = 0;
    alcCaptureStart((ALCdevice*)_phone->audio_capture_device);
    
    while (cs->send_audio) {
        alcGetIntegerv((ALCdevice*)_phone->audio_capture_device, ALC_CAPTURE_SAMPLES, (ALCsizei)sizeof(ALint), &sample);
        
        if (sample >= frame_size) {
            alcCaptureSamples((ALCdevice*)_phone->audio_capture_device, frame, frame_size);
            encoded_size = opus_encode(cs->audio_encoder, frame, frame_size, encoded_data, MAX_RTP_SIZE);
            
            if (encoded_size <= 0) {
                printf("Could not encode audio packet\n");
            } else {
                rtp_send_msg ( _phone->_rtp_audio, _phone->_messenger, encoded_data, encoded_size );
            }
        } else {
            usleep(1000);
        }
    }
    
    /* clean up codecs */
    pthread_mutex_lock(&cs->ctrl_mutex);
    alcCaptureStop((ALCdevice*)_phone->audio_capture_device);
    alcCaptureCloseDevice((ALCdevice*)_phone->audio_capture_device);    
    pthread_mutex_unlock(&cs->ctrl_mutex);
    pthread_exit ( NULL );
}

void *decode_video_thread(void *arg)
{
    INFO("Started decode video thread!");
    av_session_t* _phone = arg;
    
    codec_state *cs = _phone->cs;
    cs->video_stream = 0;
    RTPMessage *r_msg;
    int dec_frame_finished;
    AVFrame *r_video_frame;
    r_video_frame = avcodec_alloc_frame();
    AVPacket dec_video_packet;
    av_new_packet (&dec_video_packet, 65536);
    int width = 0;
    int height = 0;
    
    while (cs->receive_video) {
        r_msg = rtp_recv_msg ( _phone->_rtp_video );
        
        if (r_msg) {
            memcpy(dec_video_packet.data, r_msg->data, r_msg->length);
            dec_video_packet.size = r_msg->length;
            avcodec_decode_video2(cs->video_decoder_ctx, r_video_frame, &dec_frame_finished, &dec_video_packet);
            
            if (dec_frame_finished) {
                if (cs->video_decoder_ctx->width != width || cs->video_decoder_ctx->height != height) {
                    width = cs->video_decoder_ctx->width;
                    height = cs->video_decoder_ctx->height;
                    printf("w: %d h: %d \n", width, height);
                    video_decoder_refresh(_phone, width, height);
                }
                
                display_received_frame(_phone, r_video_frame);
            } else {
                /* TODO: request the sender to create a new i-frame immediatly */
                printf("Bad video packet\n");
            }
            
            rtp_free_msg(NULL, r_msg);
        }
        
        usleep(1000);
    }
    
    /* clean up codecs */
    pthread_mutex_lock(&cs->ctrl_mutex);
    av_free(r_video_frame);
    avcodec_close(cs->video_decoder_ctx);
    pthread_mutex_unlock(&cs->ctrl_mutex);
    pthread_exit ( NULL );
}

void *decode_audio_thread(void *arg)
{
    INFO("Started decode audio thread!");
    av_session_t* _phone = arg;
    
    codec_state *cs = _phone->cs;
    RTPMessage *r_msg;
    
    int frame_size = AUDIO_FRAME_SIZE;
    int data_size;
    
    ALCdevice *dev;
    ALCcontext *ctx;
    ALuint source, *buffers;
    dev = alcOpenDevice(NULL);
    ctx = alcCreateContext(dev, NULL);
    alcMakeContextCurrent(ctx);
    int openal_buffers = 5;
    
    buffers = calloc(sizeof(ALuint) * openal_buffers,1);
    alGenBuffers(openal_buffers, buffers);
    alGenSources((ALuint)1, &source);
    alSourcei(source, AL_LOOPING, AL_FALSE);
    
    ALuint buffer;
    ALint val;
    
    uint16_t zeros[frame_size];
    memset(zeros, 0, frame_size);
    opus_int16 PCM[frame_size];
    
    int i;
    for (i = 0; i < openal_buffers; ++i) {
        alBufferData(buffers[i], AL_FORMAT_MONO16, zeros, frame_size, 48000);
    }
    
    alSourceQueueBuffers(source, openal_buffers, buffers);
    alSourcePlay(source);
    
    if (alGetError() != AL_NO_ERROR) {
        fprintf(stderr, "Error starting audio\n");
        goto ending;
    }
    
    struct jitter_buffer *j_buf = NULL;
    
    j_buf = create_queue(20);
    
    int success = 0;
    
    int dec_frame_len = 0;
    
    
    while (cs->receive_audio) {
        
        r_msg = rtp_recv_msg ( _phone->_rtp_audio );
        
        if (r_msg) {
            /* push the packet into the queue */
            queue(j_buf, r_msg);
        }
        
        success = 0;
        alGetSourcei(source, AL_BUFFERS_PROCESSED, &val);
        
        /* grab a packet from the queue */
        if (val > 0) {
            r_msg = dequeue(j_buf, &success);
        }
        
        if (success > 0) {
            /* good packet */
            if (success == 1) {
                dec_frame_len = opus_decode(cs->audio_decoder, r_msg->data, r_msg->length, PCM, frame_size, 0);
                rtp_free_msg(NULL, r_msg);
            }
            
            /* lost packet  */
            else if (success == 2) {
                printf("Lost packet\n");
                dec_frame_len = opus_decode(cs->audio_decoder, NULL, 0, PCM, frame_size, 1);
            }
            
            if (dec_frame_len) {
                alGetSourcei(source, AL_BUFFERS_PROCESSED, &val);
                
                if (val <= 0)
                    continue;
                
                alSourceUnqueueBuffers(source, 1, &buffer);
                data_size = av_samples_get_buffer_size(NULL, 1, dec_frame_len, AV_SAMPLE_FMT_S16, 1);
                alBufferData(buffer, AL_FORMAT_MONO16, PCM, data_size, 48000);
                int error = alGetError();
                
                if (error != AL_NO_ERROR) {
                    fprintf(stderr, "Error setting buffer %d\n", error);
                    break;
                }
                
                alSourceQueueBuffers(source, 1, &buffer);
                
                if (alGetError() != AL_NO_ERROR) {
                    fprintf(stderr, "Error: could not buffer audio\n");
                    break;
                }
                
                alGetSourcei(source, AL_SOURCE_STATE, &val);
                
                if (val != AL_PLAYING)
                    alSourcePlay(source);
                
                
            }
        }
        
        usleep(1000);
    }
    
    
ending:
    /* clean up codecs */
    pthread_mutex_lock(&cs->ctrl_mutex);    
    
    alDeleteSources(1, &source);
    alDeleteBuffers(openal_buffers, buffers);
    alcMakeContextCurrent(NULL);
    alcDestroyContext(ctx);
    alcCloseDevice(dev);
    
    pthread_mutex_unlock(&cs->ctrl_mutex);
    pthread_exit ( NULL );
}





int phone_startmedia_loop ( av_session_t* _phone )
{
    if ( !_phone ){
        return -1;
    }
    
    _phone->_rtp_audio = rtp_init_session ( 
    type_audio,
    _phone->_messenger, 
    _phone->_msi->call->peers[0],
    _phone->_msi->call->key_peer,
    _phone->_msi->call->key_local,
    _phone->_msi->call->nonce_peer,
    _phone->_msi->call->nonce_local
    );
    
    _phone->_rtp_video = rtp_init_session ( 
    type_video,
    _phone->_messenger, 
    _phone->_msi->call->peers[0],
    _phone->_msi->call->key_peer,
    _phone->_msi->call->key_local,
    _phone->_msi->call->nonce_peer,
    _phone->_msi->call->nonce_local
    );
        
    init_encoder(_phone->cs);
    init_decoder(_phone->cs);
    
    /* 
     * Rise all threads
     */
    
    /* Only checks for last peer */
    if ( _phone->_msi->call->type_peer[0] == type_video && 0 > event.rise(encode_video_thread, _phone) )
    {
        INFO("Error while starting encode_video_thread()");
        return -1;
    }
    
    /* Always send audio */
    if ( 0 > event.rise(encode_audio_thread, _phone) )
    {
        INFO("Error while starting encode_audio_thread()");
        return -1;
    }
    
    /* Only checks for last peer */
    if ( _phone->_msi->call->type_peer[0] == type_video && 0 > event.rise(decode_video_thread, _phone) )
    {
        INFO("Error while starting decode_video_thread()");
        return -1;
    }
    
    if ( 0 > event.rise(decode_audio_thread, _phone) )
    {
        INFO("Error while starting decode_audio_thread()");
        return -1;
    }
    
    
    return 0;
}






/*********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 *********************************************
 */


/* Some example callbacks */

void* callback_recv_invite ( void* _arg )
{
    MSISession* _msi = _arg;

    switch ( _msi->call->type_peer[_msi->call->peer_count - 1] ){
    case type_audio:
        INFO( "Incoming audio call!");
        break;
    case type_video:
        INFO( "Incoming video call!");
        break;
    }

    pthread_exit(NULL);
}
void* callback_recv_ringing ( void* _arg )
{
    INFO ( "Ringing!" );
    pthread_exit(NULL);
}
void* callback_recv_starting ( void* _arg )
{
    MSISession* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }
    pthread_exit(NULL);
}
void* callback_recv_ending ( void* _arg )
{
    av_session_t* _phone = ((MSISession*)_arg)->agent_handler;
    
    _phone->cs->send_audio = 0;
    _phone->cs->send_video = 0;
    _phone->cs->receive_audio = 0;
    _phone->cs->receive_video = 0;
    
    /* Wait until all threads are done */
    usleep(10000000);
    
    INFO ( "Call ended!" );
    pthread_exit(NULL);
}

void* callback_recv_error ( void* _arg )
{
    MSISession* _session = _arg;

    INFO( "Error: %s", _session->last_error_str );
    pthread_exit(NULL);
}

void* callback_call_started ( void* _arg )
{
    MSISession* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }
    
    pthread_exit(NULL);
}
void* callback_call_canceled ( void* _arg )
{
    INFO ( "Call canceled!" );
    pthread_exit(NULL);
}
void* callback_call_rejected ( void* _arg )
{
    INFO ( "Call rejected!" );
    pthread_exit(NULL);
}
void* callback_call_ended ( void* _arg )
{
    av_session_t* _phone = ((MSISession*)_arg)->agent_handler;
    
    _phone->cs->send_audio = 0;
    _phone->cs->send_video = 0;
    _phone->cs->receive_audio = 0;
    _phone->cs->receive_video = 0;
    
    /* Wait until all threads are done */
    usleep(10000000);
    
    INFO ( "Call ended!" );
    pthread_exit(NULL);
}

void* callback_requ_timeout ( void* _arg )
{
    INFO( "No answer! " );
    pthread_exit(NULL);
}

av_session_t* av_init_session()
{
    av_session_t* _retu = malloc(sizeof(av_session_t));
    
    /* Initialize our mutex */
    pthread_mutex_init ( &_retu->_mutex, NULL );

    _retu->_messenger = tox_new(1);
    
    if ( !_retu->_messenger ) {
        fprintf ( stderr, "tox_new() failed!\n" );
        return NULL;
    }

    _retu->_friends = NULL;
    
    _retu->_rtp_audio = NULL;
    _retu->_rtp_video = NULL;
    
    
    const ALchar *_device_list = alcGetString(NULL, ALC_CAPTURE_DEVICE_SPECIFIER);
    int i = 0;
    const ALchar *device_names[20];
    
    if ( _device_list ) {
        INFO("\nAvailable Capture Devices are:");
        
        while (*_device_list ) {
            device_names[i] = _device_list;
            INFO("%d) %s", i, device_names[i]);
            _device_list += strlen( _device_list ) + 1;
            ++i;
        }
    }
    
    INFO("Enter capture device number");
    
    char dev[2]; char* left;
    fgets(dev, 2, stdin);
    long selection = strtol(dev, &left, 10);
    
    if ( *left ) {
        printf("'%s' is not a number!", dev);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    else {
        INFO("Selected: %d ( %s )", selection, device_names[selection]);
    }
    
    _retu->cs = av_calloc(sizeof(codec_state), 1);
    
    _retu->audio_capture_device = 
        (struct ALCdevice*)alcCaptureOpenDevice(
            device_names[selection], AUDIO_SAMPLE_RATE, AL_FORMAT_MONO16, AUDIO_FRAME_SIZE * 4);
    
        
    if (alcGetError((ALCdevice*)_retu->audio_capture_device) != AL_NO_ERROR) {
        printf("Could not start capture device! %d\n", alcGetError((ALCdevice*)_retu->audio_capture_device));
        return 0;
    }
        
    
    uint8_t _byte_address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(_retu->_messenger, _byte_address );
    fraddr_to_str( _byte_address, _retu->_my_public_id );
    
    
    /* Initialize msi */
    _retu->_msi = msi_init_session ( _retu->_messenger, (const uint8_t*)_USERAGENT );

    if ( !_retu->_msi ) {
        fprintf ( stderr, "msi_init_session() failed\n" );
        return NULL;
    }

    _retu->_msi->agent_handler = _retu;

    /* ------------------ */
    msi_register_callback(callback_call_started, MSI_OnStart);
    msi_register_callback(callback_call_canceled, MSI_OnCancel);
    msi_register_callback(callback_call_rejected, MSI_OnReject);
    msi_register_callback(callback_call_ended, MSI_OnEnd);
    msi_register_callback(callback_recv_invite, MSI_OnInvite);

    msi_register_callback(callback_recv_ringing, MSI_OnRinging);
    msi_register_callback(callback_recv_starting, MSI_OnStarting);
    msi_register_callback(callback_recv_ending, MSI_OnEnding);

    msi_register_callback(callback_recv_error, MSI_OnError);
    msi_register_callback(callback_requ_timeout, MSI_OnTimeout);
    /* ------------------ */

    return _retu;
}

int av_terminate_session(av_session_t* _phone)
{
    if ( _phone->_msi->call ){
        msi_hangup(_phone->_msi); /* Hangup the phone first */
    }
    
    free(_phone->_friends);
    msi_terminate_session(_phone->_msi);
    pthread_mutex_destroy ( &_phone->_mutex );
    
    Tox* _p = _phone->_messenger;
    _phone->_messenger = NULL; usleep(100000); /* Wait for tox_pool to end */
    tox_kill(_p);
    
    printf("\r[i] Quit!\n");
    return 0;
}

/****** AV HELPER FUNCTIONS ******/

/* Auto accept friend request */
void av_friend_requ(uint8_t *_public_key, uint8_t *_data, uint16_t _length, void *_userdata)
{
    av_session_t* _phone = _userdata;
    av_allocate_friend (_phone, -1, 0);
    
    INFO("Got friend request with message: %s", _data);
    
    tox_add_friend_norequest(_phone->_messenger, _public_key);
    
    INFO("Auto-accepted! Friend id: %d",  _phone->_friends->_id );
}

void av_friend_active(Tox *_messenger, int _friendnumber, uint8_t *_string, uint16_t _length, void *_userdata)
{
    av_session_t* _phone = _userdata;
    INFO("Friend no. %d is online", _friendnumber);
    
    av_friend_t* _this_friend = av_get_friend(_phone, _friendnumber);
    
    if ( !_this_friend ) {
        INFO("But it's not registered!");
        return;
    }
    
    (*_this_friend)._active = 1;
}

int av_add_friend(av_session_t* _phone, char* _friend_hash)
{    
    trim_spaces(_friend_hash);
    
    unsigned char *_bin_string = hex_string_to_bin(_friend_hash);
    int _number = tox_add_friend(_phone->_messenger, _bin_string, (uint8_t *)"Tox phone "_USERAGENT, sizeof("Tox phone "_USERAGENT));
    free(_bin_string);
    
    if ( _number >= 0) {
        INFO("Added friend as %d", _number );
        av_allocate_friend(_phone, _number, 0);
    }
    else
        INFO("Unknown error %i", _number );
    
    return _number;
}

int av_connect_to_dht(av_session_t* _phone, char* _dht_key, const char* _dht_addr, unsigned short _dht_port)
{
    unsigned char *_binary_string = hex_string_to_bin(_dht_key);
    
    uint16_t _port = htons(_dht_port);
    
    int _if = tox_bootstrap_from_address(_phone->_messenger, _dht_addr, 1, _port, _binary_string );
    
    free(_binary_string);
    
    return _if ? 0 : -1;
}

/*********************************/

void do_phone ( av_session_t* _phone )
{
    INFO("Welcome to tox_phone version: " _USERAGENT "\n"
         "Usage: \n"
         "f [pubkey] (add friend)\n"
         "c [a/v] (type) [friend] (friend id) (calls friend if online)\n"
         "h (if call is active hang up)\n"
         "a [a/v] (answer incoming call: a - audio / v - audio + video (audio is default))\n"
         "r (reject incoming call)\n"
         "q (quit)\n"
         "================================================================================"
         );
    
    while ( 1 )
    {        
        char _line [ 1500 ];
        int _len;
        
        if ( -1 == getinput(_line, 1500, &_len) ){
            printf(" >> "); 
            fflush(stdout);
            continue;
        }
        
        if ( _len > 1 && _line[1] != ' ' && _line[1] != '\n' ){
            INFO("Invalid input!");
            continue;
        }

        switch (_line[0]){

        case 'f':
        {
            char _id [128];
            strncpy(_id, _line + 2, 128);            
            
            av_add_friend(_phone, _id);
                    
        } break;
        case 'c':
        {
            if ( _phone->_msi->call ){
                INFO("Already in a call");
                break;
            }
            
            MSICallType _ctype;
            
            if ( _len < 5 ){
                INFO("Invalid input; usage: c a/v [friend]");
                break;
            }
            else if ( _line[2] == 'a' || _line[2] != 'v' ){ /* default and audio */
                _ctype = type_audio;
            }
            else { /* video */
                _ctype = type_video;
            }
            
            char* _end;
            int _friend = strtol(_line + 4, &_end, 10);
            
            if ( *_end ){
                INFO("Friend num has to be numerical value");
                break;
            }
            
            /* Set timeout */
            msi_invite ( _phone->_msi, _ctype, 10 * 1000, _friend );
            INFO("Calling friend: %d!", _friend);

        } break;
        case 'h':
        {
            if ( !_phone->_msi->call ){
                INFO("No call!");
                break;
            }

            msi_hangup(_phone->_msi);

            INFO("Hung up...");

        } break;
        case 'a':
        {

            if ( _phone->_msi->call && _phone->_msi->call->state != call_starting ) {
                break;
            }

            if ( _len > 1 && _line[2] == 'v' )
                msi_answer(_phone->_msi, type_video);
            else
                msi_answer(_phone->_msi, type_audio);

        } break;
        case 'r':
        {
            if ( _phone->_msi->call && _phone->_msi->call->state != call_starting ){
                break;
            }

            msi_reject(_phone->_msi, NULL);

            INFO("Call Rejected...");

        } break;
        case 'q':
        {
            INFO("Quitting!");
            return;
        }
        case '\n':
        {
        }
        default:
        {
            INFO("Invalid command!");
        } break;

        }

    }
}

void* tox_poll (void* _messenger_p)
{
    Tox** _messenger = _messenger_p;
    while( *_messenger ) { 
        tox_do(*_messenger); 
        usleep(10000);
    }
        
    pthread_exit(NULL);
}

int av_wait_dht(av_session_t* _phone, int _wait_seconds, const char* _ip, char* _key, unsigned short _port)
{
    if ( !_wait_seconds )
        return -1;
    
    int _waited = 0;
    
    while( !tox_isconnected(_phone->_messenger) ) {
        
        if ( -1 == av_connect_to_dht(_phone, _key, _ip, _port) )
        {
            INFO("Could not connect to: %s", _ip);
            av_terminate_session(_phone);
            return -1;
        }
        
        if ( _waited >= _wait_seconds ) return 0;
        
        printf(".");
        fflush(stdout);
        
        _waited ++;
        usleep(1000000);
    }
    
    int _r = _wait_seconds - _waited;
    return _r ? _r : 1;
}
/* ---------------------- */

int print_help ( const char* _name )
{
    printf ( "Usage: %s [IP] [PORT] [KEY]\n" 
	     "\t[IP] (DHT ip)\n"
	     "\t[PORT] (DHT port)\n"
	     "\t[KEY] (DHT public key)\n"
	     "P.S. Friends and key are stored in ./tox_phone.conf\n"
	     ,_name );
    return 1;
}

int main ( int argc, char* argv [] )
{
    if ( argc < 1 || argc < 4 )
	return print_help(argv[0]);
    
    char* _convertable;
    
    
    const char* _ip = argv[1];
    char* _key = argv[3];
    unsigned short _port = strtol(argv[2], &_convertable, 10);
    
    if ( *_convertable ) {
	printf("Invalid port: cannot convert string to long: %s", _convertable);
	return 1;
    }
    
    av_session_t* _phone = av_init_session();
    
    tox_callback_friend_request(_phone->_messenger, av_friend_requ, _phone);
    tox_callback_status_message(_phone->_messenger, av_friend_active, _phone);

    
    INFO("\r================================================================================\n"
         "[!] Trying dht@%s:%d"
         , _ip, _port);
    
    /* Start tox protocol */
    event.rise( tox_poll, &_phone->_messenger );
    
    /* Just clean one line */
    printf("\r       \r");
    fflush(stdout);
    
    int _r;
    int _wait_seconds = 5;
    for ( _r = 0; _r == 0; _r = av_wait_dht(_phone, _wait_seconds, _ip, _key, _port) ) _wait_seconds --;
    
        
    if ( -1 == _r ) {
        INFO("Error while connecting to dht: %s:%d", _ip, _port);
        av_terminate_session(_phone);
        return 1;
    }
    
    INFO("CONNECTED!\n"
         "================================================================================\n"
         "%s\n"
         "================================================================================"
         , _phone->_my_public_id );

    
    do_phone (_phone);
    
    av_terminate_session(_phone);
    
    return 0;
}
