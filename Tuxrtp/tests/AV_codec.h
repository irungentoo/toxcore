#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavdevice/avdevice.h>
#include <libavutil/opt.h>

#include <SDL.h>
#include <SDL_thread.h>

#ifdef __MINGW32__
#undef main /* Prevents SDL from overriding main() */
#endif

#include <stdio.h>

#define FF_QUIT_EVENT (SDL_USEREVENT + 2)

#ifdef __linux__
#define DRIVER "video4linux2"
#define DEFAULT_WEBCAM "/dev/video0"
#endif

#define CODEC           AV_CODEC_ID_VP8
#define BITRATE         5000*1000
SDL_Surface     *screen;


typedef struct VideoPicture
{
    SDL_Overlay *bmp;
    int width, height;
}VideoPicture;


typedef struct VideoState
{
    AVFormatContext *pFormatCtx;
    int              videoStream;
    AVInputFormat   *pIFormat;

    AVCodecContext  *webcam_decoder_ctx;
    AVCodec         *webcam_decoder;

    AVCodecContext  *pECodecCtx2;
    AVCodec         *pECodec2;

    AVCodecContext  *pDCodecCtx2;
    AVCodec         *pDCodec2;

    AVFrame         *pFrameWebcam;
    AVFrame         *pDFrame;
    AVPacket        packet;
    AVPacket        encoded_packet;

    int             frameFinished;
    AVDictionary    *optionsDict;
    struct SwsContext *sws_ctx;
    VideoPicture VP;
    SDL_Thread      *parse_tid;
    rtp_msg_t*     _m_msg;
    rtp_session_t* _m_session;
    int             quit;
}VideoState;


int display_frame(VideoState *is)
{
    AVPicture pict;
    SDL_LockYUVOverlay(is->VP.bmp);

    pict.data[0] = is->VP.bmp->pixels[0];
    pict.data[1] = is->VP.bmp->pixels[2];
    pict.data[2] = is->VP.bmp->pixels[1];
    pict.linesize[0] = is->VP.bmp->pitches[0];
    pict.linesize[1] = is->VP.bmp->pitches[2];
    pict.linesize[2] = is->VP.bmp->pitches[1];

    //Convert the image into YUV format that SDL uses
    sws_scale(is->sws_ctx, (uint8_t const * const *)is->pDFrame->data, is->pDFrame->linesize, 0, is->pDCodecCtx2->height, pict.data, pict.linesize );

    SDL_UnlockYUVOverlay(is->VP.bmp);
    SDL_Rect rect;
    rect.x = 0;
    rect.y = 0;
    rect.w = is->pDCodecCtx2->width;
    rect.h = is->pDCodecCtx2->height;
    SDL_DisplayYUVOverlay(is->VP.bmp, &rect);
    return 1;
}


int encode_frame(VideoState *is)
{
    int got_packet_ptr=0;
    avcodec_encode_video2(is->pECodecCtx2,&is->packet,is->pFrameWebcam,&got_packet_ptr);
    return 1;
}


int decode_frame(VideoState *is)
{
    avcodec_decode_video2(is->pDCodecCtx2, is->pDFrame, &is->frameFinished, &is->packet);
    return 1;
}


int encode_thread(void *arg)
{
    VideoState *is = (VideoState *)arg;
    AVPacket pkt1, *packet = &pkt1;
    SDL_Event       event;
    is->videoStream=0;

    while(1)
    {
        if(is->quit) break;

        if(av_read_frame(is->pFormatCtx, packet) < 0)
        {
            if(is->pFormatCtx->pb->error != 0)
            break;
        }

        /* Is this a packet from the video stream? */
        if(packet->stream_index == is->videoStream)
        {
            avcodec_decode_video2(is->webcam_decoder_ctx, is->pFrameWebcam, &is->frameFinished, packet);
            if(is->frameFinished)
            {
                encode_frame(is);
                is->_m_msg = rtp_msg_new ( is->_m_session, is->packet.data, is->packet.size, NULL ) ;
                printf("%d\n",is->packet.size);
                rtp_send_msg ( is->_m_session, is->_m_msg );
                av_free_packet(&is->packet);
                av_free_packet(packet);
            }
        }
        else
        {
            av_free_packet(packet);
        }
    }

    event.type = FF_QUIT_EVENT;
    event.user.data1 = is;
    SDL_PushEvent(&event);
    return 0;
}


int decode_thread(void *arg)
{
    VideoState *is = (VideoState *)arg;
    is->videoStream=0;
    av_new_packet (&is->packet, 50000);

    while(1)
    {
        if(is->quit) break;
        is->_m_msg = rtp_recv_msg ( is->_m_session );
        if(is-> _m_msg)
        {
            // av_packet_from_data(is->packet,is->_m_msg->_data,is->_m_msg->_length);
            memcpy(is->packet.data,is->_m_msg->_data,is->_m_msg->_length);
            is->packet.size=is->_m_msg->_length;
            avcodec_decode_video2(is->pDCodecCtx2, is->pDFrame, &is->frameFinished, &is->packet);
            if(is->frameFinished)
            {
                printf("frame finished!\n");
                display_frame(is);
                rtp_free_msg(is->_m_session, is->_m_msg);
            }
            else
            {
                av_free_packet(&is->packet);
                printf("freed packet\n");
            }
        }
    }

    return 0;
}


int init_webcam_decoder(VideoState *is)
{
    av_register_all();
    avdevice_register_all();
    is->pIFormat=av_find_input_format(DRIVER);
    if(avformat_open_input(&is->pFormatCtx,DEFAULT_WEBCAM, is->pIFormat, NULL)!=0)
    return -1;
    avformat_find_stream_info(is->pFormatCtx, NULL);
    av_dump_format(is->pFormatCtx, 0, DEFAULT_WEBCAM, 0);

    int i;
    for(i=0; i<is->pFormatCtx->nb_streams; i++)
    {
    if(is->pFormatCtx->streams[i]->codec->codec_type==AVMEDIA_TYPE_VIDEO) {
      is->videoStream=i;
      break;
    }
    }
    printf("Streams: %d Video stream = %d\n",is->pFormatCtx->nb_streams,is->videoStream);
    is->webcam_decoder_ctx=is->pFormatCtx->streams[is->videoStream]->codec;
    is->webcam_decoder=avcodec_find_decoder(is->webcam_decoder_ctx->codec_id);
    if(is->webcam_decoder==NULL)
    {
        fprintf(stderr, "Unsupported codec!\n");
        return -1;
    }
    if(is->webcam_decoder_ctx==NULL)
    {
        fprintf(stderr, "webcam_decoder_ctx failed!\n");
        return -1;
    }

    avcodec_open2(is->webcam_decoder_ctx, is->webcam_decoder, NULL);
    return 1;
}


int init_encoder(VideoState *is)
{
    av_register_all();
    avdevice_register_all();
    avcodec_register_all();
    is->pECodec2 = avcodec_find_encoder(CODEC);
    if(!is->pECodec2){printf("init pECodec2 failed\n");}
    is->pECodecCtx2 = avcodec_alloc_context3(is->pECodec2);
    if(!is->pECodecCtx2){printf("init pECodecCtx2 failed\n");}
    is->pECodecCtx2->bit_rate = BITRATE;
    is->pECodecCtx2->rc_min_rate = is->pECodecCtx2->rc_max_rate = is->pECodecCtx2->bit_rate;
    av_opt_set_double(is->pECodecCtx2->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(is->pECodecCtx2->priv_data, "quality", "realtime", 0);
    is->pECodecCtx2->thread_count = 4;
    is->pECodecCtx2->rc_buffer_aggressivity = 0.95;
    is->pECodecCtx2->rc_buffer_size = BITRATE*6;
    is->pECodecCtx2->profile = 3;
    is->pECodecCtx2->qmax = 54;
    is->pECodecCtx2->qmin = 4;
    AVRational myrational = {1,25};
    is->pECodecCtx2->time_base= myrational;
    is->pECodecCtx2->gop_size = 99999;
    //is->pECodecCtx2->pix_fmt = PIX_FMT_YUV420P;
    is->pECodecCtx2->pix_fmt = is->webcam_decoder_ctx->pix_fmt;
    is->pECodecCtx2->width = is->webcam_decoder_ctx->width;
    is->pECodecCtx2->height = is->webcam_decoder_ctx->height;
    avcodec_open2(is->pECodecCtx2,is->pECodec2,NULL);
    return 1;
}


int init_decoder(VideoState *is)
{
    avdevice_register_all();
    avcodec_register_all();
    av_register_all();
    is->pDCodec2 = avcodec_find_decoder(CODEC);
    is->pDCodecCtx2 = avcodec_alloc_context3(is->pDCodec2);
    avcodec_open2(is->pDCodecCtx2,is->pDCodec2,NULL);
    return 1;
}
