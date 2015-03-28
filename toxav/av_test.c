#include "toxav.h"
#include "../toxcore/tox.h"

/* For playing audio data */
#include <AL/al.h>
#include <AL/alc.h>

/* Processing wav's */
#include <sndfile.h>

/* For reading and displaying video data */
#include <opencv/cv.h>
#include <opencv/highgui.h>

/* For converting images TODO remove */
#include <vpx/vpx_image.h>


#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>


#define c_sleep(x) usleep(1000*x)


/* Enable/disable tests */
#define TEST_REGULAR_AV 0
#define TEST_REGULAR_A 0
#define TEST_REGULAR_V 0
#define TEST_REJECT 0
#define TEST_CANCEL 0
#define TEST_MUTE_UNMUTE 0
#define TEST_TRANSFER_A 1
#define TEST_TRANSFER_V 0


typedef struct {
    bool incoming;
    uint32_t state;
} CallControl;

const char* vdout = "AV Test";
uint32_t adout;

const char* stringify_state(TOXAV_CALL_STATE s)
{
    static const char* strings[] =
    {
        "NOT SENDING",
        "SENDING AUDIO",
        "SENDING VIDEO",
        "SENDING AUDIO AND VIDEO",
        "PAUSED",
        "END",
        "ERROR"
    };
    
    return strings [s];
}

/** 
 * Callbacks 
 */
void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    printf("Handling CALL callback\n");
    ((CallControl*)user_data)->incoming = true;
}
void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %d\n", state);
    
    ((CallControl*)user_data)->state = state;
}
void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
                                    uint16_t width, uint16_t height,
                                    uint8_t const *planes[], int32_t const stride[],
                                    void *user_data)
{
    IplImage output_img;
    const int bpl = stride[VPX_PLANE_Y];
    const int cxbpl = stride[VPX_PLANE_V];
    
    output_img.imageData = malloc(width * height * 3);
    output_img.imageSize = width * height * 3;
    output_img.width = width;
    output_img.height = height;
    
    /* FIXME: possible bug? */
    const uint8_t* yData = planes[VPX_PLANE_Y];
    const uint8_t* uData = planes[VPX_PLANE_V];
    const uint8_t* vData = planes[VPX_PLANE_U];
    
    // convert from planar to packed
    int y = 0;
    for (; y < height; ++y)
    {
        int x = 0;
        for (; x < width; ++x)
        {
            uint8_t Y = planes[VPX_PLANE_Y][x + y * bpl];
            uint8_t U = planes[VPX_PLANE_V][x/(1 << 1) + y/(1 << 1)*cxbpl];
            uint8_t V = planes[VPX_PLANE_U][x/(1 << 1) + y/(1 << 1)*cxbpl];
            output_img.imageData[width * 3 * y + x * 3 + 0] = Y;
            output_img.imageData[width * 3 * y + x * 3 + 1] = U;
            output_img.imageData[width * 3 * y + x * 3 + 2] = V;
        }
    }
    
    cvShowImage(vdout, &output_img);
    free(output_img.imageData);
}
void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
                                    int16_t const *pcm,
                                    size_t sample_count,
                                    uint8_t channels,
                                    uint32_t sampling_rate,
                                    void *user_data)
{
    uint32_t bufid;
    int32_t processed, queued;
    alGetSourcei(adout, AL_BUFFERS_PROCESSED, &processed);
    alGetSourcei(adout, AL_BUFFERS_QUEUED, &queued);

    if(processed) {
        uint32_t bufids[processed];
        alSourceUnqueueBuffers(adout, processed, bufids);
        alDeleteBuffers(processed - 1, bufids + 1);
        bufid = bufids[0];
    }
//     else if(queued < 16)
        alGenBuffers(1, &bufid);
//     else
//         return;
    

    alBufferData(bufid, channels == 2 ? AL_FORMAT_STEREO16 : AL_FORMAT_MONO16, 
                 pcm, sample_count * channels * 2, sampling_rate);
    alSourceQueueBuffers(adout, 1, &bufid);

    int32_t state;
    alGetSourcei(adout, AL_SOURCE_STATE, &state);

    if(state != AL_PLAYING) 
        alSourcePlay(adout);
}
void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/**
 */
void initialize_tox(Tox** bootstrap, ToxAV** AliceAV, CallControl* AliceCC, ToxAV** BobAV, CallControl* BobCC)
{
    Tox* Alice;
    Tox* Bob;
    
    *bootstrap = tox_new(0);
    Alice = tox_new(0);
    Bob = tox_new(0);
    
    assert(bootstrap && Alice && Bob);
    
    printf("Created 3 instances of Tox\n");
    
    printf("Preparing network...\n");
    long long unsigned int cur_time = time(NULL);
    
    uint32_t to_compare = 974536;
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    
    tox_callback_friend_request(Alice, t_accept_friend_request_cb, &to_compare);
    tox_get_address(Alice, address);
    
    assert(tox_add_friend(Bob, address, (uint8_t *)"gentoo", 7) >= 0);
    
    uint8_t off = 1;
    
    while (1) {
        tox_do(*bootstrap);
        tox_do(Alice);
        tox_do(Bob);
        
        if (tox_isconnected(*bootstrap) && tox_isconnected(Alice) && tox_isconnected(Bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }
        
        if (tox_get_friend_connection_status(Alice, 0) == 1 && tox_get_friend_connection_status(Bob, 0) == 1)
            break;
        
        c_sleep(20);
    }
    
    
    TOXAV_ERR_NEW rc;
    *AliceAV = toxav_new(Alice, &rc);
    assert(rc == TOXAV_ERR_NEW_OK);
    
    *BobAV = toxav_new(Bob, &rc);
    assert(rc == TOXAV_ERR_NEW_OK);
    
    /* Alice */
    toxav_callback_call(*AliceAV, t_toxav_call_cb, AliceCC);
    toxav_callback_call_state(*AliceAV, t_toxav_call_state_cb, AliceCC);
    toxav_callback_receive_video_frame(*AliceAV, t_toxav_receive_video_frame_cb, AliceCC);
    toxav_callback_receive_audio_frame(*AliceAV, t_toxav_receive_audio_frame_cb, AliceCC);
    
    /* Bob */
    toxav_callback_call(*BobAV, t_toxav_call_cb, BobCC);
    toxav_callback_call_state(*BobAV, t_toxav_call_state_cb, BobCC);
    toxav_callback_receive_video_frame(*BobAV, t_toxav_receive_video_frame_cb, BobCC);
    toxav_callback_receive_audio_frame(*BobAV, t_toxav_receive_audio_frame_cb, BobCC);
    
    printf("Created 2 instances of ToxAV\n");
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);
}
int iterate_tox(Tox* bootstrap, ToxAV* AliceAV, ToxAV* BobAV)
{
    tox_do(bootstrap);
    tox_do(toxav_get_tox(AliceAV));
    tox_do(toxav_get_tox(BobAV));
    
    toxav_iterate(AliceAV);
    toxav_iterate(BobAV);
    
	int mina = MIN(tox_do_interval(toxav_get_tox(AliceAV)), toxav_iteration_interval(AliceAV));
	int minb = MIN(tox_do_interval(toxav_get_tox(BobAV)), toxav_iteration_interval(BobAV));
	
    int rc = MIN(mina, minb);
	c_sleep(rc);
    
    return rc;
}

int send_opencv_img(ToxAV* av, uint32_t friend_number, const IplImage* img)
{
    /* I use vpx image coz i'm noob TODO use opencv conversion */
    vpx_image_t vpx_img;
    vpx_img.w = vpx_img.h = vpx_img.d_w = vpx_img.d_h = 0;
    
    const int w = img->width;
    const int h = img->height;
    
    vpx_img_alloc(&vpx_img, VPX_IMG_FMT_VPXI420, w, h, 1);
    
    int y = 0;
    for (; y < h; ++y)
    {
        int x = 0;
        for (; x < w; ++x)
        {
            uint8_t b = img->imageData[(x + y * w) * 3 + 0];
            uint8_t g = img->imageData[(x + y * w) * 3 + 1];
            uint8_t r = img->imageData[(x + y * w) * 3 + 2];
            
            vpx_img.planes[VPX_PLANE_Y][x + y * vpx_img.stride[VPX_PLANE_Y]] = ((66 * r + 129 * g + 25 * b) >> 8) + 16;
            
            if (!(x % (1 << vpx_img.x_chroma_shift)) && !(y % (1 << vpx_img.y_chroma_shift)))
            {
                const int i = x / (1 << vpx_img.x_chroma_shift);
                const int j = y / (1 << vpx_img.y_chroma_shift);
                vpx_img.planes[VPX_PLANE_U][i + j * vpx_img.stride[VPX_PLANE_U]] = ((112 * r + -94 * g + -18 * b) >> 8) + 128;
                vpx_img.planes[VPX_PLANE_V][i + j * vpx_img.stride[VPX_PLANE_V]] = ((-38 * r + -74 * g + 112 * b) >> 8) + 128;
            }
        }
    }
    
    int rc = toxav_send_video_frame(av, friend_number, w, h, 
                                    vpx_img.planes[VPX_PLANE_Y], 
                                    vpx_img.planes[VPX_PLANE_U], 
                                    vpx_img.planes[VPX_PLANE_V], NULL);
    
    vpx_img_free(&vpx_img);
    return rc;
}

int print_audio_devices()
{
    const char *device;

    printf("Default output device: %s\n", alcGetString(NULL, ALC_DEFAULT_DEVICE_SPECIFIER));
    printf("Output devices:\n");
    
    int i = 0;
    for(device = alcGetString(NULL, ALC_DEVICE_SPECIFIER); *device; 
        device += strlen( device ) + 1, ++i) {
        printf("%d) %s\n", i, device);
    }
    
    return 0;
}

int print_help (const char* name)
{
    printf("Usage: %s -[a:v:o:dh]\n"
           "-a <path> video input file\n"
           "-v <path> video input file\n"
           "-o <idx> output audio device index\n"
           "-d print output audio devices\n"
           "-h print this help\n", name);
    
    return 0;
}

int main (int argc, char** argv)
{
    struct stat st;
    
    /* AV files for testing */
    const char* af_name = NULL;
    const char* vf_name = NULL;
    long audio_out_dev_idx = 0;
    
    /* Pasre settings */
    CHECK_ARG: switch (getopt(argc, argv, "a:v:o:dh")) {
    case 'a':
        af_name = optarg;
        goto CHECK_ARG;
    case 'v':
        vf_name = optarg;
        goto CHECK_ARG;
    case 'o': {
        char *d;
        audio_out_dev_idx = strtol(optarg, &d, 10);
        if (*d) {
            printf("Invalid value for argument: 'o'");
            exit(1);
        }
        goto CHECK_ARG;
    }
    case 'd':
        return print_audio_devices();
    case 'h':
        return print_help(argv[0]);
    case '?':
        exit(1);
    case -1:;
    }
    
    { /* Check files */
        if (!af_name) {
            printf("Required audio input file!\n");
            exit(1);
        }
        
        if (!vf_name) {
            printf("Required video input file!\n");
            exit(1);
        }
        
        /* Check for files */
        if(stat(af_name, &st) != 0 || !S_ISREG(st.st_mode))
        {
            printf("%s doesn't seem to be a regular file!\n", af_name);
            exit(1);
        }
        
        if(stat(vf_name, &st) != 0 || !S_ISREG(st.st_mode))
        {
            printf("%s doesn't seem to be a regular file!\n", vf_name);
            exit(1);
        }
    }
    
	ALCdevice* audio_out_device;
	
	{ /* Open output device */
        const char* audio_out_dev_name = NULL;
        
        int i = 0;
        for(audio_out_dev_name = alcGetString(NULL, ALC_DEVICE_SPECIFIER); i < audio_out_dev_idx;
            audio_out_dev_name += strlen( audio_out_dev_name ) + 1, ++i)
            if (!(audio_out_dev_name + strlen( audio_out_dev_name ) + 1))
                break;
        
		audio_out_device = alcOpenDevice(audio_out_dev_name);
		if ( !audio_out_device ) {
			printf("Failed to open playback device: %s: %d\n", audio_out_dev_name, alGetError());
			exit(1);
		}
		
        ALCcontext* out_ctx = alcCreateContext(audio_out_device, NULL);
        alcMakeContextCurrent(out_ctx);
		
        uint32_t buffers[5];
		alGenBuffers(5, buffers);
		alGenSources((uint32_t)1, &adout);
		alSourcei(adout, AL_LOOPING, AL_FALSE);
		
		uint16_t zeros[10000];
		memset(zeros, 0, 10000);
		
		for ( i = 0; i < 5; ++i ) 
			alBufferData(buffers[i], AL_FORMAT_STEREO16, zeros, 10000, 48000);
		
		alSourceQueueBuffers(adout, 5, buffers);
		alSourcePlay(adout);
        
        printf("Using audio device: %s\n", audio_out_dev_name);
	}
	
    printf("Using audio file: %s\n", af_name);
    printf("Using video file: %s\n", vf_name);
    
	
    
    
    
    /* START TOX NETWORK */
    
    Tox *bootstrap;
    ToxAV *AliceAV;
    ToxAV *BobAV;
    
    CallControl AliceCC;
    CallControl BobCC;
    
    initialize_tox(&bootstrap, &AliceAV, &AliceCC, &BobAV, &BobCC);
    
    
    

#define REGULAR_CALL_FLOW(A_BR, V_BR) \
	do { \
        memset(&AliceCC, 0, sizeof(CallControl)); \
        memset(&BobCC, 0, sizeof(CallControl)); \
        \
        TOXAV_ERR_CALL rc; \
        toxav_call(AliceAV, 0, A_BR, V_BR, &rc); \
        \
        if (rc != TOXAV_ERR_CALL_OK) { \
            printf("toxav_call failed: %d\n", rc); \
            exit(1); \
        } \
        \
        \
        long long unsigned int start_time = time(NULL); \
        \
        \
        while (BobCC.state != TOXAV_CALL_STATE_END) { \
            \
            if (BobCC.incoming) { \
                TOXAV_ERR_ANSWER rc; \
                toxav_answer(BobAV, 0, A_BR, V_BR, &rc); \
                \
                if (rc != TOXAV_ERR_ANSWER_OK) { \
                    printf("toxav_answer failed: %d\n", rc); \
                    exit(1); \
                } \
                BobCC.incoming = false; \
            } else { \
                /* TODO rtp */ \
                \
                if (time(NULL) - start_time == 5) { \
                    \
                    TOXAV_ERR_CALL_CONTROL rc; \
                    toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc); \
                    \
                    if (rc != TOXAV_ERR_CALL_CONTROL_OK) { \
                        printf("toxav_call_control failed: %d\n", rc); \
                        exit(1); \
                    } \
                } \
            } \
             \
            iterate(bootstrap, AliceAV, BobAV); \
        } \
        printf("Success!\n");\
    } while(0)
    
    if (TEST_REGULAR_AV) {
		printf("\nTrying regular call (Audio and Video)...\n");
		REGULAR_CALL_FLOW(48, 4000);
	}
	
    if (TEST_REGULAR_A) {
		printf("\nTrying regular call (Audio only)...\n");
		REGULAR_CALL_FLOW(48, 0);
	}
	
	if (TEST_REGULAR_V) {
		printf("\nTrying regular call (Video only)...\n");
		REGULAR_CALL_FLOW(0, 4000);
	}
	
#undef REGULAR_CALL_FLOW
    
    if (TEST_REJECT) { /* Alice calls; Bob rejects */
        printf("\nTrying reject flow...\n");
        
        memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));
        
        {
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 0, &rc);
            
            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);
        
        /* Reject */
        {
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(BobAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (AliceCC.state != TOXAV_CALL_STATE_END)
            iterate_tox(bootstrap, AliceAV, BobAV);
        
        printf("Success!\n");
    }
    
    if (TEST_CANCEL) { /* Alice calls; Alice cancels while ringing */
        printf("\nTrying cancel (while ringing) flow...\n");
        
        memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));
        
        {
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 0, &rc);
            
            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);
        
        /* Cancel */
        {
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        /* Alice will not receive end state */
        while (BobCC.state != TOXAV_CALL_STATE_END)
            iterate_tox(bootstrap, AliceAV, BobAV);
        
        printf("Success!\n");
    }
    
    if (TEST_MUTE_UNMUTE) { /* Check Mute-Unmute etc */
        printf("\nTrying mute functionality...\n");
        
        memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));
        
        /* Assume sending audio and video */
        {
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 1000, &rc);
            
            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);
        
        /* At first try all stuff while in invalid state */
        assert(!toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_PAUSE, NULL));
        assert(!toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_RESUME, NULL));
        assert(!toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        assert(!toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO, NULL));
        
        {
            TOXAV_ERR_ANSWER rc;
            toxav_answer(BobAV, 0, 48, 4000, &rc);
            
            if (rc != TOXAV_ERR_ANSWER_OK) {
                printf("toxav_answer failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate_tox(bootstrap, AliceAV, BobAV);
        
        /* Pause and Resume */
        printf("Pause and Resume\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_PAUSE, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_PAUSED);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_RESUME, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state & (TOXAV_CALL_STATE_SENDING_A | TOXAV_CALL_STATE_SENDING_V));
        
        /* Mute/Unmute single */
        printf("Mute/Unmute single\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_A);
        
        /* Mute/Unmute both */
        printf("Mute/Unmute both\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_V);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO, NULL));
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_V);
        
        {
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_END);
        
        printf("Success!\n");
    }
    
    if (TEST_TRANSFER_A) { /* Audio encoding/decoding and transfer */
        SNDFILE* af_handle;
        SF_INFO af_info;
        
		printf("\nTrying audio enc/dec...\n");
		
		memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));
        
        { /* Call */
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 0, &rc);
            
            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);
		
		{ /* Answer */
            TOXAV_ERR_ANSWER rc;
            toxav_answer(BobAV, 0, 64, 0, &rc);
            
            if (rc != TOXAV_ERR_ANSWER_OK) {
                printf("toxav_answer failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate_tox(bootstrap, AliceAV, BobAV);
		
        /* Open audio file */
        af_handle = sf_open(af_name, SFM_READ, &af_info);
        if (af_handle == NULL)
        {
            printf("Failed to open the file.\n");
            exit(1);
        }
        
		/* Run for 5 seconds */
        
        uint32_t frame_duration = 10;
        int16_t PCM[10000];
        
        time_t start_time = time(NULL);
        time_t expected_time = af_info.frames / af_info.samplerate + 2;
        
		while ( start_time + expected_time > time(NULL) ) {
            int frame_size = (af_info.samplerate * frame_duration / 1000);
            
            int64_t count = sf_read_short(af_handle, PCM, frame_size);
            if (count > 0) {
                TOXAV_ERR_SEND_FRAME rc;
                if (toxav_send_audio_frame(AliceAV, 0, PCM, count, af_info.channels, af_info.samplerate, &rc) == false) {
                    printf("Error sending frame of size %ld: %d\n", count, rc);
                    exit(1);
                }
            }
            
            iterate_tox(bootstrap, AliceAV, BobAV);
		}
        
		printf("Played file in: %lu\n", time(NULL) - start_time);
        
        sf_close(af_handle);
		
		{ /* Hangup */
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_END);
		
		printf("Success!");
	}
	
	if (TEST_TRANSFER_V) {
        cvNamedWindow(vdout, CV_WINDOW_AUTOSIZE);
        
        CvCapture* capture = cvCreateFileCapture(vf_name);
        if (!capture) {
            printf("Failed to open video file: %s\n", vf_name);
            exit(1);
        }
        
        IplImage* frame;
        time_t start_time = time(NULL);
        
        while(start_time + 10 > time(NULL)) {
            frame = cvQueryFrame( capture );
            if (!frame)
                break;
            
        }
        
        cvReleaseCapture(&capture);
        cvDestroyWindow(vdout);
    }
    
    
    Tox* Alice = toxav_get_tox(AliceAV);
    Tox* Bob = toxav_get_tox(BobAV);
    toxav_kill(BobAV);
    toxav_kill(AliceAV);
    tox_kill(Bob);
    tox_kill(Alice);
    tox_kill(bootstrap);
    
    printf("\nTest successful!\n");
	
	alcCloseDevice(audio_out_device);
    return 0;
}
