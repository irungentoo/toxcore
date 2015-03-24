#include "toxav.h"
#include "../toxcore/tox.h"

#ifdef __APPLE__
#	include <OpenAL/al.h>
#	include <OpenAL/alc.h>
#else
#	include <AL/al.h>
#	include <AL/alc.h>
/* compatibility with older versions of OpenAL */
#	ifndef ALC_ALL_DEVICES_SPECIFIER
#		include <AL/alext.h>
#	endif  /* ALC_ALL_DEVICES_SPECIFIER */
#endif  /* __APPLE__ */

#include <opencv/cv.h>
#include <opencv/highgui.h>

#include <vpx/vpx_image.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif


/* Enable/disable tests */
#define TEST_REGULAR_AV 0
#define TEST_REGULAR_A 0
#define TEST_REGULAR_V 0
#define TEST_REJECT 0
#define TEST_CANCEL 0
#define TEST_MUTE_UNMUTE 0
#define TEST_TRANSFER_A 0
#define TEST_TRANSFER_V 1


typedef struct {
    bool incoming;
    uint32_t state;
	uint32_t output_source;
} CallControl;

const char* video_test_window = "AV Test";

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
};


int device_play_frame(uint32_t source, const int16_t* PCM, size_t size);

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
    for (int y = 0; y < height; ++y)
    {
        for (int x = 0; x < width; ++x)
        {
            uint8_t Y = planes[VPX_PLANE_Y][x + y * bpl];
            uint8_t U = planes[VPX_PLANE_V][x/(1 << 1) + y/(1 << 1)*cxbpl];
            uint8_t V = planes[VPX_PLANE_U][x/(1 << 1) + y/(1 << 1)*cxbpl];
            output_img.imageData[width * 3 * y + x * 3 + 0] = Y;
            output_img.imageData[width * 3 * y + x * 3 + 1] = U;
            output_img.imageData[width * 3 * y + x * 3 + 2] = V;
        }
    }
    
    cvShowImage(video_test_window, &output_img);
    free(output_img.imageData);
}
void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
                                    int16_t const *pcm,
                                    size_t sample_count,
                                    uint8_t channels,
                                    uint32_t sampling_rate,
                                    void *user_data)
{
    device_play_frame(((CallControl*)user_data)->output_source, pcm, sample_count);
}
void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/**
 */
void prepare(Tox* Bsn, Tox* Alice, Tox* Bob)
{
    long long unsigned int cur_time = time(NULL);
    
    uint32_t to_compare = 974536;
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    
    tox_callback_friend_request(Alice, t_accept_friend_request_cb, &to_compare);
    tox_get_address(Alice, address);
    
    assert(tox_add_friend(Bob, address, (uint8_t *)"gentoo", 7) >= 0);
    
    uint8_t off = 1;
    
    while (1) {
        tox_do(Bsn);
        tox_do(Alice);
        tox_do(Bob);
        
        if (tox_isconnected(Bsn) && tox_isconnected(Alice) && tox_isconnected(Bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }
        
        if (tox_get_friend_connection_status(Alice, 0) == 1 && tox_get_friend_connection_status(Bob, 0) == 1)
            break;
        
        c_sleep(20);
    }
    
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);
}
void prepareAV(ToxAV* AliceAV, void* AliceUD, ToxAV* BobAV, void* BobUD)
{
    /* Alice */
    toxav_callback_call(AliceAV, t_toxav_call_cb, AliceUD);
    toxav_callback_call_state(AliceAV, t_toxav_call_state_cb, AliceUD);
    toxav_callback_receive_video_frame(AliceAV, t_toxav_receive_video_frame_cb, AliceUD);
    toxav_callback_receive_audio_frame(AliceAV, t_toxav_receive_audio_frame_cb, AliceUD);
    
    /* Bob */
    toxav_callback_call(BobAV, t_toxav_call_cb, BobUD);
    toxav_callback_call_state(BobAV, t_toxav_call_state_cb, BobUD);
    toxav_callback_receive_video_frame(BobAV, t_toxav_receive_video_frame_cb, BobUD);
    toxav_callback_receive_audio_frame(BobAV, t_toxav_receive_audio_frame_cb, BobUD);
}
void iterate(Tox* Bsn, ToxAV* AliceAV, ToxAV* BobAV)
{
    tox_do(Bsn);
    tox_do(toxav_get_tox(AliceAV));
    tox_do(toxav_get_tox(BobAV));
    
    toxav_iteration(AliceAV);
    toxav_iteration(BobAV);
    
	int mina = MIN(tox_do_interval(toxav_get_tox(AliceAV)), toxav_iteration_interval(AliceAV));
	int minb = MIN(tox_do_interval(toxav_get_tox(BobAV)), toxav_iteration_interval(BobAV));
	
	c_sleep(MIN(mina, minb));
}

int device_read_frame(ALCdevice* device, int32_t frame_dur, int16_t* PCM, size_t max_size)
{
	int f_size = (8000 * frame_dur / 1000);
	
	if (max_size < f_size)
		return -1;

	/* Don't block if not enough data */
	int32_t samples;
	alcGetIntegerv(device, ALC_CAPTURE_SAMPLES, sizeof(int32_t), &samples);
	if (samples < f_size) 
		return 0;
	
	alcCaptureSamples(device, PCM, f_size);
	return f_size;
}

int device_play_frame(uint32_t source, const int16_t* PCM, size_t size)
{
	uint32_t bufid;
    int32_t processed, queued;
    alGetSourcei(source, AL_BUFFERS_PROCESSED, &processed);
    alGetSourcei(source, AL_BUFFERS_QUEUED, &queued);

    if(processed) {
        uint32_t bufids[processed];
        alSourceUnqueueBuffers(source, processed, bufids);
        alDeleteBuffers(processed - 1, bufids + 1);
        bufid = bufids[0];
    }
    else if(queued < 16)
		alGenBuffers(1, &bufid);
    else
        return 0;
    

    alBufferData(bufid, AL_FORMAT_STEREO16, PCM, size * 2 * 2, 48000);
    alSourceQueueBuffers(source, 1, &bufid);

    int32_t state;
    alGetSourcei(source, AL_SOURCE_STATE, &state);

    if(state != AL_PLAYING) 
		alSourcePlay(source);
	return 1;
}

int print_devices()
{
	const char* default_input;
	const char* default_output;
	
	const char *device;

	printf("Default input device: %s\n", alcGetString(NULL, ALC_CAPTURE_DEFAULT_DEVICE_SPECIFIER));
	printf("Default output device: %s\n", alcGetString(NULL, ALC_DEFAULT_DEVICE_SPECIFIER));
	
	printf("\n");
	
	printf("Input devices:\n");
	
	int i = 0;
	for(device = alcGetString(NULL, ALC_CAPTURE_DEVICE_SPECIFIER); *device; 
		device += strlen( device ) + 1, ++i) {
		printf("%d) %s\n", i, device);
	}
	
	printf("\n");
	printf("Output devices:\n");
	
	i = 0;
	for(device = alcGetString(NULL, ALC_DEVICE_SPECIFIER); *device; 
		device += strlen( device ) + 1, ++i) {
		printf("%d) %s\n", i, device);
	}
	
	return 0;
}

int print_help(const char* name, int rc)
{
	fprintf(stderr, "Usage: %s [-h] <in device> <out device>\n", name);
	return rc;
}

long get_device_idx(const char* arg)
{
	if (strcmp(arg, "-") == 0)
		return -1; /* Default */
	
	char *p;
	long res = strtol(arg, &p, 10);
	
	if (*p) {
		fprintf(stderr, "Invalid device!");
		exit(1);
	}
	
	return res;
}

int send_opencv_img(ToxAV* av, uint32_t friend_number, const IplImage* img)
{
    /* I use vpx image coz i'm noob TODO use opencv conversion */
    vpx_image vpx_img;
    vpx_img.w = vpx_img.h = vpx_img.d_w = vpx_img.d_h = 0;
    
    const int w = img->width;
    const int h = img->height;
    
    vpx_img_alloc(&vpx_img, VPX_IMG_FMT_VPXI420, w, h, 1);
    
    for (int y = 0; y < h; ++y)
    {
        for (int x = 0; x < w; ++x)
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

int main (int argc, char** argv)
{
    /* AV files for testing */
    const char* audio_in = "";
    const char* video_in = "";
    long audio_out_dev = 0;
    
AGAIN:
    switch (getopt(argc, argv, "a:v:o:"))
    {
        case 'a':
            audio_in = optarg;
            goto AGAIN;
            break;
        case 'v':
            video_in = optarg;
            goto AGAIN;
            break;
        case 'o':
            char *d;
            audio_out_dev = strtol(optarg, &d, 10);
            if (*d) {
                fprintf(stderr, "Invalid value for argument: 'o'");
                return 1;
            }
            goto AGAIN;
            break;
        case '?':
            return 1;
            break;
        case -1:
            break;
    }
    
    
    
    return 0;
    
	if (argc == 2) {
		if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--devices") == 0) {
			return print_devices();
		}
		if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
			return print_help(argv[0], 0);
		}
	}
	
	if (argc != 3) {
		fprintf(stderr, "Invalid input!\n");
		return print_help(argv[0], 1);
	}
	
	int i;
	
	const char* in_device_name = "";
	const char* out_device_name = "";
	
	{
		long dev = get_device_idx(argv[1]);
		if (dev == -1)
			in_device_name = alcGetString(NULL, ALC_CAPTURE_DEFAULT_DEVICE_SPECIFIER);
		else
		{
			const char* tmp;
			i = -1;
			for(tmp = alcGetString(NULL, ALC_CAPTURE_DEVICE_SPECIFIER); *tmp && i != dev;
				tmp += strlen( tmp ) + 1, ++i)
				in_device_name = tmp;
		}
		
		printf("Input device: %s\n", in_device_name);
	}
	
	{
		long dev = get_device_idx(argv[1]);
		if (dev == -1)
			out_device_name = alcGetString(NULL, ALC_DEFAULT_DEVICE_SPECIFIER);
		else
		{
			const char* tmp;
			i = -1;
			for(tmp = alcGetString(NULL, ALC_DEVICE_SPECIFIER); *tmp && i != dev;
				tmp += strlen( tmp ) + 1, ++i)
				out_device_name = tmp;
		}
		
		printf("Output device: %s\n", out_device_name);
	}
	
	ALCdevice* out_device;
	ALCcontext* out_ctx;
	uint32_t source;
	uint32_t buffers[5];
	
	{ /* Open output device */
		out_device = alcOpenDevice(out_device_name);
		if ( !out_device ) {
			fprintf(stderr, "Failed to open playback device: %s: %d\n", out_device_name, alGetError());
			return 1;
		}
		
		out_ctx = alcCreateContext(out_device, NULL);
        alcMakeContextCurrent(out_ctx);
		
		alGenBuffers(5, buffers);
		alGenSources((uint32_t)1, &source);
		alSourcei(source, AL_LOOPING, AL_FALSE);
		
		uint16_t zeros[10000];
		memset(zeros, 0, 10000);
		
		for ( i = 0; i < 5; ++i ) 
			alBufferData(buffers[i], AL_FORMAT_STEREO16, zeros, 10000, 48000);
		
		alSourceQueueBuffers(source, 5, buffers);
		alSourcePlay(source);
	}
	
	ALCdevice* in_device;
	
	{ /* Open input device */
		in_device = alcCaptureOpenDevice(in_device_name, 48000, AL_FORMAT_STEREO16, 10000);
		if ( !in_device ) {
			fprintf(stderr, "Failed to open capture device: %s: %d\n", in_device_name, alGetError());
			return 1;
		}
		
		alcCaptureStart(in_device);
	}
	
    Tox *Bsn = tox_new(0);
    Tox *Alice = tox_new(0);
    Tox *Bob = tox_new(0);
    
    assert(Bsn && Alice && Bob);
    
    prepare(Bsn, Alice, Bob);
    
    
    ToxAV *AliceAV, *BobAV;
    CallControl AliceCC, BobCC;
    
    {
        TOXAV_ERR_NEW rc;
        AliceAV = toxav_new(Alice, &rc);
        assert(rc == TOXAV_ERR_NEW_OK);
        
        BobAV = toxav_new(Bob, &rc);
        assert(rc == TOXAV_ERR_NEW_OK);
        
        prepareAV(AliceAV, &AliceCC, BobAV, &BobCC);
        printf("Created 2 instances of ToxAV\n");
    }
    

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
            iterate(Bsn, AliceAV, BobAV); \
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
            iterate(Bsn, AliceAV, BobAV);
        
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
            iterate(Bsn, AliceAV, BobAV);
        
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
            iterate(Bsn, AliceAV, BobAV);
        
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
            iterate(Bsn, AliceAV, BobAV);
        
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
            iterate(Bsn, AliceAV, BobAV);
        
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
        
        iterate(Bsn, AliceAV, BobAV);
        
        /* Pause and Resume */
        printf("Pause and Resume\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_PAUSE, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_PAUSED);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_RESUME, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state & (TOXAV_CALL_STATE_SENDING_A | TOXAV_CALL_STATE_SENDING_V));
        
        /* Mute/Unmute single */
        printf("Mute/Unmute single\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_A);
        
        /* Mute/Unmute both */
        printf("Mute/Unmute both\n");
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state ^ TOXAV_CALL_STATE_RECEIVING_V);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_A);
        assert(toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO, NULL));
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state & TOXAV_CALL_STATE_RECEIVING_V);
        
        {
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_END);
        
        printf("Success!\n");
    }
    
    if (TEST_TRANSFER_A) { /* Audio encoding/decoding and transfer */
		printf("\nTrying audio enc/dec...\n");
		
		memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));
		
		AliceCC.output_source = BobCC.output_source = source;
        
        {
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 0, &rc);
            
            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }
        
        while (!BobCC.incoming)
            iterate(Bsn, AliceAV, BobAV);
		
		{
            TOXAV_ERR_ANSWER rc;
            toxav_answer(BobAV, 0, 48, 0, &rc);
            
            if (rc != TOXAV_ERR_ANSWER_OK) {
                printf("toxav_answer failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate(Bsn, AliceAV, BobAV);
		
		int16_t PCM[10000];
		time_t start_time = time(NULL);
		
		/* Run for 5 seconds */
		while ( start_time + 10 > time(NULL) ) {
			int frame_size = device_read_frame(in_device, 20, PCM, sizeof(PCM));
			if (frame_size > 0) {
				TOXAV_ERR_SEND_FRAME rc;
				if (toxav_send_audio_frame(AliceAV, 0, PCM, frame_size, 2, 8000, &rc) == false) {
					printf("Error sending frame of size %d: %d\n", frame_size, rc);
					exit (1);
				}
			}
			
			iterate(Bsn, AliceAV, BobAV);
		}
		
		{
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);
            
            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }
        
        iterate(Bsn, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_CALL_STATE_END);
		
		printf("Success!");
	}
	
	if (TEST_TRANSFER_V) {
        if (strlen(video_in) == 0) {
            printf("Skipping video test...\n");
            goto CONTINUE;
        }
        
        cvNamedWindow(video_test_window, CV_WINDOW_AUTOSIZE);
        
        CvCapture* capture = cvCreateFileCapture(video_in);
        if (!capture) {
            printf("No file named: %s\n", video_in);
            return 1;
        }
        
        IplImage* frame;
        time_t start_time = time(NULL);
        
        while(start_time + 10 > time(NULL)) {
            frame = cvQueryFrame( capture );
            if (!frame)
                break;
            
        }
        
        cvReleaseCapture(&capture);
        cvDestroyWindow(video_test_window);
        
    CONTINUE:;
    }
    
    
    toxav_kill(BobAV);
    toxav_kill(AliceAV);
    tox_kill(Bob);
    tox_kill(Alice);
    tox_kill(Bsn);
    
    printf("\nTest successful!\n");
	
	alcCloseDevice(out_device);
	alcCaptureCloseDevice(in_device);
    return 0;
}