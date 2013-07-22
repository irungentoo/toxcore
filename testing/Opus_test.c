#include <stdio.h>
#include <stdlib.h>
#include "portaudio.h"
#include <opus/opus.h>

#define SAMPLE_RATE  (48000)
#define FRAMES_PER_BUFFER (480)
#define BITRATE (128)
#define NUM_SECONDS     (5)
#define NUM_CHANNELS    (1)
#define PA_SAMPLE_TYPE  paFloat32
typedef float SAMPLE;
#define SAMPLE_SILENCE  (0.0f)

typedef struct
{
      int          frameIndex;  /* Index into decompressed sample array. */
      int          maxFrameIndex;
      SAMPLE * samples;
      SAMPLE * decoded_frame;
}Recording;

typedef struct
{
    OpusEncoder *encoder;
    OpusDecoder *decoder;

    int frames_per_buffer;
    int max_compressed_size_buffer;
    unsigned char *EncodedBytes;
    int kbps;
}OPUS_codec;

OPUS_codec cd;

int OP_init(OPUS_codec *cd, const opus_int32 sample_rate, const int kbps, const int frames_per_buffer, const int channels)
{
    cd->kbps=kbps;
    cd->frames_per_buffer = frames_per_buffer;
    cd->max_compressed_size_buffer = (kbps*1024*frames_per_buffer*2) / (SAMPLE_RATE * 8);
    cd->EncodedBytes = (unsigned char*) malloc(cd->max_compressed_size_buffer*2);

    int err = OPUS_OK;
    cd->encoder = opus_encoder_create(sample_rate, channels, OPUS_APPLICATION_VOIP, &err);
    err = opus_encoder_ctl(cd->encoder, OPUS_SET_BITRATE(kbps*1024));
    err = opus_encoder_ctl(cd->encoder, OPUS_SET_COMPLEXITY(10));
    err = opus_encoder_ctl(cd->encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    cd->decoder = opus_decoder_create(sample_rate, channels, &err);

    opus_encoder_init(cd->encoder, sample_rate, channels, OPUS_APPLICATION_VOIP);
    opus_decoder_init(cd->decoder, sample_rate, channels);

    int nfo;
    err = opus_encoder_ctl(cd->encoder, OPUS_GET_LOOKAHEAD(&nfo));
    printf("Encoder lookahead delay : %d\n", nfo);

    return 0;
}

int OP_test_encode_decode(OPUS_codec *cd, float * const in, float * const out)
{
    int encoded_byte_cnt = opus_encode_float(cd->encoder, in, cd->frames_per_buffer, cd->EncodedBytes, cd->max_compressed_size_buffer);
    int decoded_byte_cnt = opus_decode_float(cd->decoder, cd->EncodedBytes, encoded_byte_cnt, out, cd->frames_per_buffer, 0);
    if(decoded_byte_cnt != cd->frames_per_buffer)
    {
      printf("sample count does not match: %d %d\n", cd->frames_per_buffer, decoded_byte_cnt);
    }
    return encoded_byte_cnt;
}

opus_int32 OP_encode_frame(OPUS_codec *cd, float * const in, unsigned char *out) /* returns the amount of bytes written */
{
    return opus_encode_float(cd->encoder, in, cd->frames_per_buffer, out, cd->max_compressed_size_buffer);
}

opus_int32 OP_decode_frame(OPUS_codec *cd, const unsigned char* data, opus_int32 size,float * out)
{
    return opus_decode_float(cd->decoder, data,size, out, cd->frames_per_buffer, 0);
}

void op_destroy(OPUS_codec *cd)
{
    opus_encoder_destroy(cd->encoder);
    opus_decoder_destroy(cd->decoder);
}

/* This routine will be called by the PortAudio engine when audio is needed.
** It may be called at interrupt level on some machines so don't do anything
** that could mess up the system like calling malloc() or free().
*/
static int recordCallback( const void *inputBuffer, void *outputBuffer,
                           unsigned long framesPerBuffer,
                           const PaStreamCallbackTimeInfo* timeInfo,
                           PaStreamCallbackFlags statusFlags,
                           void *userData )
{
    Recording *data = (Recording*)userData;   
    float * ucptr = &data->samples[data->frameIndex*NUM_CHANNELS];
    
    
    opus_int32 Size = OP_encode_frame(&cd, (float*)inputBuffer, (unsigned char *)cd.EncodedBytes); /* encode frame */
    
    OP_decode_frame(&cd, (unsigned char *)cd.EncodedBytes, Size,(float*)data->decoded_frame); /* decode frame */
    
    const float * out_ptr=(const float*)data->decoded_frame;
    unsigned long framesToCalc;
    unsigned long framesLeft = data->maxFrameIndex - data->frameIndex;
    long i;
    int finished;

    (void) outputBuffer; /* Prevent unused variable warnings. */
    (void) timeInfo;
    (void) statusFlags;
    (void) userData;

    if(framesLeft < framesPerBuffer)
    {
        framesToCalc = framesLeft;
        finished = paComplete;
    }
    else
    {
        framesToCalc = framesPerBuffer;
        finished = paContinue;
    }

    if(inputBuffer == NULL)
    {
        for(i=0; i<framesToCalc; ++i)
        {
            *ucptr++=SAMPLE_SILENCE;
            if(NUM_CHANNELS == 2){ *ucptr++=SAMPLE_SILENCE;} /* right */
        }
    }
    else
    {
        for(i=0; i<framesToCalc; ++i)
        {
            *ucptr++ = *out_ptr++;
            if(NUM_CHANNELS == 2) {*ucptr++ = *out_ptr++; } /* right */
        }
    }
    data->frameIndex += framesToCalc;
    return finished;
}

/* This routine will be called by the PortAudio engine when audio is needed.
** It may be called at interrupt level on some machines so don't do anything
** that could mess up the system like calling malloc() or free().
*/
static int playCallback( const void *inputBuffer, void *outputBuffer,
                         unsigned long framesPerBuffer,
                         const PaStreamCallbackTimeInfo* timeInfo,
                         PaStreamCallbackFlags statusFlags,
                         void *userData )
{
    Recording *data = (Recording*)userData;
    SAMPLE *in_ptr = &data->samples[data->frameIndex* NUM_CHANNELS];
    SAMPLE *out_ptr = (SAMPLE*)outputBuffer;
    unsigned int i;
    int finished;
    unsigned int framesLeft = data->maxFrameIndex - data->frameIndex;

    (void) inputBuffer; /* Prevent unused variable warnings. */
    (void) timeInfo;
    (void) statusFlags;
    (void) userData;
    
    if(framesLeft < framesPerBuffer)
    {
        /* final buffer... */
        for(i=0; i<framesLeft; ++i)
        {
            *out_ptr++ = *in_ptr++;  /* left */
            if(NUM_CHANNELS == 2) *out_ptr++ = *in_ptr++;  /* right */
        }
        for(i=0 ; i<framesPerBuffer; ++i)
        {
            *out_ptr++ = 0;  /* left */
            if(NUM_CHANNELS == 2) *out_ptr++ = 0;  /* right */
        }
        data->frameIndex += framesLeft;
        finished = paComplete;
    }
    else
    {
        for(i=0; i<framesPerBuffer; ++i)
        {
            *out_ptr++ = *in_ptr++;  /* left */
            if(NUM_CHANNELS == 2) *out_ptr++ = *in_ptr++;  /* right */
        }
        data->frameIndex += framesPerBuffer;
        finished = paContinue;
    }
    return finished;
}


void get_devices(int * input, int * output)
{
    *input=-1;*output=-1;
    if(Pa_GetDeviceInfo(Pa_GetDefaultInputDevice())->maxInputChannels<=0)
    {
	printf("The default input device has no channels\n");
    }
    if(Pa_GetDeviceInfo(Pa_GetDefaultOutputDevice())->maxOutputChannels<=0)
    {
	printf("The default output device has no channels\n");
    }
    int i;
    int devices=Pa_GetDeviceCount();
    const   PaDeviceInfo *deviceInfo;
    printf("detected %d devices\n",devices);
    for(i=0;i<devices;++i)
    {
	deviceInfo=Pa_GetDeviceInfo(i);
	printf("device nr: %d | name: %s | inputchannels: %d | outputchannels: %d |\n",i,deviceInfo->name,deviceInfo->maxInputChannels,deviceInfo->maxOutputChannels);
    }

    printf("Enter inputdevice nr: \n");
    scanf("%d",input);
    printf("Enter outputdevice nr: \n");
    scanf("%d",output);

    if(*input < 0 || Pa_GetDeviceInfo(*input)->maxInputChannels<=0)
    {
	printf("No valid input device found\n");
    *input=-1;
    }
    else
    {
	printf("Inputdevice: %d\n",*input);
    }
    if(*output < 0 || Pa_GetDeviceInfo(*output)->maxOutputChannels<=0)
    {
	printf("No valid output device found\n");
    *output=-1;
    }
    else
    {
	printf("Outputdevice: %d\n",*output);
    }
  
}

int main(void)
{
    PaStreamParameters  inputParameters,
                        outputParameters;
    PaStream*           stream;
    PaError             err = paNoError;
    Recording           data;
    int                 i;
    int                 totalFrames;
    int                 numSamples;
    int                 numBytes;
    
    int inputdevice,outputdevice;


    OP_init(&cd, SAMPLE_RATE, BITRATE, FRAMES_PER_BUFFER, NUM_CHANNELS);
    

    data.maxFrameIndex = totalFrames = NUM_SECONDS * SAMPLE_RATE;
    data.frameIndex = 0;
    numSamples = totalFrames * NUM_CHANNELS;
    numBytes = numSamples * sizeof(SAMPLE);
    data.samples = (SAMPLE *) malloc( numBytes );
    data.decoded_frame = (float*) malloc(cd.frames_per_buffer*sizeof(SAMPLE)*NUM_CHANNELS);
    for( i=0; i<numSamples; ++i ) data.samples[i] = 0;

    err = Pa_Initialize();
    if(err != paNoError) goto done;
    
    get_devices(&inputdevice,&outputdevice);
    if(inputdevice<0||outputdevice<0)
    {
	goto done;
    }

    inputParameters.device = inputdevice;
    inputParameters.channelCount = NUM_CHANNELS;
    inputParameters.sampleFormat = PA_SAMPLE_TYPE;
    inputParameters.suggestedLatency = Pa_GetDeviceInfo( inputParameters.device )->defaultLowInputLatency;
    inputParameters.hostApiSpecificStreamInfo = NULL;
    
    outputParameters.device = outputdevice;
    outputParameters.channelCount = NUM_CHANNELS;                  
    outputParameters.sampleFormat =  PA_SAMPLE_TYPE;
    outputParameters.suggestedLatency = Pa_GetDeviceInfo( outputParameters.device )->defaultLowOutputLatency;
    outputParameters.hostApiSpecificStreamInfo = NULL;
    
    /* record the audio */
    err = Pa_OpenStream(
              &stream,
              &inputParameters,
              NULL, /* no output */
              SAMPLE_RATE,
              FRAMES_PER_BUFFER,
              paClipOff,
              recordCallback,
              &data );
    if(err != paNoError) goto done;

    err = Pa_StartStream( stream );
    if( err != paNoError ) goto done;
    printf("=== Recording for %d seconds ===\n",NUM_SECONDS); fflush(stdout);
    while((err = Pa_IsStreamActive(stream)) == 1)
    {
        Pa_Sleep(1000);
    }
    if(err < 0) goto done;

    err = Pa_CloseStream( stream );
    if( err != paNoError ) goto done;

    /* play the recorded audio */
    data.frameIndex = 0;

    printf("=== Now playing===\n"); fflush(stdout);
    err = Pa_OpenStream(
              &stream,
              NULL, /* no input */
              &outputParameters,
              SAMPLE_RATE,
              FRAMES_PER_BUFFER,
              paClipOff,
              playCallback,
              &data );
    if(err != paNoError) goto done;

    if(stream)
    {
        err = Pa_StartStream( stream );
        if(err != paNoError) goto done;

        while(( err = Pa_IsStreamActive(stream)) == 1) Pa_Sleep(1000);
        if( err < 0 ) goto done;
        
        err = Pa_CloseStream( stream );
        if(err != paNoError) goto done;
        
        printf("Done.\n"); fflush(stdout);
    }

    done:
    Pa_Terminate();
    op_destroy(&cd);
    if(data.samples)
    {
	free( data.samples );
    }
    if(data.decoded_frame)
    {
	free(data.decoded_frame);
    }
    if(err != paNoError)
    {
        fprintf( stderr, "An error occured while using the portaudio stream\n" );
        fprintf( stderr, "Error number: %d\n", err );
        fprintf( stderr, "Error message: %s\n", Pa_GetErrorText( err ) );
        err = 1;
    }
    return err;
}
