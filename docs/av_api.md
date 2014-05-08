#A/V API reference

##Take toxmsi/phone.c as a reference

###Initialization:

```
phone_t* initPhone(uint16_t _listen_port, uint16_t _send_port);
```

function initializes sample phone. _listen_port and _send_port are variables only meant
for local testing. You will not have to do anything regarding to that since
everything will be started within a mesenger.


Phone requires one msi session and two rtp sessions ( one for audio and one for
video ). 

```
msi_session_t* msi_init_session( void* _core_handler, const uint8_t* _user_agent );
```

initializes msi session.
Params:

```
void* _core_handler - pointer to an object handling networking,
const uint8_t* _user_agent - string describing phone client version.
```

Return value:
msi_session_t* - pointer to a newly created msi session handler.

###msi_session_t reference:

How to handle msi session:
Controlling is done via callbacks and action handlers.
First register callbacks for every state/action received and make sure
NOT TO PLACE SOMETHING LIKE LOOPS THAT TAKES A LOT OF TIME TO EXECUTE; every callback is being called 
directly from event loop. You can find examples in phone.c.

Register callbacks: 
```
void msi_register_callback_call_started ( MCALLBACK );
void msi_register_callback_call_canceled ( MCALLBACK );
void msi_register_callback_call_rejected ( MCALLBACK );
void msi_register_callback_call_ended ( MCALLBACK );

void msi_register_callback_recv_invite ( MCALLBACK );
void msi_register_callback_recv_ringing ( MCALLBACK );
void msi_register_callback_recv_starting ( MCALLBACK );
void msi_register_callback_recv_ending ( MCALLBACK );
void msi_register_callback_recv_error ( MCALLBACK );

void msi_register_callback_requ_timeout ( MCALLBACK );
```

MCALLBACK is defined as: void (*callback) (void* _arg)
msi_session_t* handler is being thrown as \_arg so you can use that and \_agent_handler to get to your own phone handler
directly from callback.


Actions:

```
int msi_invite ( msi_session_t* _session, call_type _call_type, uint32_t _timeoutms );
```

Sends call invite. Before calling/sending invite msi_session_t::_friend_id is needed to be set or else
it will not work. _call_type is type of the call ( Audio/Video ) and _timeoutms is how long 
will poll wait until request is terminated.

```
int msi_hangup ( msi_session_t* _session );
```
Hangs up active call

```
int msi_answer ( msi_session_t* _session, call_type _call_type );
```
Answer incomming call. _call_type set's callee call type.

```
int msi_cancel ( msi_session_t* _session );
```
Cancel current request.

```
int msi_reject ( msi_session_t* _session );
```
Reject incomming call.


###Now for rtp:

You will need 2 sessions; one for audio one for video.
You start them with:
```
rtp_session_t* rtp_init_session ( int _max_users, int _multi_session );
```

Params:
```
int _max_users - max users. -1 if undefined
int _multi_session - any positive number means uses multi session; -1 if not.
```

Return value:
```
rtp_session_t* - pointer to a newly created rtp session handler.
```

###How to handle rtp session:
Take a look at
```
void* phone_handle_media_transport_poll ( void* _hmtc_args_p ) in phone.c
```
on example. Basically what you do is just receive a message via:
```
struct rtp_msg_s* rtp_recv_msg ( rtp_session_t* _session );
```

and then you use payload within the rtp_msg_s struct. Don't forget to deallocate it with:
void rtp_free_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg );
Receiving should be thread safe so don't worry about that.

When you capture and encode a payload you want to send it ( obviously ).

first create a new message with:
```
struct rtp_msg_s* rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length );
```

and then send it with:
```
int rtp_send_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg, void* _core_handler );
```

_core_handler is the same network handler as in msi_session_s struct.


##A/V initialization:
```
int init_receive_audio(codec_state *cs);
int init_receive_video(codec_state *cs);
Initialises the A/V decoders. On failure it will print the reason and return 0. On success it will return 1.

int init_send_audio(codec_state *cs);
int init_send_video(codec_state *cs);
Initialises the A/V encoders. On failure it will print the reason and return 0. On success it will return 1.
init_send_audio will also let the user select an input device. init_send_video will determine the webcam's output codec and initialise the appropriate decoder.

int video_encoder_refresh(codec_state *cs, int bps);
Reinitialises the video encoder with a new bitrate. ffmpeg does not expose the needed VP8 feature to change the bitrate on the fly, so this serves as a workaround.
In the future, VP8 should be used directly and ffmpeg should be dropped from the dependencies.
The variable bps is the required bitrate in bits per second.
```


###A/V encoding/decoding:
```
void *encode_video_thread(void *arg);
```
Spawns the video encoding thread. The argument should hold a pointer to a codec_state.
This function should only be called if video encoding is supported (when init_send_video returns 1).
Each video frame gets encoded into a packet, which is sent via RTP. Every 60 frames a new bidirectional interframe is encoded.
```
void *encode_audio_thread(void *arg);
```
Spawns the audio encoding thread. The argument should hold a pointer to a codec_state.
This function should only be called if audio encoding is supported (when init_send_audio returns 1).
Audio frames are read from the selected audio capture device during intitialisation. This audio capturing can be rerouted to a different device on the fly.
Each audio frame is encoded into a packet, and sent via RTP. All audio frames have the same amount of samples, which is defined in AV_codec.h.
```
int video_decoder_refresh(codec_state *cs, int width, int height);
```
Sets the SDL window dimensions and creates a pixel buffer with the requested size. It also creates a scaling context, which will be used to convert the input image format to YUV420P.

```
void *decode_video_thread(void *arg);
```
Spawns a video decoding thread. The argument should hold a pointer to a codec_state. The codec_state is assumed to contain a successfully initialised video decoder.
This function reads video packets and feeds them to the video decoder. If the video frame's resolution has changed, video_decoder_refresh() is called. Afterwards, the frame is displayed on the SDL window.
```
void *decode_audio_thread(void *arg);
```
Spawns an audio decoding thread. The argument should hold a pointer to a codec_state. The codec_state is assumed to contain a successfully initialised audio decoder.
All received audio packets are pushed into a jitter buffer and are reordered. If there is a missing packet, or a packet has arrived too late, it is treated as a lost packet and the audio decoder is informed of the packet loss. The audio decoder will then try to reconstruct the lost packet, based on information from previous packets.
Audio is played on the default OpenAL output device.


If you have any more qustions/bug reports/feature request contact the following users on the irc channel #tox-dev on irc.freenode.net:
For RTP and MSI: mannol
For audio and video: Martijnvdc
