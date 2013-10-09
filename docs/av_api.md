A/V API reference

Take toxmsi/phone.c as a reference

Initialization:

phone_t* initPhone(uint16_t _listen_port, uint16_t _send_port);
function initializes sample phone. _listen_port and _send_port are variables only meant
for local testing. You will not have to do anything regarding to that since
everything will be started within a mesenger.


Phone requires one msi session and two rtp sessions ( one for audio and one for
video ). 

msi_session_t* msi_init_session( void* _core_handler, const uint8_t* _user_agent );

initializes msi session.
Params:
void* _core_handler - pointer to an object handling networking,
const uint8_t* _user_agent - string describing phone client version.

Return value:
msi_session_t* - pointer to a newly created msi session handler.

msi_session_t reference:

How to handle msi session:
Controling is done via callbacks and action handlers.
First register callbacks for every state/action received and make sure
NOT TO PLACE SOMETHING LIKE LOOPS THAT TAKES A LOT OF TIME TO EXECUTE; every callback is being called 
directly from event loop. You can find examples in phone.c.

Register callbacks: 
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

MCALLBACK is defined as: void (*callback) (void* _arg)
msi_session_t* handler is being thrown as _arg so you can use that and _agent_handler to get to your own phone handler
directly from callback.


Actions:
int msi_invite ( msi_session_t* _session, call_type _call_type, uint32_t _timeoutms );
Sends call invite. Before calling/sending invite msi_session_t::_friend_id is needed to be set or else
it will not work. _call_type is type of the call ( Audio/Video ) and _timeoutms is how long 
will poll wait until request is terminated.

int msi_hangup ( msi_session_t* _session );
Hangs up active call

int msi_answer ( msi_session_t* _session, call_type _call_type );
Answer incomming call. _call_type set's callee call type.

int msi_cancel ( msi_session_t* _session );
Cancel current request.

int msi_reject ( msi_session_t* _session );
Reject incomming call.




Now for rtp:
You will need 2 sessions; one for audio one for video.
You start them with:

rtp_session_t* rtp_init_session ( int _max_users, int _multi_session );

Params:
int _max_users - max users. -1 if undefined
int _multi_session - any positive number means uses multi session; -1 if not.

Return value:
rtp_session_t* - pointer to a newly created rtp session handler.

How to handle rtp session:
Take a look at
void* phone_handle_media_transport_poll ( void* _hmtc_args_p ) in phone.c
on example. Basically what you do is just receive a message via:

struct rtp_msg_s* rtp_recv_msg ( rtp_session_t* _session );

and then you use payload within the rtp_msg_s struct. Don't forget to deallocate it with:
void rtp_free_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg );
Receiving should be thread safe so don't worry about that.

When you capture and encode a payload you want to send it ( obvoisly ).

first create a new message with:
struct rtp_msg_s* rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length );

and then send it with:
int rtp_send_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg, void* _core_handler );

_core_handler is the same network handler as in msi_session_s struct.

That's pretty much it, if you have any more qustions/bug reports/feature request contact 
me on the irc channel #tox-dev on irc.freenode.net under nick mannol or ask Martijnvdc.


A/V Encoding Decoding:

