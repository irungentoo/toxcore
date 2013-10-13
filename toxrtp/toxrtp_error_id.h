#ifndef _RTP_ERROR_ID_
#define _RTP_ERROR_ID_

#include "toxrtp_error.h"

typedef enum error_s {
    RTP_ERROR_PACKET_DROPED = 1,
    RTP_ERROR_EMPTY_MESSAGE,
    RTP_ERROR_STD_SEND_FAILURE,
    RTP_ERROR_NO_EXTERNAL_HEADER,
    RTP_ERROR_INVALID_EXTERNAL_HEADER,
    RTP_ERROR_HEADER_PARSING,
    RTP_ERROR_PAYLOAD_NULL,
    RTP_ERROR_PAYLOAD_INVALID,

} error_t;


/* Only needed to be called once */
#ifndef REGISTER_RTP_ERRORS
#define REGISTER_RTP_ERRORS \
    t_rtperr_register( RTP_ERROR_PACKET_DROPED, "Ivalid sequence number, packet is late" ); \
    t_rtperr_register( RTP_ERROR_EMPTY_MESSAGE, "Tried to send an empty message" ); \
    t_rtperr_register( RTP_ERROR_STD_SEND_FAILURE, "Failed call function: sendto" ); \
    t_rtperr_register( RTP_ERROR_NO_EXTERNAL_HEADER, "While parsing external header" ); \
    t_rtperr_register( RTP_ERROR_INVALID_EXTERNAL_HEADER, "While parsing external header" ); \
    t_rtperr_register( RTP_ERROR_HEADER_PARSING, "While parsing header" ); \
    t_rtperr_register( RTP_ERROR_PAYLOAD_NULL, "Payload is NULL" ); \
    t_rtperr_register( RTP_ERROR_PAYLOAD_INVALID, "Invalid payload size" );
#endif /* REGISTER_RTP_ERRORS */

#endif /* _RTP_ERROR_ID_ */
