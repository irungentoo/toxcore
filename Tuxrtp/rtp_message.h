#ifndef _RTP__MESSAGE_H_
#define _RTP__MESSAGE_H_

#include "../core/network.h"
#include "../core/helper.h"

#define _MAX_SEQU_NUM 65535
#define _CRSC_LEN(x) (x * 4)

#define DEALLOCATOR_MSG(MSG) \
    free(MSG->_header->_csrc); \
    free(MSG->_header); \
    if(MSG->_ext_header) free(MSG->_ext_header); \
    free(MSG->_data); \
    if ( MSG->next ) free(MSG->next); \
    if ( MSG->prev ) free(MSG->prev);

typedef struct rtp_header_s {
    uint8_t      _flags;             /* Version(2),Padding(1), Ext(1), Cc(4) */
    uint8_t      _marker_payload_t;  /* Marker(1), PlayLoad Type(7) */
    uint16_t     _sequence_number;   /* Sequence Number */
    uint32_t     _timestamp;         /* Timestamp */
    uint32_t     _ssrc;              /* SSRC */
    uint32_t*    _csrc;              /* CSRC's table */

    uint32_t     _length;            /* A little something for allocation */

    } rtp_header_t;

typedef struct rtp_ext_header_s {
    uint16_t     _ext_type;          /* Extension profile */
    uint16_t     _ext_len;           /* Number of extensions */
    uint32_t*    _hd_ext;            /* Extension's table */


    } rtp_ext_header_t;

typedef struct rtp_msg_s {
    struct rtp_header_s*     _header;
    struct rtp_ext_header_s* _ext_header;
    uint32_t                 _header_lenght;

    uint8_t*                 _data;
    uint32_t                 _length;
    IP_Port                  _from;
    struct rtp_msg_s*        next;
    struct rtp_msg_s*        prev;


    } rtp_msg_t;


rtp_header_t*   rtp_extract_header ( uint8_t* payload, size_t size );


uint8_t*        rtp_add_header ( rtp_header_t* _header, uint8_t* payload, size_t size );

/* Adding flags and settings */
void            rtp_header_add_flag_version ( rtp_header_t* _header, int value );
void            rtp_header_add_flag_padding ( rtp_header_t* _header, int value );
void            rtp_header_add_flag_extension ( rtp_header_t* _header, int value );
void            rtp_header_add_flag_CSRC_count ( rtp_header_t* _header, int value );
void            rtp_header_add_setting_marker ( rtp_header_t* _header, int value );
void            rtp_header_add_setting_payload ( rtp_header_t* _header, int value );


/* Getting values from flags and settings */
uint8_t rtp_header_get_flag_version ( rtp_header_t* _header );
uint8_t rtp_header_get_flag_padding ( rtp_header_t* _header );
uint8_t rtp_header_get_flag_extension ( rtp_header_t* _header );
uint8_t rtp_header_get_flag_CSRC_count ( rtp_header_t* _header );
uint8_t rtp_header_get_setting_marker ( rtp_header_t* _header );
uint8_t rtp_header_get_setting_payload_type ( rtp_header_t* _header );

#endif /* _RTP__MESSAGE_H_ */
