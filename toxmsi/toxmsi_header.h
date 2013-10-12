#ifndef _MSI_HEADER_
#define _MSI_HEADER_

/* Basic format of the unparsed header string
 * ( No spaces in field allowed )
 * Version 0.1.1\n\r
 * Request INVITE\n\r
 * Response\n\r
 * Friend-id ( from ip )\n\r
 * Call-type AUDIO\n\r
 * User-agent phone-v.1.0.0\n\r
 */


/* define raw header terminator */
static const char* _RAW_TERMINATOR = "\n\r";

/* define string formats for the identifiers */
#define _VERSION_FIELD          "Version"
#define _REQUEST_FIELD          "Request"
#define _RESPONSE_FIELD         "Response"
#define _FRIENDID_FIELD         "Friend-id"
#define _CALLTYPE_FIELD         "Call-type"
#define _USERAGENT_FIELD        "User-agent"
#define _INFO_FIELD             "INFO"
#define _REASON_FIELD           "Reason"
#define _CALL_ID_FIELD          "Call-id"

#define HEADER_VALUES   \
/*uint8_t* _header_field */ \
uint8_t* _header_value;

typedef struct msi_header_s { /* raw header list */
    uint8_t* _header_field;
    uint8_t* _header_value;

    struct msi_header_s* next;

} msi_header_t;



typedef struct msi_header_version_s { /* Defines our version */
    HEADER_VALUES

} msi_header_version_t;

typedef struct msi_header_request_s { /* Defines our request */
    HEADER_VALUES

} msi_header_request_t;

typedef struct msi_header_response_s { /* Defines our response */
    HEADER_VALUES

} msi_header_response_t;

typedef struct msi_header_friendid_s { /* Defines source that sent the message */
    HEADER_VALUES

} msi_header_friendid_t;

typedef struct msi_header_call_type_s { /* Defines the type of the call */
    HEADER_VALUES

} msi_header_call_type_t;

typedef struct msi_header_user_agent_s { /* Defines the device of the participant */
    HEADER_VALUES

} msi_header_user_agent_t;

typedef struct msi_header_call_id_s { /* Call id that is used to identify the call */
    HEADER_VALUES

} msi_header_call_id_t;

typedef struct msi_header_info_s { /* Defines informational message header */
    HEADER_VALUES

} msi_header_info_t;

typedef struct msi_header_reason_s { /* Defines reason mostly for error messages */
    HEADER_VALUES

} msi_header_reason_t;

struct msi_msg_s;

/*
 * Parses the header list to header types
 */
int             msi_parse_headers ( struct msi_msg_s* _msg );

/* Make sure it's null terminated */
msi_header_t*   msi_parse_raw_data ( const uint8_t* _data );

#endif /* _MSI_HEADER_ */
