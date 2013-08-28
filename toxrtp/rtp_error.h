#ifndef _RTP_ERROR_
#define _RTP_ERROR_

#define PRINT_FORMAT "Error %d: %s at %s:%d\n"
#define PRINT_ARGS( _errno ) _errno, t_rtperr(_errno), __FILE__, __LINE__


const char* t_rtperr ( int _errno );
void        t_rtperr_register ( int _id, const char* _info );

void        t_invoke_error ( int _id );
void        t_rtperr_print ( const char* _val, ... );

#define t_perror( _errno ) t_rtperr_print ( PRINT_FORMAT, PRINT_ARGS ( _errno ) )

#ifdef _STDIO_H /* I don't want you be telling me error handlers produce errors */
#define t_errexit( _errno ) exit(-_errno)
#endif /* _STDIO_H */

#endif /* _RTP_ERROR_ */
