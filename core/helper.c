#include "helper.h"
#include "network.h"

int set_ip_port(const char* _ip, short _port, void* _dest)
{
	if ( !_dest )
	{
		return FAILURE;
	}

    IP_Port* _dest_c = (IP_Port*) _dest;

	_dest_c->ip.i = inet_addr(_ip);
	_dest_c->port = htons(_port);

    return SUCCESS;
}
