#include "netaddr.h"
#include <ccan/cast/cast.h>
#include <netdb.h>
#include <stdlib.h>

void netaddr_to_addrinfo(struct addrinfo *ai, const struct netaddr *a)
{
	ai->ai_flags = 0;
	ai->ai_family = a->saddr.s.sa_family;
	ai->ai_socktype = a->type;
	ai->ai_protocol = a->protocol;
	ai->ai_addrlen = a->addrlen;
	ai->ai_addr = cast_const(struct sockaddr *, &a->saddr.s);
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;
}
