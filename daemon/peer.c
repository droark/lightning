#include "cryptopkt.h"
#include "dns.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "pkt.h"
#include <arpa/inet.h>
#include <ccan/endian/endian.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Send and receive (encrypted) hello message. */
static struct io_plan *peer_test_check(struct io_conn *conn, struct peer *peer)
{
	if (peer->inpkt_len != 6)
		fatal("Bad packet len %zu", peer->inpkt_len);
	if (memcmp(peer->inpkt, "hello", 6) != 0)
		fatal("Bad packet '%.6s'", (char *)peer->inpkt);
	log_info(peer->log, "Successful hello!");
	return io_close(conn);
}

static struct io_plan *peer_test_read(struct io_conn *conn, struct peer *peer)
{
	return peer_read_packet(conn, peer, peer_test_check);
}

static struct io_plan *peer_test(struct io_conn *conn, struct peer *peer)
{
	return peer_write_packet(conn, peer, "hello", 6, peer_test_read);
}

static u16 get_port(const struct netaddr *addr)
{
	switch (addr->saddr.s.sa_family) {
	case AF_INET:
		return ntohs(addr->saddr.ipv4.sin_port);
	case AF_INET6:
		return ntohs(addr->saddr.ipv6.sin6_port);
	default:
		abort();
	}
}

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->state->peers, &peer->list);
}

static struct peer *new_peer(struct lightningd_state *state,
			     struct io_conn *conn,
			     int addr_type, int addr_protocol,
			     const char *in_or_out)
{
	struct peer *peer = tal(state, struct peer);
	char name[INET6_ADDRSTRLEN];

	/* FIXME: Stop listening if too many peers? */
	list_add(&state->peers, &peer->list);

	peer->state = state;
	peer->addr.type = addr_type;
	peer->addr.protocol = addr_protocol;
	peer->io_data = NULL;

	/* FIXME: Attach IO logging for this peer. */
	tal_add_destructor(peer, destroy_peer);

	peer->addr.addrlen = sizeof(peer->addr.saddr);
	if (getpeername(io_conn_fd(conn), &peer->addr.saddr.s,
			&peer->addr.addrlen) != 0) {
		log_unusual(state->base_log,
			    "Could not get address for peer: %s",
			    strerror(errno));
		return tal_free(peer);
	}

	if (!inet_ntop(peer->addr.saddr.s.sa_family, &peer->addr.saddr,
		       name, INET6_ADDRSTRLEN))
		strcpy(name, "UNCONVERTABLE-ADDR");

	peer->log = new_log(peer, state->log_record, "%s-%s:%s:%u",
			    log_prefix(state->base_log), in_or_out,
			    name, get_port(&peer->addr));
	return peer;
}

struct io_plan *peer_connected_out(struct io_conn *conn,
				   struct lightningd_state *state,
				   const char *name, const char *port)
{
	struct peer *peer = new_peer(state, conn, SOCK_STREAM, IPPROTO_TCP,
				     "out");
	if (!peer) {
		log_unusual(peer->log, "Failed to make peer for %s:%s",
			    name, port);
		return io_close(conn);
	}
	log_info(peer->log, "Connected out to %s:%s", name, port);
	return peer_crypto_setup(conn, peer, peer_test);
}

static struct io_plan *peer_connected_in(struct io_conn *conn,
					 struct lightningd_state *state)
{
	struct peer *peer = new_peer(state, conn, SOCK_STREAM, IPPROTO_TCP,
				     "in");
	if (!peer)
		return io_close(conn);

	log_info(peer->log, "Peer connected in");
	return peer_crypto_setup(conn, peer, peer_test);
}

static int make_listen_fd(struct lightningd_state *state,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(state->base_log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (!addr || bind(fd, addr, len) == 0) {
		if (listen(fd, 5) == 0)
			return fd;
		log_unusual(state->base_log, "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
	} else
		log_debug(state->base_log, "Failed to bind on %u socket: %s",
			  domain, strerror(errno));

	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd_state *state, unsigned int portnum)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;
	u16 listen_port;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(state, AF_INET6, portnum ? &addr6 : NULL,
			     sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(state->base_log,
				    "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			addr.sin_port = in6.sin6_port;
			listen_port = ntohs(addr.sin_port);
			log_info(state->base_log,
				 "Creating IPv6 listener on port %u",
				 listen_port);
			io_new_listener(state, fd1, peer_connected_in, state);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(state, AF_INET,
			     addr.sin_port ? &addr : NULL, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(state->base_log,
				    "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			listen_port = ntohs(addr.sin_port);
			log_info(state->base_log,
				 "Creating IPv4 listener on port %u",
				 listen_port);
			io_new_listener(state, fd2, peer_connected_in, state);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address");
}

static char *json_connect(struct json_connection *jcon,
			  const jsmntok_t *params,
			  struct json_result *response)
{
	jsmntok_t *host, *port;
	const char *hoststr, *portstr;

	json_get_params(jcon->buffer, params, "host", &host, "port", &port,
			NULL);

	if (!host || !port)
		return "Need host and port";

	hoststr = tal_strndup(response, jcon->buffer + host->start,
			      host->end - host->start);
	portstr = tal_strndup(response, jcon->buffer + port->start,
			      port->end - port->start);
	if (!dns_resolve_and_connect(jcon->state, hoststr, portstr,
				     peer_connected_out))
		return "DNS failed";

	json_object_start(response, NULL);
	json_object_end(response);
	return NULL;
}

const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port}",
	"Returns an empty result (meaning connection in progress)"
};
