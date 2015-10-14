#ifndef LIGHTNING_DAEMON_PRIVKEY_H
#define LIGHTNING_DAEMON_PRIVKEY_H
/* Routines to handle private keys. */
#include "config.h"

struct peer;
struct lightningd_state;

void privkey_sign(struct peer *peer, const void *src, size_t len,
		  unsigned char signature[64]);

void privkey_init(struct lightningd_state *state);

#endif /* LIGHTNING_DAEMON_PRIVKEY_H */
