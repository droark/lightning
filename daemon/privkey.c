#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "privkey.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static u8 privkey[32];

void privkey_sign(struct peer *peer, const void *src, size_t len,
		  u8 signature[64])
{
	struct sha256 s;
	secp256k1_ecdsa_signature sig;

	sha256(&s, memcheck(src, len), len);
	if (!secp256k1_ecdsa_sign(peer->state->secpctx, &sig, s.u.u8,
				  privkey, NULL, NULL))
		fatal("Failed to sign %zu bytes", len);

	/* FIXME: marshall compact! */
	memcpy(signature, &sig, sizeof(sig));
}

/* FIXME: We shouldn't make a new privkey every time! */
void privkey_init(struct lightningd_state *state)
{
	u8 pubkey[33];
	size_t outlen;
	int fd = open("privkey", O_RDONLY);

	if (fd < 0) {
		if (errno != ENOENT)
			fatal("Failed to open privkey: %s", strerror(errno));

		log_unusual(state->base_log, "Creating privkey file");
		do {
			if (RAND_bytes(privkey, sizeof(privkey)) != 1)
				fatal("Could not get random bytes for privkey");
		} while (!secp256k1_ec_pubkey_create(state->secpctx, &state->id,
						     privkey));

		fd = open("privkey", O_CREAT|O_EXCL|O_WRONLY, 0400);
		if (fd < 0)
		 	fatal("Failed to create privkey file: %s",
			      strerror(errno));
		if (!write_all(fd, privkey, sizeof(privkey))) {
			unlink_noerr("privkey");
		 	fatal("Failed to write to privkey file: %s",
			      strerror(errno));
		}
		if (fsync(fd) != 0)
		 	fatal("Failed to sync to privkey file: %s",
			      strerror(errno));
		close(fd);

		fd = open("privkey", O_RDONLY);
		if (fd < 0)
			fatal("Failed to reopen privkey: %s", strerror(errno));
	}
	if (!read_all(fd, privkey, sizeof(privkey)))
		fatal("Failed to read privkey: %s", strerror(errno));
	close(fd);
	if (!secp256k1_ec_pubkey_create(state->secpctx, &state->id, privkey))
		fatal("Invalid privkey");

	secp256k1_ec_pubkey_serialize(state->secpctx, pubkey, &outlen,
				      &state->id, SECP256K1_EC_COMPRESSED);
	assert(outlen == sizeof(pubkey));
	log_info(state->base_log, "ID: ");
	log_add_hex(state->base_log, pubkey, outlen);
}
