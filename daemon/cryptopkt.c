#include "cryptopkt.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "pkt.h"
#include "privkey.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/io/io_plan.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <inttypes.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#define MAX_PKT_LEN (1024 * 1024)

#define ROUNDUP(x,a) (((x) + ((a)-1)) & ~((a)-1))

struct crypto_pkt {
	/* HMAC */
	struct sha256 hmac;
	/* Total length transmitted. */
	le64 totlen;
	/* ... contents... */
	u8 data[];
};

/* We open/restart a conversation with this. */
struct intro {
	/* My node's public key (ie. ID). */
	u8 pubkey[33];
	/* Temporary key for ECDH */
	u8 sessionkey[33];
	/* Signature of all the above (FIXME: Serialize!) */
	u8 signature[64];
};

/* ARM loves to add padding to structs. :( */ 
#define INTRO_SIZE (33 + 33 + 64)

#define ENCKEY_SEED 0
#define HMACKEY_SEED 1
#define IV_SEED 2

struct enckey {
	struct sha256 k;
};

struct hmackey {
	struct sha256 k;
};

struct iv {
	unsigned char iv[AES_BLOCK_SIZE];
};

static void sha_with_seed(const unsigned char secret[32],
			  const unsigned char serial_pubkey[33],
			  unsigned char seed,
			  struct sha256 *res)
{
	struct sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, memcheck(secret, 32), 32);
	sha256_update(&ctx, memcheck(serial_pubkey, 33), 33);
	sha256_u8(&ctx, seed);
	sha256_done(&ctx, res);
}

static struct enckey enckey_from_secret(const unsigned char secret[32],
					const unsigned char serial_pubkey[33])
{
	struct enckey enckey;
	sha_with_seed(secret, serial_pubkey, ENCKEY_SEED, &enckey.k);
	return enckey;
}

static struct hmackey hmackey_from_secret(const unsigned char secret[32],
					  const unsigned char serial_pubkey[33])
{
	struct hmackey hmackey;
	sha_with_seed(secret, serial_pubkey, HMACKEY_SEED, &hmackey.k);
	return hmackey;
}

static struct iv iv_from_secret(const unsigned char secret[32],
				const unsigned char serial_pubkey[33])
{
	struct sha256 sha;
	struct iv iv;

	sha_with_seed(secret, serial_pubkey, IV_SEED, &sha);
	memcpy(iv.iv, sha.u.u8, sizeof(iv.iv));
	return iv;
}

struct dir_state {
	u64 totlen;
	struct hmackey hmackey;
	EVP_CIPHER_CTX evpctx;

	/* Current packet. */
	struct crypto_pkt *cpkt;
};

static bool setup_crypto(struct dir_state *dir,
			 u8 shared_secret[32], u8 serial_pubkey[33])
{
	struct iv iv;
	struct enckey enckey;

	dir->totlen = 0;	
	dir->hmackey = hmackey_from_secret(shared_secret, serial_pubkey);
	dir->cpkt = NULL;
	
	iv = iv_from_secret(shared_secret, serial_pubkey);
	enckey = enckey_from_secret(shared_secret, serial_pubkey);

	return EVP_EncryptInit(&dir->evpctx, EVP_aes_128_ctr(),
			       memcheck(enckey.k.u.u8, sizeof(enckey.k)),
			       memcheck(iv.iv, sizeof(iv.iv))) == 1;
}

struct io_data {
	/* Stuff we need to keep around to talk to peer. */
	struct dir_state in, out;

	/* Header we're currently reading. */
	size_t len_in;
	struct crypto_pkt hdr_in;
};

static struct pkt *decrypt_pkt(struct peer *peer, struct crypto_pkt *cpkt)
{
	size_t len, full_len;
	struct sha256 hmac;
	struct pkt *pkt;
	int outlen;
	struct io_data *iod = peer->io_data;

	len = le64_to_cpu(iod->hdr_in.totlen) - iod->in.totlen;
	full_len = ROUNDUP(len, AES_BLOCK_SIZE);

	HMAC(EVP_sha256(), iod->in.hmackey.k.u.u8, sizeof(iod->in.hmackey),
	     (unsigned char *)&cpkt->totlen, sizeof(cpkt->totlen) + full_len,
	     hmac.u.u8, NULL);

	if (CRYPTO_memcmp(&hmac, &cpkt->hmac, sizeof(hmac)) != 0) {
		log_unusual(peer->log, "Packet has bad HMAC");
		return NULL;
	}

	/* FIXME: Assumes we can decrypt in place! */
	EVP_DecryptUpdate(&iod->in.evpctx, cpkt->data, &outlen,
			  memcheck(cpkt->data, full_len), full_len);
	assert(outlen == full_len);

	pkt = (struct pkt *)tal_arr(peer, char, sizeof(*pkt) + len);
	/* FIXME: Make this just u32, since it's not sent on wire! */
	pkt->len = le32_to_cpu(len);
	memcpy(pkt->data, cpkt->data, len);

	return pkt;
}

static struct crypto_pkt *encrypt_pkt(struct peer *peer, const struct pkt *pkt,
				      size_t *total_len)
{
	static unsigned char zeroes[AES_BLOCK_SIZE-1];
	struct crypto_pkt *cpkt;
	unsigned char *dout;
	size_t len, full_len;
	int outlen;
	struct io_data *iod = peer->io_data;

	len = le32_to_cpu(pkt->len);
	full_len = ROUNDUP(len, AES_BLOCK_SIZE);
	*total_len = sizeof(*cpkt) + full_len;

	cpkt = (struct crypto_pkt *)tal_arr(peer, char, *total_len);
	iod->out.totlen += len;
	cpkt->totlen = cpu_to_le64(iod->out.totlen);

	dout = cpkt->data;
	EVP_EncryptUpdate(&iod->out.evpctx, dout, &outlen,
			  memcheck(pkt->data, len), len);
	dout += outlen;

	/* Now encrypt tail, padding with zeroes if necessary. */
	EVP_EncryptUpdate(&iod->out.evpctx, dout, &outlen, zeroes,
			  full_len - len);
	assert(dout + outlen == cpkt->data + full_len);

	HMAC(EVP_sha256(), iod->out.hmackey.k.u.u8, sizeof(iod->out.hmackey),
	     (unsigned char *)&cpkt->totlen, sizeof(cpkt->totlen) + full_len,
	     cpkt->hmac.u.u8, NULL);

	return cpkt;
}

static int do_read_packet(int fd, struct io_plan_arg *arg)
{
	struct peer *peer = arg->u1.vp;
	struct io_data *iod = peer->io_data;
	u64 max;
	size_t data_off;
	int ret;

	/* Still reading header? */
	if (iod->len_in < sizeof(iod->hdr_in)) {
		ret = read(fd, (char *)&iod->hdr_in + iod->len_in,
			   sizeof(iod->hdr_in) - iod->len_in);
		if (ret <= 0)
			return -1;
		iod->len_in += ret;
		/* We don't ever send empty packets, so don't check for
		 * that here. */
		return 0;
	}

	max = ROUNDUP(le64_to_cpu(iod->hdr_in.totlen) - iod->in.totlen,
		      AES_BLOCK_SIZE);

	if (iod->len_in == sizeof(iod->hdr_in)) {
		/* FIXME: Handle re-xmit. */
		if (le64_to_cpu(iod->hdr_in.totlen) < iod->in.totlen) {
			log_unusual(peer->log,
				    "Packet went backwards: %"PRIu64
				    " -> %"PRIu64,
				    iod->in.totlen,
				    le64_to_cpu(iod->hdr_in.totlen));
			return -1;
		}
		if (le64_to_cpu(iod->hdr_in.totlen)
		    > iod->in.totlen + MAX_PKT_LEN) {
			log_unusual(peer->log,
				    "Packet overlength: %"PRIu64" -> %"PRIu64,
				    iod->in.totlen,
				    le64_to_cpu(iod->hdr_in.totlen));
			return -1;
		}
		iod->in.cpkt = (struct crypto_pkt *)
			tal_arr(iod, u8, sizeof(struct crypto_pkt) + max);
		memcpy(iod->in.cpkt, &iod->hdr_in, sizeof(iod->hdr_in));
	}

	data_off = iod->len_in - sizeof(struct crypto_pkt);
	ret = read(fd, iod->in.cpkt->data + data_off, max - data_off);
	if (ret <= 0)
		return -1;

	iod->len_in += ret;
	if (iod->len_in <= max)
		return 0;

	*((struct pkt **)arg->u2.vp) = decrypt_pkt(peer, iod->in.cpkt);
	iod->in.cpkt = tal_free(iod->in.cpkt);

	if (!*((struct pkt **)arg->u2.vp))
		return -1;
	iod->in.totlen += max;
	return 1;
}

struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct pkt **pkt,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *))
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	peer->io_data->len_in = 0;
	arg->u1.vp = peer;
	arg->u2.vp = pkt;

	return io_set_plan(conn, IO_IN, do_read_packet,
			   (struct io_plan *(*)(struct io_conn *, void *))cb,
			   peer);
}

/* Caller must free pkt! */
struct io_plan *peer_write_packet(struct io_conn *conn,
				  struct peer *peer,
				  const struct pkt *pkt,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *))
{
	struct io_data *iod = peer->io_data;
	size_t totlen;

	/* We free previous packet here, rather than doing indirection
	 * via io_write */
	tal_free(iod->out.cpkt);
	iod->out.cpkt = encrypt_pkt(peer, pkt, &totlen);
	return io_write(conn, iod->out.cpkt, totlen, next, peer);
}

struct key_negotiate {
	struct peer *peer;
	u8 seckey[32];

	struct intro intro;
	struct io_plan *(*cb)(struct io_conn *, struct peer *);
};

static struct io_plan *handshake_complete(struct io_conn *conn,
					  struct key_negotiate *neg)
{
	secp256k1_pubkey theirkey, sessionkey;
	struct peer *peer = neg->peer;
	struct sha256 sha;
	size_t outlen;
	secp256k1_ecdsa_signature sig;
	u8 shared_secret[32];
	u8 serial_pubkey[33];
	struct io_plan *(*cb)(struct io_conn *, struct peer *);

	if (!secp256k1_ec_pubkey_parse(peer->state->secpctx, &theirkey,
				       neg->intro.pubkey,
				       sizeof(neg->intro.pubkey))) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad pubkey");
		return io_close(conn);
	}

	if (!secp256k1_ec_pubkey_parse(peer->state->secpctx, &sessionkey,
				       neg->intro.sessionkey,
				       sizeof(neg->intro.sessionkey))) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad sessionkey");
		return io_close(conn);
	}

	sha256(&sha, &neg->intro, INTRO_SIZE - sizeof(neg->intro.signature));
	/* FIXME: deserialize! */
	memcpy(&sig, neg->intro.signature, sizeof(sig));
	if (!secp256k1_ecdsa_verify(peer->state->secpctx, &sig, sha.u.u8,
				    &theirkey)) {
		log_unusual(peer->log, "Bad signature");
		return io_close(conn);
	}

	/* Derive shared secret. */
	if (!secp256k1_ecdh(peer->state->secpctx, shared_secret,
			    &sessionkey, neg->seckey)) {
		log_unusual(peer->log, "Bad ECDH");
		return io_close(conn);
	}

	peer->io_data = tal(peer, struct io_data);

	/* We need our serialized key again, for output crypto setup */
	secp256k1_ec_pubkey_serialize(peer->state->secpctx,
				      serial_pubkey, &outlen, &peer->state->id,
				      SECP256K1_EC_COMPRESSED);
	assert(outlen == sizeof(serial_pubkey));

	/* Each side combines with their OWN pubkey to SENDING crypto. */
	if (!setup_crypto(&peer->io_data->in, shared_secret, neg->intro.pubkey)
	    || !setup_crypto(&peer->io_data->out, shared_secret, serial_pubkey)){
		log_unusual(peer->log, "Failed setup_crypto()");
		return io_close(conn);
	}
	
	/* All complete, return to caller. */
	cb = neg->cb;
	tal_free(neg);
	return cb(conn, peer);
}

static struct io_plan *intro_receive(struct io_conn *conn,
				     struct key_negotiate *neg)
{
	/* Now read their intro. */
	return io_read(conn, &neg->intro, INTRO_SIZE, handshake_complete, neg);
}

static void gen_sessionkey(secp256k1_context *ctx,
			   u8 seckey[32],
			   secp256k1_pubkey *pubkey)
{
	do {
		if (RAND_bytes(seckey, 32) != 1)
			fatal("Could not get random bytes for sessionkey");
	} while (!secp256k1_ec_pubkey_create(ctx, pubkey, seckey));
}
	
/* FIXME: We should write out canned node info first, eg. what
 * services we offer. */
struct io_plan *peer_crypto_setup(struct io_conn *conn, struct peer *peer,
				  struct io_plan *(*cb)(struct io_conn *,
							struct peer *))
{
	/* This looks like a crypto packet, so we can use the same thing
	 * for key refresh or in connectionless protocols. */
	struct key_negotiate *neg = tal(conn, struct key_negotiate);
	size_t outputlen;
	secp256k1_pubkey sessionkey;

	neg->peer = peer;
	neg->cb = cb;
	gen_sessionkey(peer->state->secpctx, neg->seckey, &sessionkey);

	/* This is the non-padded size. */
	BUILD_ASSERT(INTRO_SIZE <= sizeof(neg->intro));
	BUILD_ASSERT(INTRO_SIZE
		     == (offsetof(struct intro, signature)
			 + sizeof(neg->intro.signature)));

	secp256k1_ec_pubkey_serialize(peer->state->secpctx,
				      neg->intro.pubkey, &outputlen,
				      &peer->state->id,
				      SECP256K1_EC_COMPRESSED);
	assert(outputlen == sizeof(neg->intro.pubkey));
	secp256k1_ec_pubkey_serialize(peer->state->secpctx,
				      neg->intro.sessionkey, &outputlen,
				      &sessionkey,
				      SECP256K1_EC_COMPRESSED);
	assert(outputlen == sizeof(neg->intro.sessionkey));

	privkey_sign(peer, &neg->intro,
		     INTRO_SIZE - sizeof(neg->intro.signature),
		     neg->intro.signature);

	return io_write(conn, &neg->intro, INTRO_SIZE, intro_receive, neg);
}
