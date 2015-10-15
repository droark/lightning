#include "cryptopkt.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
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

/* First encrypted packet says who we are and prove that it's us */
struct session_proof {
	/* Signature of all the below using pubkey (FIXME: Serialize!) */
	u8 signature[64];
	/* My node's public key (ie. ID). */
	u8 pubkey[33];
	/* Your session key, to avoid replay. */
	u8 sessionkey[33];
	/* Optional protobuf. */
	u8 optdata[];
};

/* Temporary structure for negotiation (peer->io_data->neg) */
struct key_negotiate {
	/* Our session secret key. */
	u8 seckey[32];

	/* Our pubkey, their pubkey. */
	u8 our_sessionpubkey[33], their_sessionpubkey[33];

	/* Callback once it's all done. */
	struct io_plan *(*cb)(struct io_conn *, struct peer *);
};

/* ARM loves to add padding to structs; be paranoid! */ 
#define SESSION_PROOF_BASE_SIZE (64 + 33 + 33)

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

	/* For negotiation phase. */
	struct key_negotiate *neg;
};

static void *decrypt_pkt(struct peer *peer, struct crypto_pkt *cpkt, size_t *len)
{
	size_t full_len;
	struct sha256 hmac;
	int outlen;
	struct io_data *iod = peer->io_data;

	*len = le64_to_cpu(iod->hdr_in.totlen) - iod->in.totlen;
	full_len = ROUNDUP(*len, AES_BLOCK_SIZE);

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

	return tal_dup_arr(peer, u8, cpkt->data, *len, 0);
}

static struct crypto_pkt *encrypt_pkt(struct peer *peer,
				      const void *data, size_t len,
				      size_t *total_len)
{
	static unsigned char zeroes[AES_BLOCK_SIZE-1];
	struct crypto_pkt *cpkt;
	unsigned char *dout;
	size_t full_len;
	int outlen;
	struct io_data *iod = peer->io_data;

	full_len = ROUNDUP(len, AES_BLOCK_SIZE);
	*total_len = sizeof(*cpkt) + full_len;

	cpkt = (struct crypto_pkt *)tal_arr(peer, char, *total_len);
	iod->out.totlen += len;
	cpkt->totlen = cpu_to_le64(iod->out.totlen);
	
	dout = cpkt->data;
	EVP_EncryptUpdate(&iod->out.evpctx, dout, &outlen,
			  memcheck(data, len), len);
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

	peer->inpkt = decrypt_pkt(peer, iod->in.cpkt, &peer->inpkt_len);
	iod->in.cpkt = tal_free(iod->in.cpkt);

	if (!peer->inpkt)
		return -1;
	iod->in.totlen += peer->inpkt_len;
	return 1;
}

struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *))
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	peer->io_data->len_in = 0;
	arg->u1.vp = peer;
	return io_set_plan(conn, IO_IN, do_read_packet,
			   (struct io_plan *(*)(struct io_conn *, void *))cb,
			   peer);
}

/* Caller must free data! */
struct io_plan *peer_write_packet(struct io_conn *conn,
				  struct peer *peer,
				  const void *data, size_t len,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *))
{
	struct io_data *iod = peer->io_data;
	size_t totlen;

	/* We free previous packet here, rather than doing indirection
	 * via io_write */
	tal_free(iod->out.cpkt);
	iod->out.cpkt = encrypt_pkt(peer, data, len, &totlen);
	return io_write(conn, iod->out.cpkt, totlen, next, peer);
}

static struct io_plan *check_proof(struct io_conn *conn, struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;
	struct session_proof *proof = peer->inpkt;
	secp256k1_pubkey theirid;
	struct sha256 sha;
	secp256k1_ecdsa_signature sig;
	struct io_plan *(*cb)(struct io_conn *, struct peer *);

	if (peer->inpkt_len < SESSION_PROOF_BASE_SIZE) {
		log_unusual(peer->log, "Underlength proof packet %zu",
			    peer->inpkt_len);
		return io_close(conn);
	}

	if (!secp256k1_ec_pubkey_parse(peer->state->secpctx, &theirid,
				       proof->pubkey, sizeof(proof->pubkey))) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad pubkey");
		return io_close(conn);
	}

	/* They should have sent back our session pubkey */
	BUILD_ASSERT(sizeof(neg->our_sessionpubkey)==sizeof(proof->sessionkey));
	if (memcmp(neg->our_sessionpubkey, proof->sessionkey,
		   sizeof(proof->sessionkey)) != 0) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad sessionkey copy");
		return io_close(conn);
	}

	sha256(&sha, (char *)proof + sizeof(proof->signature),
	       peer->inpkt_len - sizeof(proof->signature));
	/* FIXME: deserialize! */
	memcpy(&sig, proof->signature, sizeof(sig));
	if (!secp256k1_ecdsa_verify(peer->state->secpctx, &sig, sha.u.u8,
				    &theirid)) {
		log_unusual(peer->log, "Bad signature");
		return io_close(conn);
	}

	/* FIXME: Parse optdata! */

	/* All complete, return to caller. */
	cb = neg->cb;
	peer->io_data->neg = tal_free(neg);
	return cb(conn, peer);
}

static struct io_plan *receive_proof(struct io_conn *conn, struct peer *peer)
{
	return peer_read_packet(conn, peer, check_proof);
}

static struct io_plan *keys_exchanged(struct io_conn *conn, struct peer *peer)
{
	u8 shared_secret[32];
	secp256k1_pubkey sessionkey;
	size_t outlen;
	struct session_proof proof;
	struct key_negotiate *neg = peer->io_data->neg;

	if (!secp256k1_ec_pubkey_parse(peer->state->secpctx, &sessionkey,
				       neg->their_sessionpubkey,
				       sizeof(neg->their_sessionpubkey))) {
		/* FIXME: Dump key in this case. */
		log_unusual(peer->log, "Bad sessionkey");
		return io_close(conn);
	}

	/* Derive shared secret. */
	if (!secp256k1_ecdh(peer->state->secpctx, shared_secret,
			    &sessionkey, neg->seckey)) {
		log_unusual(peer->log, "Bad ECDH");
		return io_close(conn);
	}

	/* Each side combines with their OWN session key to SENDING crypto. */
	if (!setup_crypto(&peer->io_data->in, shared_secret,
			  neg->their_sessionpubkey)
	    || !setup_crypto(&peer->io_data->out, shared_secret,
			     neg->our_sessionpubkey)) {
		log_unusual(peer->log, "Failed setup_crypto()");
		return io_close(conn);
	}

	/* Now construct, sign and send the proof. */
	secp256k1_ec_pubkey_serialize(peer->state->secpctx,
				      proof.pubkey, &outlen, &peer->state->id,
				      SECP256K1_EC_COMPRESSED);
	assert(outlen == sizeof(proof.pubkey));
	BUILD_ASSERT(sizeof(proof.sessionkey)
		     == sizeof(neg->their_sessionpubkey));
	memcpy(proof.sessionkey, neg->their_sessionpubkey,
	       sizeof(proof.sessionkey));

	/* This is the non-padded size. */
	BUILD_ASSERT(SESSION_PROOF_BASE_SIZE
		     == offsetof(struct session_proof, optdata));

	privkey_sign(peer, (char *)&proof + sizeof(proof.signature),
		     SESSION_PROOF_BASE_SIZE - sizeof(proof.signature),
		     proof.signature);
	
	/* We don't send any optdata */
	return peer_write_packet(conn, peer, &proof, SESSION_PROOF_BASE_SIZE,
				 receive_proof);
}

static struct io_plan *session_key_receive(struct io_conn *conn,
					   struct peer *peer)
{
	struct key_negotiate *neg = peer->io_data->neg;
	/* Now read their key. */
	return io_read(conn, neg->their_sessionpubkey,
		       sizeof(neg->their_sessionpubkey), keys_exchanged, peer);
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

struct io_plan *peer_crypto_setup(struct io_conn *conn, struct peer *peer,
				  struct io_plan *(*cb)(struct io_conn *,
							struct peer *))
{
	size_t outputlen;
	secp256k1_pubkey sessionkey;
	struct key_negotiate *neg;

	peer->io_data = tal(peer, struct io_data);

	/* We store negotiation state here. */
	neg = peer->io_data->neg = tal(peer->io_data, struct key_negotiate);
	neg->cb = cb;

	gen_sessionkey(peer->state->secpctx, neg->seckey, &sessionkey);

	secp256k1_ec_pubkey_serialize(peer->state->secpctx,
				      neg->our_sessionpubkey, &outputlen,
				      &sessionkey,
				      SECP256K1_EC_COMPRESSED);
	assert(outputlen == sizeof(neg->our_sessionpubkey));
	return io_write(conn, neg->our_sessionpubkey, outputlen,
			session_key_receive, peer);
}
