/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2017 Sartura d.o.o.
 *
 * Author: Juraj Vijtiuk <juraj.vijtiuk@sartura.hr>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "libssh_esp32_config.h"

#include "libssh/wrapper.h"
#include "libssh/crypto.h"
#include "libssh/priv.h"
#include "libssh/misc.h"
#if defined(MBEDTLS_CHACHA20_C) && defined(MBEDTLS_POLY1305_C)
#include "libssh/bytearray.h"
#include "libssh/chacha20-poly1305-common.h"
#include <mbedtls/chacha20.h>
#include <mbedtls/poly1305.h>
#endif

#ifdef HAVE_LIBMBEDCRYPTO
#include <mbedtls/md.h>
#ifdef MBEDTLS_GCM_C
#include <mbedtls/gcm.h>
#endif /* MBEDTLS_GCM_C */

static mbedtls_entropy_context ssh_mbedtls_entropy;
static mbedtls_ctr_drbg_context ssh_mbedtls_ctr_drbg;

static int libmbedcrypto_initialized = 0;

void ssh_reseed(void)
{
    mbedtls_ctr_drbg_reseed(&ssh_mbedtls_ctr_drbg, NULL, 0);
}

int ssh_get_random(void *where, int len, int strong)
{
    return ssh_mbedtls_random(where, len, strong);
}

SHACTX sha1_init(void)
{
    SHACTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha1_update_esp32_port(SHACTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha1_final(unsigned char *md, SHACTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

__attribute__((weak))
void sha1(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

static mbedtls_md_type_t nid_to_md_algo(int nid)
{
    switch (nid) {
        case NID_mbedtls_nistp256:
            return MBEDTLS_MD_SHA256;
        case NID_mbedtls_nistp384:
            return MBEDTLS_MD_SHA384;
        case NID_mbedtls_nistp521:
            return MBEDTLS_MD_SHA512;
    }
    return MBEDTLS_MD_NONE;
}

void evp(int nid, unsigned char *digest, int len,
        unsigned char *hash, unsigned int *hlen)
{
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);


    if (md_info != NULL) {
        *hlen = mbedtls_md_get_size(md_info);
        mbedtls_md(md_info, digest, len, hash);
    }
}

EVPCTX evp_init(int nid)
{
    EVPCTX ctx = NULL;
    int rc;
    mbedtls_md_type_t algo = nid_to_md_algo(nid);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(algo);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void evp_update(EVPCTX ctx, const void *data, unsigned long len)
{
    mbedtls_md_update(ctx, data, len);
}

void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen)
{
    *mdlen = mbedtls_md_get_size(ctx->md_info);
    mbedtls_md_finish(ctx, md);
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
}

SHA256CTX sha256_init(void)
{
    SHA256CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if(ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha256_update(SHA256CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha256_final(unsigned char *md, SHA256CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha256(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA384CTX sha384_init(void)
{
    SHA384CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha384_update(SHA384CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha384_final(unsigned char *md, SHA384CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha384(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

SHA512CTX sha512_init(void)
{
    SHA512CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}

void sha512_update(SHA512CTX c, const void *data, unsigned long len)
{
    mbedtls_md_update(c, data, len);
}

void sha512_final(unsigned char *md, SHA512CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

void sha512(const unsigned char *digest, int len, unsigned char *hash)
{
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (md_info != NULL) {
        mbedtls_md(md_info, digest, len, hash);
    }
}

MD5CTX md5_init(void)
{
    MD5CTX ctx = NULL;
    int rc;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if (md_info == NULL) {
        return NULL;
    }

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_md_init(ctx);

    rc = mbedtls_md_setup(ctx, md_info, 0);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    rc = mbedtls_md_starts(ctx);
    if (rc != 0) {
        SAFE_FREE(ctx);
        return NULL;
    }

    return ctx;
}


void md5_update_esp32_port(MD5CTX c, const void *data, unsigned long len) {
    mbedtls_md_update(c, data, len);
}

void md5_final(unsigned char *md, MD5CTX c)
{
    mbedtls_md_finish(c, md);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

int ssh_kdf(struct ssh_crypto_struct *crypto,
            unsigned char *key, size_t key_len,
            int key_type, unsigned char *output,
            size_t requested_len)
{
    return sshkdf_derive_key(crypto, key, key_len,
                             key_type, output, requested_len);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type)
{
    HMACCTX ctx = NULL;
    const mbedtls_md_info_t *md_info = NULL;
    int rc;

    ctx = malloc(sizeof(mbedtls_md_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    switch (type) {
        case SSH_HMAC_SHA1:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            break;
        case SSH_HMAC_SHA256:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case SSH_HMAC_SHA512:
            md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        default:
            goto error;
    }

    mbedtls_md_init(ctx);

    if (md_info == NULL) {
        goto error;
    }

    rc = mbedtls_md_setup(ctx, md_info, 1);
    if (rc != 0) {
        goto error;
    }

    rc = mbedtls_md_hmac_starts(ctx, key, len);
    if (rc != 0) {
        goto error;
    }

    return ctx;

error:
    mbedtls_md_free(ctx);
    SAFE_FREE(ctx);
    return NULL;
}

void hmac_update(HMACCTX c, const void *data, unsigned long len)
{
    mbedtls_md_hmac_update(c, data, len);
}

void hmac_final(HMACCTX c, unsigned char *hashmacbuf, unsigned int *len)
{
    *len = mbedtls_md_get_size(c->md_info);
    mbedtls_md_hmac_finish(c, hashmacbuf);
    mbedtls_md_free(c);
    SAFE_FREE(c);
}

static int
cipher_init(struct ssh_cipher_struct *cipher,
            mbedtls_operation_t operation,
            void *key,
            void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    mbedtls_cipher_context_t *ctx;
    int rc;

    if (operation == MBEDTLS_ENCRYPT) {
        ctx = &cipher->encrypt_ctx;
    } else if (operation == MBEDTLS_DECRYPT) {
        ctx = &cipher->decrypt_ctx;
    } else {
        SSH_LOG(SSH_LOG_WARNING, "unknown operation");
        return 1;
    }

    mbedtls_cipher_init(ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_cipher_setup(ctx, cipher_info);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setup failed");
        goto error;
    }

    rc = mbedtls_cipher_setkey(ctx, key,
                               cipher_info->key_bitlen,
                               operation);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_setkey failed");
        goto error;
    }

    rc = mbedtls_cipher_set_iv(ctx, IV, cipher_info->iv_size);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_iv failed");
        goto error;
    }

    return 0;
error:
    mbedtls_cipher_free(ctx);
    return 1;
}

static int
cipher_set_encrypt_key(struct ssh_cipher_struct *cipher,
                       void *key,
                       void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_ENCRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    return SSH_ERROR;
}

static int
cipher_set_encrypt_key_cbc(struct ssh_cipher_struct *cipher,
                           void *key,
                           void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_ENCRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    /* libssh only encypts and decrypts packets that are multiples of a block
     * size, and no padding is used */
    rc = mbedtls_cipher_set_padding_mode(&cipher->encrypt_ctx,
            MBEDTLS_PADDING_NONE);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    rc = mbedtls_cipher_reset(&cipher->encrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    return SSH_ERROR;
}

#ifdef MBEDTLS_GCM_C
static int
cipher_set_key_gcm(struct ssh_cipher_struct *cipher,
                   void *key,
                   void *IV)
{
    const mbedtls_cipher_info_t *cipher_info = NULL;
    int rc;

    mbedtls_gcm_init(&cipher->gcm_ctx);
    cipher_info = mbedtls_cipher_info_from_type(cipher->type);

    rc = mbedtls_gcm_setkey(&cipher->gcm_ctx,
                            MBEDTLS_CIPHER_ID_AES,
                            key,
                            cipher_info->key_bitlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_setkey failed");
        goto error;
    }

    /* Store the IV so we can increment the packet counter later */
    memcpy(cipher->last_iv, IV, AES_GCM_IVLEN);

    return 0;
error:
    mbedtls_gcm_free(&cipher->gcm_ctx);
    return 1;
}
#endif /* MBEDTLS_GCM_C */

static int
cipher_set_decrypt_key(struct ssh_cipher_struct *cipher,
                       void *key,
                       void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_DECRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static int
cipher_set_decrypt_key_cbc(struct ssh_cipher_struct *cipher,
                           void *key,
                           void *IV)
{
    int rc;

    rc = cipher_init(cipher, MBEDTLS_DECRYPT, key, IV);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "cipher_init failed");
        goto error;
    }

    rc = mbedtls_cipher_set_padding_mode(&cipher->decrypt_ctx,
            MBEDTLS_PADDING_NONE);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_set_padding_mode failed");
        goto error;
    }

    mbedtls_cipher_reset(&cipher->decrypt_ctx);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed");
        goto error;
    }

    return SSH_OK;
error:
    mbedtls_cipher_free(&cipher->decrypt_ctx);
    return SSH_ERROR;
}

static void cipher_encrypt(struct ssh_cipher_struct *cipher,
                           void *in,
                           void *out,
                           size_t len)
{
    size_t outlen = 0;
    size_t total_len = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->encrypt_ctx, (unsigned char *) out + outlen,
            &outlen);

    total_len += outlen;

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during encryption");
        return;
    }

    if (total_len != len) {
#ifndef ESP32
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
#else
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %u for %u",
                outlen, len);
#endif
        return;
    }

}

static void cipher_encrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        size_t len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->encrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during encryption");
        return;
    }

    if (outlen != len) {
#ifndef ESP32
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
#else
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %u for %u",
                outlen, len);
#endif
        return;
    }

}

static void cipher_decrypt(struct ssh_cipher_struct *cipher,
                           void *in,
                           void *out,
                           size_t len)
{
    size_t outlen = 0;
    int rc = 0;
    size_t total_len = 0;

    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len == len) {
        return;
    }

    rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
            outlen, &outlen);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    total_len += outlen;

    if (total_len != len) {
#ifndef ESP32
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
#else
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %u for %u",
                outlen, len);
#endif
        return;
    }

}

static void cipher_decrypt_cbc(struct ssh_cipher_struct *cipher, void *in, void *out,
        size_t len)
{
    size_t outlen = 0;
    int rc = 0;
    rc = mbedtls_cipher_update(&cipher->decrypt_ctx, in, len, out, &outlen);
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update failed during decryption");
        return;
    }

    /* MbedTLS caches the last block when decrypting with cbc.
     * By calling finish the block is flushed to out, however the unprocessed
     * data counter is not reset.
     * Calling mbedtls_cipher_reset resets the unprocessed data counter.
     */
    if (outlen == 0) {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, out, &outlen);
    } else if (outlen == len) {
        return;
    } else {
        rc = mbedtls_cipher_finish(&cipher->decrypt_ctx, (unsigned char *) out +
                outlen , &outlen);
    }

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_finish failed during decryption");
        return;
    }

    rc = mbedtls_cipher_reset(&cipher->decrypt_ctx);

    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_reset failed during decryption");
        return;
    }

    if (outlen != len) {
#ifndef ESP32
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %zu for %zu",
                outlen, len);
#else
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_cipher_update: output size %u for %u",
                outlen, len);
#endif
        return;
    }

}

#ifdef MBEDTLS_GCM_C
static int
cipher_gcm_get_length(struct ssh_cipher_struct *cipher,
                      void *in,
                      uint8_t *out,
                      size_t len,
                      uint64_t seq)
{
    (void)cipher;
    (void)seq;

    /* The length is not encrypted: Copy it to the result buffer */
    memcpy(out, in, len);

    return SSH_OK;
}

static void
cipher_encrypt_gcm(struct ssh_cipher_struct *cipher,
                   void *in,
                   void *out,
                   size_t len,
                   uint8_t *tag,
                   uint64_t seq)
{
    size_t authlen, aadlen;
    int rc;

    (void) seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    /* The length is not encrypted */
    memcpy(out, in, aadlen);
    rc = mbedtls_gcm_crypt_and_tag(&cipher->gcm_ctx,
                                   MBEDTLS_GCM_ENCRYPT,
                                   len - aadlen, /* encrypted data len */
                                   cipher->last_iv, /* IV */
                                   AES_GCM_IVLEN,
                                   in, /* aad */
                                   aadlen,
                                   (const unsigned char *)in + aadlen, /* input */
                                   (unsigned char *)out + aadlen, /* output */
                                   authlen,
                                   tag); /* tag */
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_crypt_and_tag failed");
        return;
    }

    /* Increment the IV for the next invocation */
    uint64_inc(cipher->last_iv + 4);
}

static int
cipher_decrypt_gcm(struct ssh_cipher_struct *cipher,
                   void *complete_packet,
                   uint8_t *out,
                   size_t encrypted_size,
                   uint64_t seq)
{
    size_t authlen, aadlen;
    int rc;

    (void) seq;

    aadlen = cipher->lenfield_blocksize;
    authlen = cipher->tag_size;

    rc = mbedtls_gcm_auth_decrypt(&cipher->gcm_ctx,
                                  encrypted_size, /* encrypted data len */
                                  cipher->last_iv, /* IV */
                                  AES_GCM_IVLEN,
                                  complete_packet, /* aad */
                                  aadlen,
                                  (const uint8_t *)complete_packet + aadlen + encrypted_size, /* tag */
                                  authlen,
                                  (const uint8_t *)complete_packet + aadlen, /* input */
                                  (unsigned char *)out); /* output */
    if (rc != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_gcm_auth_decrypt failed");
        return SSH_ERROR;
    }

    /* Increment the IV for the next invocation */
    uint64_inc(cipher->last_iv + 4);

    return SSH_OK;
}
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CHACHA20_C) && defined(MBEDTLS_POLY1305_C)

struct chacha20_poly1305_keysched {
    bool initialized;
    /* cipher handle used for encrypting the packets */
    mbedtls_chacha20_context main_ctx;
    /* cipher handle used for encrypting the length field */
    mbedtls_chacha20_context header_ctx;
    /* Poly1305 key */
    mbedtls_poly1305_context poly_ctx;
};

static void
chacha20_poly1305_cleanup(struct ssh_cipher_struct *cipher)
{
    struct chacha20_poly1305_keysched *ctx = NULL;

    if (cipher->chacha20_schedule == NULL) {
        return;
    }

    ctx = cipher->chacha20_schedule;

    if (ctx->initialized) {
        mbedtls_chacha20_free(&ctx->main_ctx);
        mbedtls_chacha20_free(&ctx->header_ctx);
        mbedtls_poly1305_free(&ctx->poly_ctx);
        ctx->initialized = false;
    }

    SAFE_FREE(cipher->chacha20_schedule);
}

static int
chacha20_poly1305_set_key(struct ssh_cipher_struct *cipher,
                          void *key,
                          UNUSED_PARAM(void *IV))
{
    struct chacha20_poly1305_keysched *ctx = NULL;
    uint8_t *u8key = key;
    int ret = SSH_ERROR, rv;

    if (cipher->chacha20_schedule == NULL) {
        ctx = calloc(1, sizeof(*ctx));
        if (ctx == NULL) {
            return -1;
        }
        cipher->chacha20_schedule = ctx;
    } else {
        ctx = cipher->chacha20_schedule;
    }

    if (!ctx->initialized) {
        mbedtls_chacha20_init(&ctx->main_ctx);
        mbedtls_chacha20_init(&ctx->header_ctx);
        mbedtls_poly1305_init(&ctx->poly_ctx);
        ctx->initialized = true;
    }

    /* ChaCha20 keys initialization */
    /* K2 uses the first half of the key */
    rv = mbedtls_chacha20_setkey(&ctx->main_ctx, u8key);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_setkey(main_ctx) failed");
        goto out;
    }

    /* K1 uses the second half of the key */
    rv = mbedtls_chacha20_setkey(&ctx->header_ctx, u8key + CHACHA20_KEYLEN);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_setkey(header_ctx) failed");
        goto out;
    }

    ret = SSH_OK;
out:
    if (ret != SSH_OK) {
        chacha20_poly1305_cleanup(cipher);
    }
    return ret;
}

static const uint8_t zero_block[CHACHA20_BLOCKSIZE] = {0};

static int
chacha20_poly1305_set_iv(struct ssh_cipher_struct *cipher,
                         uint64_t seq)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t seqbuf[12] = {0};
    int ret;

    /* The nonce in mbedTLS is 96 b long. The counter is passed through separate
     * parameter of 32 b size.
     * Encode the seqence number into the last 8 bytes.
     */
    PUSH_BE_U64(seqbuf, 4, seq);
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("seqbuf (chacha20 IV)", seqbuf, sizeof(seqbuf));
#endif /* DEBUG_CRYPTO */

    ret = mbedtls_chacha20_starts(&ctx->header_ctx, seqbuf, 0);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_starts(header_ctx) failed");
        return SSH_ERROR;
    }

    ret = mbedtls_chacha20_starts(&ctx->main_ctx, seqbuf, 0);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_starts(main_ctx) failed");
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int
chacha20_poly1305_packet_setup(struct ssh_cipher_struct *cipher,
                               uint64_t seq,
                               int do_encrypt)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t poly_key[CHACHA20_BLOCKSIZE];
    int ret = SSH_ERROR, rv;

    /* The initialization for decrypt was already done with the length block */
    if (do_encrypt) {
        rv = chacha20_poly1305_set_iv(cipher, seq);
        if (rv != SSH_OK) {
            return SSH_ERROR;
        }
    }

    /* Output full ChaCha block so that counter increases by one for
     * next step. */
    rv = mbedtls_chacha20_update(&ctx->main_ctx, sizeof(zero_block),
                                 zero_block, poly_key);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_update failed");
        goto out;
    }
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("poly_key", poly_key, POLY1305_KEYLEN);
#endif /* DEBUG_CRYPTO */

    /* Set the Poly1305 key */
    rv = mbedtls_poly1305_starts(&ctx->poly_ctx, poly_key);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_poly1305_starts failed");
        goto out;
    }

    ret = SSH_OK;
out:
    explicit_bzero(poly_key, sizeof(poly_key));
    return ret;
}

static int
chacha20_poly1305_aead_decrypt_length(struct ssh_cipher_struct *cipher,
                                      void *in,
                                      uint8_t *out,
                                      size_t len,
                                      uint64_t seq)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    int rv;

    if (len < sizeof(uint32_t)) {
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("encrypted length", (uint8_t *)in, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */

    /* Set IV for the header context */
    rv = chacha20_poly1305_set_iv(cipher, seq);
    if (rv != SSH_OK) {
        return SSH_ERROR;
    }

    rv = mbedtls_chacha20_update(&ctx->header_ctx, sizeof(uint32_t), in, out);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_update failed");
        return SSH_ERROR;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("deciphered length", out, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */

    return SSH_OK;
}

static int
chacha20_poly1305_aead_decrypt(struct ssh_cipher_struct *cipher,
                               void *complete_packet,
                               uint8_t *out,
                               size_t encrypted_size,
                               uint64_t seq)
{
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    uint8_t *mac = (uint8_t *)complete_packet + sizeof(uint32_t) +
                   encrypted_size;
    uint8_t tag[POLY1305_TAGLEN] = {0};
    int ret = SSH_ERROR;
    int rv, cmp = 0;

    /* Prepare the Poly1305 key */
    rv = chacha20_poly1305_packet_setup(cipher, seq, 0);
    if (rv != SSH_OK) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to setup packet");
        goto out;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("received mac", mac, POLY1305_TAGLEN);
#endif /* DEBUG_CRYPTO */

    /* Calculate MAC of received data */
    rv = mbedtls_poly1305_update(&ctx->poly_ctx, complete_packet,
                                 encrypted_size + sizeof(uint32_t));
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_poly1305_update failed");
        goto out;
    }

    rv = mbedtls_poly1305_finish(&ctx->poly_ctx, tag);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_poly1305_finish failed");
        goto out;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("calculated mac", tag, POLY1305_TAGLEN);
#endif /* DEBUG_CRYPTO */

    /* Verify the calculated MAC matches the attached MAC */
    cmp = secure_memcmp(tag, mac, POLY1305_TAGLEN);
    if (cmp != 0) {
        /* mac error */
        SSH_LOG(SSH_LOG_PACKET, "poly1305 verify error");
        return SSH_ERROR;
    }

    /* Decrypt the message */
    rv = mbedtls_chacha20_update(&ctx->main_ctx, encrypted_size,
                                 (uint8_t *)complete_packet + sizeof(uint32_t),
                                 out);
    if (rv != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_update failed");
        goto out;
    }

    ret = SSH_OK;
out:
    return ret;
}

static void
chacha20_poly1305_aead_encrypt(struct ssh_cipher_struct *cipher,
                               void *in,
                               void *out,
                               size_t len,
                               uint8_t *tag,
                               uint64_t seq)
{
    struct ssh_packet_header *in_packet = in, *out_packet = out;
    struct chacha20_poly1305_keysched *ctx = cipher->chacha20_schedule;
    int ret;

    /* Prepare the Poly1305 key */
    ret = chacha20_poly1305_packet_setup(cipher, seq, 1);
    if (ret != SSH_OK) {
        SSH_LOG(SSH_LOG_WARNING, "Failed to setup packet");
        return;
    }

#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("plaintext length",
                    (unsigned char *)&in_packet->length, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */
    /* step 2, encrypt length field */
    ret = mbedtls_chacha20_update(&ctx->header_ctx, sizeof(uint32_t),
                                  (unsigned char *)&in_packet->length,
                                  (unsigned char *)&out_packet->length);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_update failed");
        return;
    }
#ifdef DEBUG_CRYPTO
    ssh_log_hexdump("encrypted length",
                    (unsigned char *)&out_packet->length, sizeof(uint32_t));
#endif /* DEBUG_CRYPTO */

    /* step 3, encrypt packet payload (main_ctx counter == 1) */
    /* We already did encrypt one block so the counter should be in the correct position */
    ret = mbedtls_chacha20_update(&ctx->main_ctx, len - sizeof(uint32_t),
                                  in_packet->payload, out_packet->payload);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_chacha20_update failed");
        return;
    }

    /* step 4, compute the MAC */
    ret = mbedtls_poly1305_update(&ctx->poly_ctx, (const unsigned char *)out_packet, len);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_poly1305_update failed");
        return;
    }
    ret = mbedtls_poly1305_finish(&ctx->poly_ctx, tag);
    if (ret != 0) {
        SSH_LOG(SSH_LOG_WARNING, "mbedtls_poly1305_finish failed");
        return;
    }
}
#endif /* defined(MBEDTLS_CHACHA20_C) && defined(MBEDTLS_POLY1305_C) */


static void cipher_cleanup(struct ssh_cipher_struct *cipher)
{
    mbedtls_cipher_free(&cipher->encrypt_ctx);
    mbedtls_cipher_free(&cipher->decrypt_ctx);
#ifdef MBEDTLS_GCM_C
    mbedtls_gcm_free(&cipher->gcm_ctx);
#endif /* MBEDTLS_GCM_C */
}

#ifdef WITH_INSECURE_NONE
static void
none_crypt(UNUSED_PARAM(struct ssh_cipher_struct *cipher),
           void *in,
           void *out,
           size_t len)
{
    memcpy(out, in, len);
}
#endif /* WITH_INSECURE_NONE */

static struct ssh_cipher_struct ssh_ciphertab[] = {
#ifdef WITH_BLOWFISH_CIPHER
    {
        .name = "blowfish-cbc",
        .blocksize = 8,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_BLOWFISH_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
#endif /* WITH_BLOWFISH_CIPHER */
    {
        .name = "aes128-ctr",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-ctr",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-ctr",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CTR,
        .set_encrypt_key = cipher_set_encrypt_key,
        .set_decrypt_key = cipher_set_decrypt_key,
        .encrypt = cipher_encrypt,
        .decrypt = cipher_decrypt,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes128-cbc",
        .blocksize = 16,
        .keysize = 128,
        .type = MBEDTLS_CIPHER_AES_128_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes192-cbc",
        .blocksize = 16,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_AES_192_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-cbc",
        .blocksize = 16,
        .keysize = 256,
        .type = MBEDTLS_CIPHER_AES_256_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
#ifdef MBEDTLS_GCM_C
    {
        .name = "aes128-gcm@openssh.com",
        .blocksize = 16,
        .lenfield_blocksize = 4, /* not encrypted, but authenticated */
        .keysize = 128,
        .tag_size = AES_GCM_TAGLEN,
        .type = MBEDTLS_CIPHER_AES_128_GCM,
        .set_encrypt_key = cipher_set_key_gcm,
        .set_decrypt_key = cipher_set_key_gcm,
        .aead_encrypt = cipher_encrypt_gcm,
        .aead_decrypt_length = cipher_gcm_get_length,
        .aead_decrypt = cipher_decrypt_gcm,
        .cleanup = cipher_cleanup
    },
    {
        .name = "aes256-gcm@openssh.com",
        .blocksize = 16,
        .lenfield_blocksize = 4, /* not encrypted, but authenticated */
        .keysize = 256,
        .tag_size = AES_GCM_TAGLEN,
        .type = MBEDTLS_CIPHER_AES_256_GCM,
        .set_encrypt_key = cipher_set_key_gcm,
        .set_decrypt_key = cipher_set_key_gcm,
        .aead_encrypt = cipher_encrypt_gcm,
        .aead_decrypt_length = cipher_gcm_get_length,
        .aead_decrypt = cipher_decrypt_gcm,
        .cleanup = cipher_cleanup
    },
#endif /* MBEDTLS_GCM_C */
    {
        .name = "3des-cbc",
        .blocksize = 8,
        .keysize = 192,
        .type = MBEDTLS_CIPHER_DES_EDE3_CBC,
        .set_encrypt_key = cipher_set_encrypt_key_cbc,
        .set_decrypt_key = cipher_set_decrypt_key_cbc,
        .encrypt = cipher_encrypt_cbc,
        .decrypt = cipher_decrypt_cbc,
        .cleanup = cipher_cleanup
    },
    {
#if defined(MBEDTLS_CHACHA20_C) && defined(MBEDTLS_POLY1305_C)
        .ciphertype = SSH_AEAD_CHACHA20_POLY1305,
        .name = "chacha20-poly1305@openssh.com",
        .blocksize = 8,
        .lenfield_blocksize = 4,
        .keylen = sizeof(struct chacha20_poly1305_keysched),
        .keysize = 2 * CHACHA20_KEYLEN * 8,
        .tag_size = POLY1305_TAGLEN,
        .set_encrypt_key = chacha20_poly1305_set_key,
        .set_decrypt_key = chacha20_poly1305_set_key,
        .aead_encrypt = chacha20_poly1305_aead_encrypt,
        .aead_decrypt_length = chacha20_poly1305_aead_decrypt_length,
        .aead_decrypt = chacha20_poly1305_aead_decrypt,
        .cleanup = chacha20_poly1305_cleanup
#else
        .name = "chacha20-poly1305@openssh.com"
#endif
    },
#ifdef WITH_INSECURE_NONE
    {
        .name = "none",
        .blocksize = 8,
        .keysize = 0,
        .encrypt = none_crypt,
        .decrypt = none_crypt,
    },
#endif /* WITH_INSECURE_NONE */
    {
        .name = NULL,
        .blocksize = 0,
        .keysize = 0,
        .set_encrypt_key = NULL,
        .set_decrypt_key = NULL,
        .encrypt = NULL,
        .decrypt = NULL,
        .cleanup = NULL
    }
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
    return ssh_ciphertab;
}

int ssh_crypto_init(void)
{
    UNUSED_VAR(size_t i);
    int rc;

    if (libmbedcrypto_initialized) {
        return SSH_OK;
    }

    mbedtls_entropy_init(&ssh_mbedtls_entropy);
    mbedtls_ctr_drbg_init(&ssh_mbedtls_ctr_drbg);

    rc = mbedtls_ctr_drbg_seed(&ssh_mbedtls_ctr_drbg, mbedtls_entropy_func,
            &ssh_mbedtls_entropy, NULL, 0);
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    }

#if (defined(MBEDTLS_CHACHA20_C) && defined(MBEDTLS_POLY1305_C))
    for (i = 0; ssh_ciphertab[i].name != NULL; i++) {
        int cmp;

        cmp = strcmp(ssh_ciphertab[i].name, "chacha20-poly1305@openssh.com");
        if (cmp == 0) {
            memcpy(&ssh_ciphertab[i],
                   ssh_get_chacha20poly1305_cipher(),
                   sizeof(struct ssh_cipher_struct));
            break;
        }
    }
#endif

    libmbedcrypto_initialized = 1;

    return SSH_OK;
}

int ssh_mbedtls_random(void *where, int len, int strong)
{
    int rc = 0;
    if (strong) {
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_ON);
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
        mbedtls_ctr_drbg_set_prediction_resistance(&ssh_mbedtls_ctr_drbg,
                MBEDTLS_CTR_DRBG_PR_OFF);
    } else {
        rc = mbedtls_ctr_drbg_random(&ssh_mbedtls_ctr_drbg, where, len);
    }

    return !rc;
}

mbedtls_ctr_drbg_context *ssh_get_mbedtls_ctr_drbg_context(void)
{
    return &ssh_mbedtls_ctr_drbg;
}

void ssh_crypto_finalize(void)
{
    if (!libmbedcrypto_initialized) {
        return;
    }

    mbedtls_ctr_drbg_free(&ssh_mbedtls_ctr_drbg);
    mbedtls_entropy_free(&ssh_mbedtls_entropy);

    libmbedcrypto_initialized = 0;
}

#endif /* HAVE_LIBMBEDCRYPTO */
