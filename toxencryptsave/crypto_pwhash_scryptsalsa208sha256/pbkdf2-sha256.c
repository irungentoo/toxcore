#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef  VANILLA_NACL /* toxcore only uses this when libsodium is unavailable */

/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <crypto_hash_sha256.h>
#include <crypto_auth_hmacsha256.h>

#include "pbkdf2-sha256.h"
#include "sysendian.h"
#include "../../toxcore/crypto_core.h"

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
              size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
        uint8_t         key[32] = {0};
        size_t          i;
        uint8_t         salt_and_ivec[saltlen + 4];
        uint8_t         U[32];
        uint8_t         T[32];
        uint64_t        j;
        int             k;
        size_t          clen;

    if (passwdlen > 32) {
        /* For some reason libsodium allows 64byte keys meaning keys
         * between 32byte and 64bytes are not compatible with libsodium.
           toxencryptsave should only give 32byte passwds so this isn't an issue here.*/
        crypto_hash_sha256(key, passwd, passwdlen);
    } else {
        memcpy(key, passwd, passwdlen);
    }

    memcpy(salt_and_ivec, salt, saltlen);

        for (i = 0; i * 32 < dkLen; i++) {
                be32enc(salt_and_ivec + saltlen, (uint32_t)(i + 1));
                crypto_auth_hmacsha256(U, salt_and_ivec, sizeof(salt_and_ivec), key);

                memcpy(T, U, 32);

                for (j = 2; j <= c; j++) {
                        crypto_auth_hmacsha256(U, U, 32, key);

                        for (k = 0; k < 32; k++) {
                                T[k] ^= U[k];
            }
                }

                clen = dkLen - i * 32;
                if (clen > 32) {
                        clen = 32;
        }
                memcpy(&buf[i * 32], T, clen);
        }
    crypto_memzero((void *) key, sizeof(key));
}

#endif
